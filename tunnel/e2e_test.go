package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Shared test rig
//
// Everything here runs on the in-memory fake transport, so the whole vertical
// slice (handshake -> ARQ -> target forwarding -> teardown) is exercised on a
// NON-ROOT machine, which is the P3 exit condition.
// ---------------------------------------------------------------------------

// testRecordLimit is the carrier budget the fake link advertises.
const testRecordLimit = 1500

// fakeServerAddr is the address the fake link treats as "the server". The fake
// ignores the destination of a write, so any valid AddrPort works.
var fakeServerAddr = netip.MustParseAddrPort("192.0.2.2:10002")

// tcpEchoServer starts a loopback TCP echo server and returns its address plus
// a stop function.
//
// The rig takes a testing.TB rather than a *testing.T so the benchmarks in
// bench_test.go can drive the exact same setup: a benchmark that used a
// different rig would measure a different system.
func tcpEchoServer(t testing.TB) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// newTestServer starts a Server on one end of a fake link and returns the
// client-side endpoint, the server-side endpoint and the running server.
func newTestServer(t testing.TB, cfg ServerConfig, dial TargetDialer) (*fakeEndpoint, *fakeEndpoint, *Server) {
	t.Helper()
	cEp, sEp := newFakeLink("client", "server", testRecordLimit)
	srv, err := NewServerWithTransport(cfg, sEp, dial)
	if err != nil {
		t.Fatalf("NewServerWithTransport: %v", err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(srv.Close)
	return cEp, sEp, srv
}

// newTestClient builds a Client on the other end of the same fake link.
func newTestClient(t testing.TB, cfg ClientConfig, cEp *fakeEndpoint) *Client {
	t.Helper()
	cli, err := NewClientWithTransport(cfg, cEp)
	if err != nil {
		t.Fatalf("NewClientWithTransport: %v", err)
	}
	t.Cleanup(cli.Close)
	return cli
}

// pokeRecord delivers one pre-encoded record to the peer as a carrier request.
func pokeRecord(t *testing.T, from *fakeEndpoint, wire []byte) {
	t.Helper()
	if _, err := from.Poke(wire, fakeServerAddr); err != nil {
		t.Fatalf("%s: poke: %v", from.name, err)
	}
}

// sendTestSYN seals and delivers a SYN built the way the client builds it.
func sendTestSYN(t *testing.T, from *fakeEndpoint, psk, target string, ts int64, nonce [ClientNonceSize]byte) PSKHandshakeKeys {
	t.Helper()
	payload := make([]byte, SynPayloadBase)
	copy(payload[:ClientNonceSize], nonce[:])
	binary.BigEndian.PutUint64(payload[ClientNonceSize:SynPayloadBase], uint64(ts))
	payload = appendTargetTLV(payload, target)
	keys := DerivePSKHandshakeKeys(psk, nonce)
	wire := SealMAC(&Record{
		Magic: MagicDefault, Version: Version, Cmd: CmdHandshakeSyn, Data: payload,
	}, &keys.SynMAC, testRecordLimit)
	if len(wire) == 0 {
		t.Fatal("failed to seal test SYN")
	}
	pokeRecord(t, from, wire)
	return keys
}

// readRecordReads one record off an endpoint and parses it.
func readRecord(t *testing.T, ep *fakeEndpoint, timeout time.Duration) *Record {
	t.Helper()
	raw := make([]byte, testRecordLimit)
	n, _ := ep.readWithin(t, raw, timeout)
	rec, err := ParseOwned(raw[:n], MagicDefault, testRecordLimit)
	if err != nil {
		t.Fatalf("%s: parse reply: %v", ep.name, err)
	}
	return rec
}

func randomNonce(t *testing.T) [ClientNonceSize]byte {
	t.Helper()
	var n [ClientNonceSize]byte
	if _, err := rand.Read(n[:]); err != nil {
		t.Fatal(err)
	}
	return n
}

// ---------------------------------------------------------------------------
// End-to-end over the fake transport (non-root)
// ---------------------------------------------------------------------------

func TestE2EFakeTransportRoundTrip(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cfg := ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}
	cEp, _, _ := newTestServer(t, cfg, nil)
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	want := []byte("hello icmp tunnel")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo = %q, want %q", got, want)
	}
}

func TestE2EMultiChunkOrdering(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cEp, _, _ := newTestServer(t, ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// A 40KB transfer spans many records in both directions, which exercises
	// sequencing, cumulative ACKs and the reorder buffers.
	payload := make([]byte, 40*1024)
	rng := mrand.New(mrand.NewPCG(1, 2))
	for i := range payload {
		payload[i] = byte(rng.UintN(256))
	}

	readDone := make(chan error, 1)
	got := make([]byte, len(payload))
	go func() {
		_, err := io.ReadFull(conn, got)
		readDone <- err
	}()

	written := 0
	for written < len(payload) {
		end := written + 1000
		if end > len(payload) {
			end = len(payload)
		}
		n, err := conn.Write(payload[written:end])
		if err != nil {
			t.Fatalf("write at %d: %v", written, err)
		}
		written += n
	}
	if err := <-readDone; err != nil {
		t.Fatalf("read %d bytes: %v", written, err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("round-tripped payload differs")
	}
}

func TestE2ERequestedTargetGranted(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cfg := ServerConfig{
		TargetAddr:     "tcp://127.0.0.1:1", // unreachable default: never dialed
		AllowedTargets: []string{"tcp://" + backend},
		Passwords:      []string{"secret"},
	}
	cEp, _, _ := newTestServer(t, cfg, nil)
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var granted string
	conn, err := cli.DialTunnel(ctx, DialOptions{
		Target:    "tcp://" + backend,
		OnGranted: func(g string) { granted = g },
	})
	if err != nil {
		t.Fatalf("DialTunnel with requested target: %v", err)
	}
	defer conn.Close()
	if granted != "tcp://"+backend {
		t.Fatalf("granted = %q, want %q", granted, "tcp://"+backend)
	}

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	one := make([]byte, 1)
	if _, err := io.ReadFull(conn, one); err != nil {
		t.Fatalf("read: %v", err)
	}
}

func TestE2EDeniedTargetNeverEstablishes(t *testing.T) {
	cfg := ServerConfig{
		TargetAddr:     "tcp://127.0.0.1:1",
		AllowedTargets: []string{"tcp://127.0.0.1:22"},
		Passwords:      []string{"secret"},
	}
	cEp, _, _ := newTestServer(t, cfg, nil)
	cli := newTestClient(t, ClientConfig{
		ServerAddr:        "192.0.2.2",
		Passwords:         []string{"secret"},
		HandshakeAttempts: 2,
		HandshakeBackoff:  time.Millisecond,
	}, cEp)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := cli.DialTunnel(ctx, DialOptions{Target: "tcp://127.0.0.1:23"})
	if !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("denied target must surface ErrHandshakeTimeout, got %v", err)
	}
}

func TestE2ENoiseModeRoundTrip(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := ServerConfig{
		TargetAddr: "tcp://" + backend,
		Passwords:  []string{"secret"},
		PrivateKey: fmt.Sprintf("%x", kp.PrivateKey[:]),
	}
	cEp, _, _ := newTestServer(t, cfg, nil)
	cli := newTestClient(t, ClientConfig{
		ServerAddr: "192.0.2.2",
		Passwords:  []string{"secret"},
		ServerPub:  kp.PublicKey,
	}, cEp)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatalf("Noise DialTunnel: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	want := []byte("noise-protected payload")
	if _, err := conn.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo = %q, want %q", got, want)
	}
}

func TestE2EWrongPSKNeverEstablishes(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()
	cEp, _, _ := newTestServer(t, ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"right"}}, nil)
	cli := newTestClient(t, ClientConfig{
		ServerAddr:        "192.0.2.2",
		Passwords:         []string{"wrong"},
		HandshakeAttempts: 2,
		HandshakeBackoff:  time.Millisecond,
	}, cEp)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := cli.DialTunnel(ctx, DialOptions{}); !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("wrong PSK must surface ErrHandshakeTimeout, got %v", err)
	}
}

func TestE2ESessionTearsDownWhenClientCloses(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()
	cEp, _, srv := newTestServer(t, ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ts := conn.(*TunnelSession)
	if srv.Stats().Sessions != 1 {
		t.Fatalf("server sessions = %d, want 1", srv.Stats().Sessions)
	}
	_ = conn.Close()

	select {
	case <-ts.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel session did not report Done after Close")
	}
	if ts.Err() == nil {
		t.Fatal("TunnelSession.Err must be non-nil once Done is closed")
	}

	deadline := time.Now().Add(3 * time.Second)
	for srv.Stats().Sessions != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.Stats().Sessions != 0 {
		t.Fatalf("server session was not torn down: %d still live", srv.Stats().Sessions)
	}
}

func TestE2EConcurrentTunnels(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()
	cEp, _, _ := newTestServer(t, ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)

	const tunnels = 4
	errs := make(chan error, tunnels)
	for i := 0; i < tunnels; i++ {
		go func(i int) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			conn, err := cli.DialTunnel(ctx, DialOptions{})
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			msg := []byte(fmt.Sprintf("tunnel-%02d", i))
			if _, err := conn.Write(msg); err != nil {
				errs <- err
				return
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, got); err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(got, msg) {
				errs <- fmt.Errorf("tunnel %d: echo %q != %q", i, got, msg)
				return
			}
			errs <- nil
		}(i)
	}
	for i := 0; i < tunnels; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent tunnel: %v", err)
		}
	}
}
