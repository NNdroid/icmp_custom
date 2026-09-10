package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Backfill for the contracts the behaviour suites reach only indirectly:
// the public logging surface, the drop counters an operator watches, the
// poll schedule an embedder inspects, and the path-validation handshake.
// ---------------------------------------------------------------------------

func TestStdLoggerPublicMethodsCarryTheirLevelPrefix(t *testing.T) {
	lines := asLogLines(t, func() {
		l := stdLogger{level: LogLevelDebug}
		l.Debugf("dbg %d", 1)
		l.Infof("inf %d", 2)
		l.Warnf("wrn %d", 3)
		l.Errorf("err %d", 4)
	})
	// Every method routes through emit, so the padded level column and the
	// formatting must survive the public surface, not just the internal one.
	want := []string{
		"[DEBUG] dbg 1",
		"[INFO ] inf 2",
		"[WARN ] wrn 3",
		"[ERROR] err 4",
	}
	if len(lines) != len(want) {
		t.Fatalf("captured %d lines, want %d: %q", len(lines), len(want), lines)
	}
	for i, w := range want {
		if !strings.HasSuffix(lines[i], w) {
			t.Fatalf("line %d = %q, want suffix %q", i, lines[i], w)
		}
	}

	quiet := asLogLines(t, func() {
		l := stdLogger{level: LogLevelError}
		l.Debugf("no")
		l.Infof("no")
		l.Warnf("no")
		l.Errorf("yes")
	})
	if len(quiet) != 1 || !strings.Contains(quiet[0], "yes") {
		t.Fatalf("an error-level logger passed %d lines, want only the error: %q", len(quiet), quiet)
	}
}

func TestEventsDroppedSurfacesTheBusOverflow(t *testing.T) {
	// The counter is the only way an operator learns the handler is too slow,
	// so it must be reachable for BOTH endpoints, not just internally.
	block := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(block) }) }
	defer release()

	cEp, _, srv := newTestServer(t, ServerConfig{
		TargetAddr: "tcp://127.0.0.1:1",
		Passwords:  []string{"secret"},
	}, nil)
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)

	srv.SetEventHandler(func(SessionEvent) { <-block })
	cli.SetEventHandler(func(ClientEvent) { <-block })

	// The buses buffer 256 (server) and 128 (client) events, so overflow the
	// larger one and expect the excess to be counted, not queued.
	for i := 0; i < 300; i++ {
		srv.events.emit(SessionEvent{Kind: SessionEstablished, SessionID: uint32(i)})
		cli.events.emit(ClientEvent{Kind: TunnelEstablished, Session: uint32(i)})
	}
	if srv.EventsDropped() == 0 {
		t.Fatal("a blocked handler must show up in Server.EventsDropped")
	}
	if cli.EventsDropped() == 0 {
		t.Fatal("a blocked handler must show up in Client.EventsDropped")
	}
}

func TestLogWarnAndLogErrorReachTheInjectedSink(t *testing.T) {
	// The logger must be injected at construction: the field is read by
	// background goroutines the moment Start runs, so swapping it afterwards
	// would be a data race by construction.
	sink := &captureLogger{}
	cEp, sEp := newFakeLink("client", "server", testRecordLimit)
	srv, err := NewServerWithTransport(ServerConfig{
		TargetAddr: "tcp://127.0.0.1:1",
		Passwords:  []string{"secret"},
		Logger:     sink,
	}, sEp, nil)
	if err != nil {
		t.Fatalf("NewServerWithTransport: %v", err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(srv.Close)

	cli, err := NewClientWithTransport(ClientConfig{
		ServerAddr: "192.0.2.2",
		Passwords:  []string{"secret"},
		Logger:     sink,
	}, cEp)
	if err != nil {
		t.Fatalf("NewClientWithTransport: %v", err)
	}
	t.Cleanup(cli.Close)

	srv.logError("server error %d", 7)
	cli.logWarn("client warn %d", 8)
	cli.logDebug("client debug %d", 9)

	sink.mu.Lock()
	defer sink.mu.Unlock()
	joined := strings.Join(sink.lines, "\n")
	for _, want := range []string{"server error 7", "client warn 8", "client debug 9"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("sink is missing %q; captured %q", want, joined)
		}
	}
}

func TestMinDurationPicksTheSmallerSide(t *testing.T) {
	cases := []struct {
		a, b, want time.Duration
	}{
		{time.Second, time.Millisecond, time.Millisecond},
		{time.Millisecond, time.Second, time.Millisecond},
		{0, time.Second, 0},
		{time.Nanosecond, time.Nanosecond, time.Nanosecond},
		{-time.Second, time.Second, -time.Second},
	}
	for _, c := range cases {
		if got := minDuration(c.a, c.b); got != c.want {
			t.Fatalf("minDuration(%v, %v) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestPollScheduleMirrorsTheConfiguredClient(t *testing.T) {
	cEp, _, _ := newTestServer(t, ServerConfig{
		TargetAddr: "tcp://127.0.0.1:1",
		Passwords:  []string{"secret"},
	}, nil)
	cli := newTestClient(t, ClientConfig{
		ServerAddr:       "192.0.2.2",
		Passwords:        []string{"secret"},
		PollsInFlight:    3,
		PollInterval:     40 * time.Millisecond,
		IdlePollInterval: 2 * time.Second,
		KeepAlive:        7 * time.Second,
	}, cEp)

	got := cli.PollSchedule()
	if got.PollsInFlight != 3 || got.PollInterval != 40*time.Millisecond ||
		got.IdlePoll != 2*time.Second || got.KeepAlive != 7*time.Second {
		t.Fatalf("PollSchedule = %+v, want the explicitly configured values", got)
	}
}

func TestClientStartRequiresAListenAddress(t *testing.T) {
	cEp, _, _ := newTestServer(t, ServerConfig{
		TargetAddr: "tcp://127.0.0.1:1",
		Passwords:  []string{"secret"},
	}, nil)
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)

	err := cli.Start()
	if err == nil {
		t.Fatal("Start without a listen address must fail loudly")
	}
	if !errors.Is(err, ErrConfigRequired) {
		t.Fatalf("Start error = %v, want ErrConfigRequired", err)
	}
	// The message must point an embedder at DialTunnel: that is the whole
	// reason the error exists.
	if !strings.Contains(err.Error(), "DialTunnel") {
		t.Fatalf("Start error %v should mention DialTunnel", err)
	}
}

func TestClientStartSurfacesAListenFailure(t *testing.T) {
	cEp, _, _ := newTestServer(t, ServerConfig{
		TargetAddr: "tcp://127.0.0.1:1",
		Passwords:  []string{"secret"},
	}, nil)
	// Occupying the port first proves the listen error is surfaced, not
	// swallowed behind a goroutine.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot grab a local port: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	cli := newTestClient(t, ClientConfig{
		ServerAddr: "192.0.2.2",
		Passwords:  []string{"secret"},
		ListenAddr: addr,
	}, cEp)
	if err := cli.Start(); err == nil {
		t.Fatal("Start on an occupied port must fail")
	}
}

func TestProfileDefaultConstructorsFailLoudly(t *testing.T) {
	// A transport name this build does not implement is a configuration
	// mistake and must name the accepted value, on both endpoints.
	_, err := NewServerWithDialer(ServerConfig{Transport: "udp", Passwords: []string{"k"}}, nil)
	if err == nil || !errors.Is(err, ErrConfigRequired) {
		t.Fatalf("NewServerWithDialer(transport=udp) = %v, want ErrConfigRequired", err)
	}
	if !strings.Contains(err.Error(), TransportICMP) {
		t.Fatalf("transport error %v must name the accepted transport", err)
	}
	_, err = NewClient(ClientConfig{Transport: "udp", ServerAddr: "192.0.2.2", Passwords: []string{"k"}})
	if err == nil || !errors.Is(err, ErrConfigRequired) {
		t.Fatalf("NewClient(transport=udp) = %v, want ErrConfigRequired", err)
	}

	// On this platform the ICMP carrier itself must refuse to open (either no
	// raw-socket capability or no such support at all) — and it must refuse
	// BEFORE the session layer is built, leaving nothing half-open.
	if _, err := NewServer(ServerConfig{Passwords: []string{"k"}}); err == nil {
		t.Skip("this platform can open an ICMP carrier; nothing to assert")
	}

	// The peer is validated before any socket is touched.
	_, err = NewClient(ClientConfig{ServerAddr: "not an address", Passwords: []string{"k"}})
	if err == nil || !strings.Contains(err.Error(), "invalid 'server'") {
		t.Fatalf("NewClient(bad server) = %v, want an 'invalid server' error", err)
	}

	// A malformed ICMP profile is rejected at construction, not at first poll.
	_, err = NewClient(ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"k"}, ICMP: ICMPProfile{Family: "sneaky"}})
	if err == nil {
		t.Fatal("NewClient with an unknown ICMP family must fail")
	}
}

func TestPathChallengeRoundTripAndExpiry(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cEp, _, srv := newTestServer(t, ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer conn.Close()

	var sess *ServerSession
	srv.sessions.Range(func(_, v any) bool {
		if s, ok := v.(*ServerSession); ok {
			sess = s
			return false
		}
		return true
	})
	if sess == nil {
		t.Fatal("no live session found after DialTunnel")
	}

	peer := netip.MustParseAddrPort("203.0.113.9:4444")
	path := PathID{Peer: peer}

	// A response with the wrong payload size is rejected before the map is
	// even consulted — that gate runs on every spoofed response.
	for _, n := range []int{0, PathChallengeSize - 1, PathChallengeSize + 1} {
		if sess.acceptPathResponse(peer, make([]byte, n)) {
			t.Fatalf("a %d-byte path response must be rejected", n)
		}
	}
	// No challenge is pending for this peer yet.
	if sess.acceptPathResponse(peer, make([]byte, PathChallengeSize)) {
		t.Fatal("a response with no pending challenge must be rejected")
	}

	// The challenge sends a 16-byte token toward the claimed new path.
	sess.sendPathChallenge(path)
	sess.challengeMu.Lock()
	pending, ok := sess.pathChallenges[peer.Addr()]
	sess.challengeMu.Unlock()
	if !ok {
		t.Fatal("sendPathChallenge must record the pending token")
	}

	// The wrong token must not move the session, the right one must.
	if sess.acceptPathResponse(peer, bytes.Repeat([]byte{0xAA}, PathChallengeSize)) {
		t.Fatal("a wrong token must be rejected")
	}
	if !sess.acceptPathResponse(peer, pending.token[:]) {
		t.Fatal("the correct token must be accepted")
	}
	// Acceptance is single-use: the pending entry is consumed.
	if sess.acceptPathResponse(peer, pending.token[:]) {
		t.Fatal("a consumed challenge must not accept a second response")
	}

	// An expired challenge must not validate, even with the right token.
	sess.sendPathChallenge(path)
	sess.challengeMu.Lock()
	pending = sess.pathChallenges[peer.Addr()]
	pending.expires = time.Now().Add(-time.Second)
	sess.pathChallenges[peer.Addr()] = pending
	sess.challengeMu.Unlock()
	if sess.acceptPathResponse(peer, pending.token[:]) {
		t.Fatal("an expired challenge must be rejected")
	}

	// The pending table is bounded: more distinct peers than maxPathChallenges
	// must evict, never grow without limit.
	for i := 0; i < maxPathChallenges+4; i++ {
		other := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), uint16(4000+i))
		sess.sendPathChallenge(PathID{Peer: other})
	}
	sess.challengeMu.Lock()
	size := len(sess.pathChallenges)
	sess.challengeMu.Unlock()
	if size > maxPathChallenges {
		t.Fatalf("pathChallenges grew to %d, want <= %d", size, maxPathChallenges)
	}
	// The eviction policy replaces an arbitrary entry (Go map order), so only
	// the bound is guaranteed — the table is a safety valve, not a cache.
}

// datagramOnly exposes ONLY the Transport surface of the fake endpoint: no
// Poller and no MaxRecordSizer. That is what forces the client onto the
// keepAlive path instead of the poll loop, mirroring a datagram carrier.
type datagramOnly struct{ ep *fakeEndpoint }

func (d *datagramOnly) ReadRecord(buf []byte) (int, PathID, error) {
	return d.ep.ReadRecord(buf)
}
func (d *datagramOnly) WriteRecord(rec []byte, to netip.AddrPort) error {
	return d.ep.WriteRecord(rec, to)
}
func (d *datagramOnly) ReplyRecord(rec []byte, path PathID) error {
	return d.ep.ReplyRecord(rec, path)
}
func (d *datagramOnly) LocalID() string  { return d.ep.LocalID() }
func (d *datagramOnly) RemoteID() string { return d.ep.RemoteID() }
func (d *datagramOnly) Close() error     { return d.ep.Close() }

func TestKeepAlivePingsKeepADatagramTunnelAlive(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	// The client end must be wrapped in the datagram-only view while the
	// server keeps the raw endpoint, so build the pair by hand.
	cEp, sEp := newFakeLink("client", "server", testRecordLimit)
	srv, err := NewServerWithTransport(ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, sEp, nil)
	if err != nil {
		t.Fatalf("NewServerWithTransport: %v", err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(srv.Close)

	cli, err := NewClientWithTransport(ClientConfig{
		ServerAddr: "192.0.2.2",
		Passwords:  []string{"secret"},
		KeepAlive:  20 * time.Millisecond, // several ticks inside the test window
	}, &datagramOnly{cEp})
	if err != nil {
		t.Fatalf("NewClientWithTransport: %v", err)
	}
	t.Cleanup(cli.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer conn.Close()

	// Stay idle long enough for several keepalive pings and their pongs. A
	// session that mishandles Ping/Pong dies here with an idle timeout.
	time.Sleep(150 * time.Millisecond)

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	want := []byte("still alive?")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write after idle: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read after idle: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo = %q, want %q", got, want)
	}
}

func TestClientStartServesLocalConnectionsEndToEnd(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	// Pre-pick an ephemeral port so the test can dial Start's listener. The
	// close-then-reuse window is tiny and local-only.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	listenAddr := probe.Addr().String()
	_ = probe.Close()

	cEp, _, _ := newTestServer(t, ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)
	cli := newTestClient(t, ClientConfig{
		ServerAddr: "192.0.2.2",
		Passwords:  []string{"secret"},
		ListenAddr: listenAddr,
	}, cEp)

	started := make(chan error, 1)
	go func() { started <- cli.Start() }()

	// Wait for the listener to come up, then push bytes through the full
	// chain: local TCP -> serveConn -> tunnel -> target -> back.
	var local net.Conn
	deadline := time.Now().Add(3 * time.Second)
	for {
		local, err = net.Dial("tcp", listenAddr)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Start never opened %s: %v", listenAddr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer local.Close()

	_ = local.SetDeadline(time.Now().Add(5 * time.Second))
	want := []byte("through Start()")
	if _, err := local.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(local, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo = %q, want %q", got, want)
	}

	// Close must unblock Start and it must report nil: a stop requested by the
	// owner is success, not an accept error.
	cli.Close()
	select {
	case err := <-started:
		if err != nil {
			t.Fatalf("Start after Close = %v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not unblock Start")
	}
}

func TestServerClosesTheSessionWhenTheTargetWriteFails(t *testing.T) {
	// A target that accepts but can never be written: the server must tear the
	// session down instead of silently swallowing data forever.
	cEp, _, _ := newTestServer(t, ServerConfig{
		TargetAddr: "tcp://127.0.0.1:9",
		Passwords:  []string{"secret"},
	}, func(ctx context.Context, sessionID uint32, network, address string) (net.Conn, error) {
		inside, outside := net.Pipe()
		_ = outside.Close() // every write to `inside` fails immediately
		return inside, nil
	})
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	// Either outcome proves the teardown reached the client promptly: the
	// server may tear the session down before the write (broken pipe) or the
	// read after it observes the close. What must NOT happen is both succeed.
	if _, err := conn.Write([]byte("this write must kill the session")); err == nil {
		buf := make([]byte, 16)
		if _, err := conn.Read(buf); err == nil {
			t.Fatal("the client end must observe the server-side teardown")
		}
	}
}

func TestReackDuplicateDataAnswersTheHighestContiguousAck(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cEp, _, srv := newTestServer(t, ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer conn.Close()

	var sess *ServerSession
	srv.sessions.Range(func(_, v any) bool {
		if s, ok := v.(*ServerSession); ok {
			sess = s
			return false
		}
		return true
	})
	if sess == nil {
		t.Fatal("no live session found after DialTunnel")
	}

	// Nothing delivered yet: currentAck is 0, so the duplicate-ACK helper must
	// stay silent rather than ACK sequence 0.
	sess.reackDuplicateData(PathID{Peer: fakeServerAddr})

	// Push one byte through, then re-ack: the helper must emit the cumulative
	// ACK for the delivered run without touching the receive queue.
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("a")); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if ack := sess.currentAck(); ack == 0 {
		t.Fatal("delivered data must advance the cumulative ack")
	}
	sess.reackDuplicateData(PathID{Peer: fakeServerAddr})
}
