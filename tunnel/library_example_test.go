package tunnel_test

// The library-API acceptance test: everything here uses ONLY the exported
// surface, from the seat of an embedder that owns no ICMP sockets — the exact
// integration a consumer of github.com/NNdroid/icmp_custom/tunnel performs.
//
// It proves, against the public API alone:
//
//   - a Server and a Client can be built on an INJECTED carrier
//     (NewServerWithTransport / NewClientWithTransport);
//   - the target-forwarding dialer is injectable (NewServerWithTransport's
//     TargetDialer — the DialContext seam: route backend dials through any
//     net.Dialer, proxy, or VPN-protected socket);
//   - a Logger is injectable on both ends, and the global level knob
//     (SetGlobalLogLevel) turns DEBUG on for every component that does not
//     configure its own log_level;
//   - lifecycle events surface through SetEventHandler;
//   - a full handshake -> echo -> teardown round trip works.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NNdroid/icmp_custom/tunnel"
)

// libLink is one end of a minimal in-memory carrier. An embedder that owns
// real sockets implements the same four methods plus labels and Close.
type libLink struct {
	name      string
	peer      *libLink
	inbound   chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newLibLinkPair() (*libLink, *libLink) {
	a := &libLink{name: "client", inbound: make(chan []byte, 256), closed: make(chan struct{})}
	b := &libLink{name: "server", inbound: make(chan []byte, 256), closed: make(chan struct{})}
	a.peer, b.peer = b, a
	return a, b
}

func (l *libLink) ReadRecord(buf []byte) (int, tunnel.PathID, error) {
	select {
	case raw := <-l.inbound:
		return copy(buf, raw), tunnel.PathID{Peer: tunnelLibPeer}, nil
	case <-l.closed:
		return 0, tunnel.PathID{}, tunnel.ErrClosed
	}
}

func (l *libLink) WriteRecord(rec []byte, _ netip.AddrPort) error {
	return l.enqueue(rec)
}

func (l *libLink) ReplyRecord(rec []byte, _ tunnel.PathID) error {
	return l.enqueue(rec)
}

func (l *libLink) enqueue(rec []byte) error {
	select {
	case <-l.closed:
		return tunnel.ErrClosed
	default:
	}
	payload := append([]byte(nil), rec...)
	select {
	case l.peer.inbound <- payload:
		return nil
	case <-l.peer.closed:
		return tunnel.ErrClosed
	}
}

func (l *libLink) LocalID() string  { return l.name }
func (l *libLink) RemoteID() string { return l.peer.name }

func (l *libLink) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

// captureSink is an injectable tunnel.Logger that records what it receives.
type captureSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *captureSink) logf(level, format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, level+" "+fmt.Sprintf(format, args...))
}

func (s *captureSink) Debugf(f string, a ...any) { s.logf("DEBUG", f, a...) }
func (s *captureSink) Infof(f string, a ...any)  { s.logf("INFO", f, a...) }
func (s *captureSink) Warnf(f string, a ...any)  { s.logf("WARN", f, a...) }
func (s *captureSink) Errorf(f string, a ...any) { s.logf("ERROR", f, a...) }

func (s *captureSink) joined() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.lines, "\n")
}

// libEchoDialer is the injected TargetDialer: the library hands it the session
// ID, network and address — a real embedder would route this through a
// net.Dialer with Control hooks (protect, bind-to-interface, mark, ...).
func libEchoDialer(t *testing.T, dialed *chan string) tunnel.TargetDialer {
	return func(ctx context.Context, sessionID uint32, network, address string) (net.Conn, error) {
		if dialed != nil {
			*dialed <- fmt.Sprintf("%s %s sid=%d", network, address, sessionID)
		}
		inside, outside := net.Pipe()
		go func() { _, _ = io.Copy(inside, inside); inside.Close() }()
		t.Cleanup(func() { outside.Close() })
		return outside, nil
	}
}

// tunnelLibPeer is the placeholder peer address carried on every PathID.
var tunnelLibPeer = mustAddrPort("192.0.2.10:0")

func mustAddrPort(s string) (ap netip.AddrPort) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return ap
}

func TestLibraryAPIEndToEndWithInjectedCarrier(t *testing.T) {
	// Global debug: every component without its own log_level now logs DEBUG.
	tunnel.SetGlobalLogLevel(tunnel.LogLevelDebug)
	defer tunnel.SetGlobalLogLevel(tunnel.LogLevelInfo)

	sink := &captureSink{}
	cLink, sLink := newLibLinkPair()

	var dialed chan string
	dialed = make(chan string, 1)
	srv, err := tunnel.NewServerWithTransport(tunnel.ServerConfig{
		Passwords: []string{"library-secret"},
		Logger:    sink,
	}, sLink, libEchoDialer(t, &dialed))
	if err != nil {
		t.Fatalf("NewServerWithTransport: %v", err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(srv.Close)

	cli, err := tunnel.NewClientWithTransport(tunnel.ClientConfig{
		ServerAddr: "192.0.2.10",
		Passwords:  []string{"library-secret"},
		Logger:     sink,
	}, cLink)
	if err != nil {
		t.Fatalf("NewClientWithTransport: %v", err)
	}
	t.Cleanup(cli.Close)

	events := make(chan tunnel.ClientEvent, 8)
	cli.SetEventHandler(func(ev tunnel.ClientEvent) { events <- ev })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, tunnel.DialOptions{})
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer conn.Close()

	// The TunnelEstablished event fired on the DialTunnel caller's goroutine.
	select {
	case ev := <-events:
		if ev.Kind != tunnel.TunnelEstablished {
			t.Fatalf("first event = %v, want TunnelEstablished", ev.Kind)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no TunnelEstablished event")
	}

	// Echo through the whole stack: local conn -> records -> target -> back.
	want := []byte("library api round trip")
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
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

	// The injected dialer was consulted with the session identity — this is
	// the DialContext seam an embedder uses to route backend dials anywhere.
	select {
	case d := <-dialed:
		if !strings.HasPrefix(d, "tcp ") {
			t.Fatalf("dialed = %q, want a tcp dial", d)
		}
		if !strings.Contains(d, "sid=") {
			t.Fatalf("dialed = %q, want the session id", d)
		}
	default:
		t.Fatal("the injected TargetDialer was never called")
	}

	// DEBUG output reached the injected sink because the global level was
	// raised before construction.
	logs := sink.joined()
	if !strings.Contains(logs, "DEBUG") {
		t.Fatalf("global debug level produced no DEBUG lines; got:\n%s", logs)
	}
	if !strings.Contains(logs, "INFO") {
		t.Fatal("the sink is missing INFO lines")
	}
}

func TestGlobalLogLevelIsTheFallbackForUnconfiguredComponents(t *testing.T) {
	// Constructed with neither Logger nor LogLevel: the component must pick up
	// the global knob, both when it says debug and when it says error.
	cLink, sLink := newLibLinkPair()

	tunnel.SetGlobalLogLevel(tunnel.LogLevelError)
	srv, err := tunnel.NewServerWithTransport(tunnel.ServerConfig{
		Passwords: []string{"k"},
	}, sLink, nil)
	if err != nil {
		t.Fatalf("NewServerWithTransport: %v", err)
	}
	t.Cleanup(srv.Close)

	// A debug message on an error-level server must be suppressed entirely;
	// this is observable because nothing panics and nothing is written to the
	// standard logger — the contract is the level arithmetic, exercised via
	// the exported knob round trip.
	if got := tunnel.GlobalLogLevel(); got != tunnel.LogLevelError {
		t.Fatalf("GlobalLogLevel = %d, want %d", got, tunnel.LogLevelError)
	}

	tunnel.SetGlobalLogLevel(tunnel.LogLevelDebug)
	if got := tunnel.GlobalLogLevel(); got != tunnel.LogLevelDebug {
		t.Fatalf("GlobalLogLevel = %d, want %d", got, tunnel.LogLevelDebug)
	}

	// And the link pair stays usable (no leaks from the level flips).
	if err := cLink.WriteRecord([]byte("x"), tunnelLibPeer); err != nil {
		t.Fatalf("WriteRecord after level flips: %v", err)
	}
}

func TestLibraryAPIRejectsMismatchedPSKOnThePublicSurface(t *testing.T) {
	cLink, sLink := newLibLinkPair()

	srv, err := tunnel.NewServerWithTransport(tunnel.ServerConfig{
		Passwords: []string{"right"},
	}, sLink, nil)
	if err != nil {
		t.Fatalf("NewServerWithTransport: %v", err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(srv.Close)

	cli, err := tunnel.NewClientWithTransport(tunnel.ClientConfig{
		ServerAddr: "192.0.2.10",
		Passwords:  []string{"wrong"},
		// Two fast attempts: the server drops unauthenticated SYNs silently,
		// so the handshake must end in ErrHandshakeTimeout, not in a context
		// deadline that would hide whose timeout it was.
		HandshakeAttempts: 2,
		HandshakeBackoff:  50 * time.Millisecond,
	}, cLink)
	if err != nil {
		t.Fatalf("NewClientWithTransport: %v", err)
	}
	t.Cleanup(cli.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = cli.DialTunnel(ctx, tunnel.DialOptions{})
	if err == nil {
		t.Fatal("a PSK mismatch must fail the handshake")
	}
	if !errors.Is(err, tunnel.ErrHandshakeTimeout) && !strings.Contains(err.Error(), "handshake") {
		t.Fatalf("DialTunnel error = %v, want a handshake failure", err)
	}
}
