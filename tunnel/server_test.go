package tunnel

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Construction and configuration
//
// These are pure "does the constructor reject the obvious mistakes" checks. The
// interesting runtime behaviour lives in e2e_test.go; what matters here is that
// no configuration can silently degrade into an unauthenticated or
// mis-filtered server.
// ---------------------------------------------------------------------------

func TestNewServerRejectsNilTransport(t *testing.T) {
	_, err := NewServerWithTransport(ServerConfig{Passwords: []string{"x"}}, nil, nil)
	if err == nil {
		t.Fatal("a nil transport must be rejected")
	}
}

func TestNewServerRequiresNonBlankPSK(t *testing.T) {
	a, _ := newFakeLink("client", "server", testRecordLimit)

	if _, err := NewServerWithTransport(ServerConfig{}, a, nil); !errors.Is(err, ErrConfigRequired) {
		t.Fatalf("empty passwords: err = %v, want ErrConfigRequired", err)
	}
	if _, err := NewServerWithTransport(ServerConfig{Passwords: []string{"   ", "\t"}}, a, nil); !errors.Is(err, ErrConfigRequired) {
		t.Fatalf("blank-only passwords: err = %v, want ErrConfigRequired", err)
	}

	// A blank entry next to a real one is trimmed away, not fatal.
	srv, err := NewServerWithTransport(ServerConfig{Passwords: []string{"  ", " real ", ""}}, a, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(srv.cfg.Passwords) != 1 || srv.cfg.Passwords[0] != "real" {
		t.Fatalf("passwords = %q, want [real]", srv.cfg.Passwords)
	}
}

func TestNewServerMagicDefaults(t *testing.T) {
	a, _ := newFakeLink("client", "server", testRecordLimit)

	srv, err := NewServerWithTransport(ServerConfig{Passwords: []string{"x"}}, a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if srv.cfg.Magic != MagicDefault {
		t.Fatalf("magic = 0x%08X, want MagicDefault 0x%08X", srv.cfg.Magic, MagicDefault)
	}

	// A configured magic is honoured verbatim.
	const custom = uint32(0x11223344)
	srv2, err := NewServerWithTransport(ServerConfig{Passwords: []string{"x"}, Magic: custom}, a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if srv2.cfg.Magic != custom {
		t.Fatalf("magic = 0x%08X, want 0x%08X", srv2.cfg.Magic, custom)
	}
}

func TestNewServerRejectsMalformedNoiseKey(t *testing.T) {
	a, _ := newFakeLink("client", "server", testRecordLimit)
	if _, err := NewServerWithTransport(ServerConfig{Passwords: []string{"x"}, PrivateKey: "not-hex"}, a, nil); err == nil {
		t.Fatal("a malformed noise private key must be rejected")
	}
}

func TestNewServerRecordBudgetFollowsCarrier(t *testing.T) {
	a, _ := newFakeLink("client", "server", 1200)
	srv, err := NewServerWithTransport(ServerConfig{Passwords: []string{"x"}}, a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if srv.maxRecordSize != 1200 {
		t.Fatalf("maxRecordSize = %d, want 1200", srv.maxRecordSize)
	}
	if srv.maxPayload != MaxPayloadFor(1200) {
		t.Fatalf("maxPayload = %d, want %d", srv.maxPayload, MaxPayloadFor(1200))
	}
}

// ---------------------------------------------------------------------------
// Target filtering (pure)
// ---------------------------------------------------------------------------

func TestMatchTargetPattern(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		child   string
		want    bool
	}{
		{"exact", "tcp://127.0.0.1:22", "tcp://127.0.0.1:22", true},
		{"network mismatch", "tcp://127.0.0.1:22", "udp://127.0.0.1:22", false},
		{"host wildcard", "tcp://*:22", "tcp://10.0.0.5:22", true},
		{"host wildcard port mismatch", "tcp://*:22", "tcp://10.0.0.5:23", false},
		{"single char host", "tcp://10.0.0.?:22", "tcp://10.0.0.9:22", true},
		{"single char host rejects two", "tcp://10.0.0.?:22", "tcp://10.0.0.99:22", false},
		{"port range wildcard", "tcp://10.0.0.5:8*", "tcp://10.0.0.5:8080", true},
		{"scheme case-insensitive", "TCP://Example.COM:22", "tcp://example.com:22", true},
		{"host case-insensitive", "tcp://EXAMPLE.com:22", "tcp://example.COM:22", true},
		{"no scheme means tcp", "127.0.0.1:22", "tcp://127.0.0.1:22", true},
		{"discard sink no port", "discard://*", "discard://anything-at-all", true},
		{"bare port pattern", "tcp://22", "tcp://22", true},
		{"ipv6 literal", "tcp://[::1]:22", "tcp://[::1]:22", true},
		{"ipv6 literal mismatch", "tcp://[::1]:22", "tcp://[::2]:22", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchTargetPattern(tc.pattern, tc.child); got != tc.want {
				t.Fatalf("matchTargetPattern(%q, %q) = %v, want %v", tc.pattern, tc.child, got, tc.want)
			}
		})
	}
}

func TestWildcardMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"", "", true},
		{"", "x", false},
		{"*", "", true},
		{"*", "anything", true},
		{"a*c", "abc", true},
		{"a*c", "ac", true},
		{"a*c", "abbbbc", true},
		{"a*c", "abd", false},
		{"?", "x", true},
		{"?", "xy", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"*a*b*c*", "xxaxxbxxcxx", true},
		{"*a*b*c*", "xxaxxcxx", false},
	}
	for _, tc := range cases {
		if got := wildcardMatch(tc.pattern, tc.s); got != tc.want {
			t.Fatalf("wildcardMatch(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}

func TestTargetAllowedEmptyListDeniesEverything(t *testing.T) {
	if targetAllowed("tcp://127.0.0.1:22", nil) {
		t.Fatal("an empty allowed_targets list must deny every request")
	}
	if targetAllowed("tcp://127.0.0.1:22", []string{"  ", ""}) {
		t.Fatal("blank-only patterns must deny every request")
	}
	if !targetAllowed("tcp://127.0.0.1:22", []string{"tcp://127.0.0.1:22"}) {
		t.Fatal("an exact pattern must allow its endpoint")
	}
}

// ---------------------------------------------------------------------------
// Session events
// ---------------------------------------------------------------------------

// eventRecorder installs a handler that fans SessionEvents into a channel. It
// must be called before Start; the channel is buffered generously so the
// test's own scheduling never drops an event.
func startRecordingServer(t *testing.T, cfg ServerConfig, dial TargetDialer) (*fakeEndpoint, *Server, <-chan SessionEvent) {
	t.Helper()
	cEp, sEp := newFakeLink("client", "server", testRecordLimit)
	srv, err := NewServerWithTransport(cfg, sEp, dial)
	if err != nil {
		t.Fatalf("NewServerWithTransport: %v", err)
	}
	events := make(chan SessionEvent, 64)
	srv.SetEventHandler(func(ev SessionEvent) { events <- ev })
	go func() { _ = srv.Start() }()
	t.Cleanup(srv.Close)
	return cEp, srv, events
}

func waitSessionEvent(t *testing.T, events <-chan SessionEvent, kind SessionEventKind, timeout time.Duration) SessionEvent {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case ev := <-events:
			if ev.Kind == kind {
				return ev
			}
		case <-deadline:
			t.Fatalf("timed out after %v waiting for a %s event", timeout, kind)
			return SessionEvent{}
		}
	}
}

func TestServerEmitsEstablishedThenClosed(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cEp, srv, events := startRecordingServer(t,
		ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}

	est := waitSessionEvent(t, events, SessionEstablished, 3*time.Second)
	if est.SessionID == 0 {
		t.Fatal("established event carried a zero session ID")
	}
	if est.Network != "tcp" {
		t.Fatalf("established network = %q, want tcp", est.Network)
	}
	if est.Address != backend {
		t.Fatalf("established address = %q, want %q", est.Address, backend)
	}
	if srv.Stats().Sessions != 1 {
		t.Fatalf("live sessions = %d, want 1", srv.Stats().Sessions)
	}

	_ = conn.Close()
	closed := waitSessionEvent(t, events, SessionClosed, 3*time.Second)
	if closed.SessionID != est.SessionID {
		t.Fatalf("closed event session = 0x%08X, want 0x%08X", closed.SessionID, est.SessionID)
	}
}

func TestServerEmitsTargetDenied(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	// AllowedTargets is deliberately empty: every client-requested endpoint is
	// denied, so the SYN is dropped and the only observability is the event.
	cEp, srv, events := startRecordingServer(t,
		ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)

	const requested = "tcp://127.0.0.1:22"
	sendTestSYN(t, cEp, "secret", requested, time.Now().Unix(), randomNonce(t))

	ev := waitSessionEvent(t, events, SessionTargetDenied, 3*time.Second)
	if ev.Detail != requested {
		t.Fatalf("denied detail = %q, want %q", ev.Detail, requested)
	}
	if ev.Network != "tcp" || ev.Address != "127.0.0.1:22" {
		t.Fatalf("denied event network/address = %q/%q", ev.Network, ev.Address)
	}
	if srv.Stats().Sessions != 0 {
		t.Fatalf("a denied request must not create a session (got %d)", srv.Stats().Sessions)
	}
	// Denied SYNs are silently dropped: no ACK comes back.
	cEp.assertSilent(t, 150*time.Millisecond)
}

func TestServerEmitsAuthRejected(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cEp, srv, events := startRecordingServer(t,
		ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer conn.Close()
	est := waitSessionEvent(t, events, SessionEstablished, 3*time.Second)

	// A structurally valid DATA record for a live session whose AEAD tag is
	// garbage: the shape check passes, authentication must not.
	forged := []byte("forged payload")
	rec := &Record{
		Magic: MagicDefault, Version: Version, Cmd: CmdData,
		SessionID: est.SessionID, PacketNo: 1, Seq: 1, Data: forged,
	}
	wire, err := rec.Marshal(testRecordLimit)
	if err != nil {
		t.Fatalf("marshal forged record: %v", err)
	}
	pokeRecord(t, cEp, wire)

	ev := waitSessionEvent(t, events, SessionAuthRejected, 3*time.Second)
	if ev.SessionID != est.SessionID {
		t.Fatalf("auth-rejected session = 0x%08X, want 0x%08X", ev.SessionID, est.SessionID)
	}
	if srv.Stats().AuthFailures == 0 {
		t.Fatal("AuthFailures counter did not advance")
	}
}

func TestServerEmitsReplayDropped(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cEp, srv, events := startRecordingServer(t,
		ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)

	// Capture every client->server record verbatim while letting it through.
	// A mutex is required: several client goroutines may be poking at once, and
	// the Data records are interleaved with keepalive/poll traffic.
	sEp := cEp.peer
	var (
		capMu    sync.Mutex
		captured [][]byte
	)
	sEp.SetInboundFilter(func(p fakePacket) bool {
		if p.isPoke {
			capMu.Lock()
			captured = append(captured, append([]byte(nil), p.data...))
			capMu.Unlock()
		}
		return false
	})

	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer conn.Close()
	waitSessionEvent(t, events, SessionEstablished, 3*time.Second)

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("replay-me")); err != nil {
		t.Fatal(err)
	}
	one := make([]byte, 1)
	if _, err := conn.Read(one); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	// Find a captured DATA record. Re-injecting it verbatim must be rejected by
	// the replay window, not re-delivered to the target.
	capMu.Lock()
	snapshot := append([][]byte(nil), captured...)
	capMu.Unlock()

	var replayed []byte
	for _, wire := range snapshot {
		rec, err := ParseOwned(wire, MagicDefault, testRecordLimit)
		if err == nil && rec.Cmd == CmdData {
			replayed = wire
			break
		}
	}
	if replayed == nil {
		t.Fatalf("no DATA record was captured among %d client records", len(snapshot))
	}
	pokeRecord(t, cEp, replayed)

	ev := waitSessionEvent(t, events, SessionReplayDropped, 3*time.Second)
	if ev.SessionID == 0 {
		t.Fatal("replay-dropped event carried a zero session ID")
	}
	if srv.Stats().ReplayDrops == 0 {
		t.Fatal("ReplayDrops counter did not advance")
	}
}

func TestServerCountsDecodeFailures(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cEp, srv, _ := startRecordingServer(t,
		ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)

	// Junk that is far too short to be a record.
	pokeRecord(t, cEp, []byte("nope"))

	deadline := time.Now().Add(2 * time.Second)
	for srv.Stats().DecodeFailures == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if srv.Stats().DecodeFailures == 0 {
		t.Fatal("junk input did not increment DecodeFailures")
	}
}

// ---------------------------------------------------------------------------
// Handshake idempotency (SYN cache)
// ---------------------------------------------------------------------------

func TestServerSynReplayResendsCachedAck(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cEp, srv, _ := startRecordingServer(t,
		ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)

	nonce := randomNonce(t)
	ts := time.Now().Unix()
	sendTestSYN(t, cEp, "secret", "", ts, nonce)
	first := readRecord(t, cEp, 3*time.Second)
	if first.Cmd != CmdHandshakeAck {
		t.Fatalf("first reply cmd = 0x%02X, want CmdHandshakeAck", first.Cmd)
	}

	// Byte-identical SYN retransmission: the cached ACK is resent and no second
	// session is created.
	sendTestSYN(t, cEp, "secret", "", ts, nonce)
	second := readRecord(t, cEp, 3*time.Second)
	if second.Cmd != CmdHandshakeAck {
		t.Fatalf("second reply cmd = 0x%02X, want CmdHandshakeAck", second.Cmd)
	}
	if second.SessionID != first.SessionID {
		t.Fatalf("replayed SYN got session 0x%08X, want the cached 0x%08X", second.SessionID, first.SessionID)
	}
	if n := srv.Stats().Sessions; n != 1 {
		t.Fatalf("live sessions = %d, want 1 (a replayed SYN must not dial twice)", n)
	}
}

func TestServerRejectsSYNWithStaleTimestamp(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cEp, srv, _ := startRecordingServer(t,
		ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)

	// 10 minutes in the past is well outside the +-300s acceptance window.
	sendTestSYN(t, cEp, "secret", "", time.Now().Add(-10*time.Minute).Unix(), randomNonce(t))
	cEp.assertSilent(t, 200*time.Millisecond)
	if srv.Stats().Sessions != 0 {
		t.Fatalf("a stale SYN must not establish a session (got %d)", srv.Stats().Sessions)
	}
}

func TestServerRejectsSYNWithBadMAC(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cEp, srv, _ := startRecordingServer(t,
		ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"right"}}, nil)

	// Sealed with the wrong PSK: the HMAC check must fail and no session appear.
	sendTestSYN(t, cEp, "wrong", "", time.Now().Unix(), randomNonce(t))
	cEp.assertSilent(t, 200*time.Millisecond)
	if srv.Stats().Sessions != 0 {
		t.Fatalf("a bad-MAC SYN must not establish a session (got %d)", srv.Stats().Sessions)
	}
}

// ---------------------------------------------------------------------------
// Internal helpers with observable contracts
// ---------------------------------------------------------------------------

func TestServerAllocateSessionIDIsUnique(t *testing.T) {
	a, _ := newFakeLink("client", "server", testRecordLimit)
	srv, err := NewServerWithTransport(ServerConfig{Passwords: []string{"x"}}, a, nil)
	if err != nil {
		t.Fatal(err)
	}

	const n = 256
	seen := make(map[uint32]struct{}, n)
	for i := 0; i < n; i++ {
		sid, err := srv.allocateSessionID()
		if err != nil {
			t.Fatalf("allocateSessionID: %v", err)
		}
		if sid == 0 {
			t.Fatal("allocateSessionID returned 0 (reserved: zero is 'no session')")
		}
		if _, dup := seen[sid]; dup {
			t.Fatalf("allocateSessionID returned 0x%08X twice", sid)
		}
		seen[sid] = struct{}{}
		srv.sessions.Store(sid, &ServerSession{sessionID: sid})
	}
}

func TestSynLimiterRateLimitsPerIP(t *testing.T) {
	lim := newSynLimiter(5, 20)
	now := time.Now()

	allowed := 0
	for i := 0; i < 100; i++ {
		if lim.Allow("192.0.2.7", now) {
			allowed++
		}
	}
	if allowed == 0 || allowed > 20 {
		t.Fatalf("burst allowance = %d, want 1..20", allowed)
	}

	// A different source IP has its own bucket.
	if !lim.Allow("192.0.2.8", now) {
		t.Fatal("a fresh source IP must not inherit another IP's bucket")
	}
}
