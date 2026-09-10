package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Construction and configuration
// ---------------------------------------------------------------------------

func TestNewClientRejectsBadConfig(t *testing.T) {
	a, _ := newFakeLink("client", "server", testRecordLimit)

	if _, err := NewClientWithTransport(ClientConfig{Passwords: []string{"x"}, ServerAddr: "192.0.2.2"}, nil); err == nil {
		t.Fatal("a nil transport must be rejected")
	}
	if _, err := NewClientWithTransport(ClientConfig{Passwords: []string{"x"}}, a); !errors.Is(err, ErrConfigRequired) {
		t.Fatalf("empty server: err = %v, want ErrConfigRequired", err)
	}
	if _, err := NewClientWithTransport(ClientConfig{ServerAddr: "192.0.2.2"}, a); !errors.Is(err, ErrConfigRequired) {
		t.Fatalf("empty passwords: err = %v, want ErrConfigRequired", err)
	}
	if _, err := NewClientWithTransport(ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"  "}}, a); !errors.Is(err, ErrConfigRequired) {
		t.Fatalf("blank-only passwords: err = %v, want ErrConfigRequired", err)
	}
	if _, err := NewClientWithTransport(ClientConfig{ServerAddr: "not an address", Passwords: []string{"x"}}, a); err == nil {
		t.Fatal("an unparseable server address must be rejected")
	}
}

func TestNewClientAcceptedAddrForms(t *testing.T) {
	// ICMP binds no port, so a bare host is the natural form and a host:port is
	// accepted with the port ignored (kept as a placeholder).
	cases := []struct {
		in   string
		want string
	}{
		{"192.0.2.2", "192.0.2.2:0"},
		{"192.0.2.2:12345", "192.0.2.2:12345"},
		{"2001:db8::1", "[2001:db8::1]:0"},
		{" 192.0.2.2 ", "192.0.2.2:0"},
	}
	for _, tc := range cases {
		a, _ := newFakeLink("client", "server", testRecordLimit)
		cli, err := NewClientWithTransport(ClientConfig{ServerAddr: tc.in, Passwords: []string{"x"}}, a)
		if err != nil {
			t.Fatalf("server %q: %v", tc.in, err)
		}
		if got := cli.serverAddr.String(); got != tc.want {
			t.Fatalf("server %q parsed to %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNewClientMagicAndSendWindowDefaults(t *testing.T) {
	a, _ := newFakeLink("client", "server", testRecordLimit)
	cli, err := NewClientWithTransport(ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"x"}}, a)
	if err != nil {
		t.Fatal(err)
	}
	if cli.magic != MagicDefault {
		t.Fatalf("magic = 0x%08X, want MagicDefault", cli.magic)
	}
	if cli.cfg.SendWindow != defaultSendWindow {
		t.Fatalf("send window = %d, want %d", cli.cfg.SendWindow, defaultSendWindow)
	}

	const custom = uint32(0x0BADC0DE)
	cli2, err := NewClientWithTransport(ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"x"}, Magic: custom}, a)
	if err != nil {
		t.Fatal(err)
	}
	if cli2.magic != custom {
		t.Fatalf("magic = 0x%08X, want 0x%08X", cli2.magic, custom)
	}
}

func TestClientTuningDefaults(t *testing.T) {
	var cfg ClientConfig
	if got := cfg.pollsInFlight(); got != defaultPollsInFlight {
		t.Fatalf("pollsInFlight = %d, want %d", got, defaultPollsInFlight)
	}
	if got := cfg.pollInterval(); got != defaultPollInterval {
		t.Fatalf("pollInterval = %v, want %v", got, defaultPollInterval)
	}
	if got := cfg.idlePoll(); got != defaultIdlePollInterval {
		t.Fatalf("idlePoll = %v, want %v", got, defaultIdlePollInterval)
	}
	if got := cfg.keepAlive(); got != defaultKeepAlive {
		t.Fatalf("keepAlive = %v, want %v", got, defaultKeepAlive)
	}
	if got := cfg.handshakeAttempts(); got != clientMaxHandshakeAttempts {
		t.Fatalf("handshakeAttempts = %d, want %d", got, clientMaxHandshakeAttempts)
	}
	if got := cfg.handshakeBackoff(); got != clientHandshakeBackoff {
		t.Fatalf("handshakeBackoff = %v, want %v", got, clientHandshakeBackoff)
	}

	// Explicit values must win over the defaults.
	set := ClientConfig{
		PollsInFlight:     9,
		PollInterval:      3 * time.Millisecond,
		IdlePollInterval:  7 * time.Millisecond,
		KeepAlive:         11 * time.Millisecond,
		HandshakeAttempts: 2,
		HandshakeBackoff:  5 * time.Millisecond,
	}
	if set.pollsInFlight() != 9 || set.pollInterval() != 3*time.Millisecond ||
		set.idlePoll() != 7*time.Millisecond || set.keepAlive() != 11*time.Millisecond ||
		set.handshakeAttempts() != 2 || set.handshakeBackoff() != 5*time.Millisecond {
		t.Fatal("explicit tuning values must override the defaults")
	}
}

func TestClientStartRequiresListenAddr(t *testing.T) {
	a, _ := newFakeLink("client", "server", testRecordLimit)
	cli, err := NewClientWithTransport(ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"x"}}, a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)

	// Start is the CLI mode; without a listen address it must refuse rather
	// than silently do nothing. It returns before it would ever block.
	if err := cli.Start(); !errors.Is(err, ErrConfigRequired) {
		t.Fatalf("Start without listen: err = %v, want ErrConfigRequired", err)
	}
}

// ---------------------------------------------------------------------------
// Handshake behaviour
// ---------------------------------------------------------------------------

func TestClientHandshakeTimeoutEmitsRetryEvents(t *testing.T) {
	// No server on the far end: every SYN hits a black hole.
	cEp, _ := newFakeLink("client", "server", testRecordLimit)
	cli, err := NewClientWithTransport(ClientConfig{
		ServerAddr:        "192.0.2.2",
		Passwords:         []string{"secret"},
		HandshakeAttempts: 3,
		HandshakeBackoff:  2 * time.Millisecond,
	}, cEp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)

	retries := make(chan int, 8)
	died := make(chan ClientEvent, 4)
	cli.SetEventHandler(func(ev ClientEvent) {
		switch ev.Kind {
		case HandshakeRetrying:
			retries <- ev.Attempt
		case TunnelDied:
			died <- ev
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := cli.DialTunnel(ctx, DialOptions{}); !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("err = %v, want ErrHandshakeTimeout", err)
	}

	// Three attempts means exactly two retransmit notifications: attempts 2, 3.
	var got []int
	deadline := time.After(2 * time.Second)
	for len(got) < 2 {
		select {
		case a := <-retries:
			got = append(got, a)
		case <-deadline:
			t.Fatalf("only %d retry events seen: %v", len(got), got)
		}
	}
	if got[0] != 2 || got[1] != 3 {
		t.Fatalf("retry attempts = %v, want [2 3]", got)
	}

	// A failed handshake is reported as a died event with a zero session.
	select {
	case ev := <-died:
		if ev.Session != 0 {
			t.Fatalf("handshake-failure died event session = %d, want 0", ev.Session)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no TunnelDied event after a failed handshake")
	}
}

func TestClientHandshakeHonoursContextCancel(t *testing.T) {
	cEp, _ := newFakeLink("client", "server", testRecordLimit)
	cli, err := NewClientWithTransport(ClientConfig{
		ServerAddr:        "192.0.2.2",
		Passwords:         []string{"secret"},
		HandshakeAttempts: 100, // never give up on its own
		HandshakeBackoff:  500 * time.Millisecond,
	}, cEp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if _, err := cli.DialTunnel(ctx, DialOptions{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
}

func TestClientRejectsOversizedTarget(t *testing.T) {
	cEp, _ := newFakeLink("client", "server", testRecordLimit)
	cli, err := NewClientWithTransport(ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)

	big := make([]byte, TargetMaxLen+1)
	for i := range big {
		big[i] = 'a'
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := cli.DialTunnel(ctx, DialOptions{Target: string(big)}); err == nil {
		t.Fatal("an over-long target must be rejected before the SYN is sent")
	}
}

// ---------------------------------------------------------------------------
// Live session surface
// ---------------------------------------------------------------------------

func TestClientEstablishedThenDiedEvents(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cEp, _, _ := newTestServer(t, ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)
	cli, err := NewClientWithTransport(ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cli.Close)

	established := make(chan ClientEvent, 4)
	died := make(chan ClientEvent, 4)
	cli.SetEventHandler(func(ev ClientEvent) {
		switch ev.Kind {
		case TunnelEstablished:
			established <- ev
		case TunnelDied:
			died <- ev
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}

	var est ClientEvent
	select {
	case est = <-established:
	case <-time.After(2 * time.Second):
		t.Fatal("no TunnelEstablished event")
	}
	if est.Session == 0 {
		t.Fatal("established event carried a zero session ID")
	}

	_ = conn.Close()

	select {
	case ev := <-died:
		if ev.Session != est.Session {
			t.Fatalf("died event session = 0x%08X, want 0x%08X", ev.Session, est.Session)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no TunnelDied event after the caller closed the connection")
	}
}

func TestClientStatsTracksLiveSessions(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cEp, _, _ := newTestServer(t, ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)

	if got := cli.Stats().Sessions; got != 0 {
		t.Fatalf("idle client sessions = %d, want 0", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	if got := cli.Stats().Sessions; got != 1 {
		t.Fatalf("live client sessions = %d, want 1", got)
	}

	_ = conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	for cli.Stats().Sessions != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := cli.Stats().Sessions; got != 0 {
		t.Fatalf("client session was not retired: %d still live", got)
	}
}

func TestClientCloseTearsDownLiveTunnels(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cEp, _, _ := newTestServer(t, ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	ts := conn.(*TunnelSession)

	// Client.Close is the embedder's shutdown path: it must unblock every
	// caller waiting on a tunnel without requiring each one to close first.
	cli.Close()

	select {
	case <-ts.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("Client.Close did not tear down the live tunnel")
	}
	if ts.Err() == nil {
		t.Fatal("TunnelSession.Err must be non-nil once Done is closed")
	}

	// A closed client refuses new work.
	if _, err := cli.DialTunnel(context.Background(), DialOptions{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("DialTunnel after Close: err = %v, want ErrClosed", err)
	}
}
