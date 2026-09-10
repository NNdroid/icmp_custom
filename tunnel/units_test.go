package tunnel

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Small units that the behaviour suites reach only by accident.
//
// These are not coverage-chasing: each one is a contract an embedder or an
// operator depends on — an enum's log text, a String() that appears in an error
// message, a deadline that must survive a reconnect, an eviction policy that
// bounds a table.
// ---------------------------------------------------------------------------

func TestRecordPayloadLenReportsTheWirePayloadLength(t *testing.T) {
	r := &Record{Data: make([]byte, 37)}
	if got := r.PayloadLen(); got != 37 {
		t.Fatalf("PayloadLen = %d, want 37", got)
	}
	if got := (&Record{}).PayloadLen(); got != 0 {
		t.Fatalf("an empty record's PayloadLen = %d, want 0", got)
	}
}

func TestMTUModeStrings(t *testing.T) {
	cases := map[mtuMode]string{
		mtuFixed:   "fixed",
		mtuInBand:  "auto",
		mtuProbe:   "probe",
		mtuMode(9): "unknown",
	}
	for mode, want := range cases {
		if got := mode.String(); got != want {
			t.Fatalf("mtuMode(%d).String() = %q, want %q", mode, got, want)
		}
	}
	// The string must round-trip through the parser, because it is what
	// appears in the config file and in the startup log line.
	for _, mode := range []mtuMode{mtuFixed, mtuInBand, mtuProbe} {
		got, err := parseMTUMode(mode.String())
		if err != nil {
			t.Fatalf("parseMTUMode(%q): %v", mode.String(), err)
		}
		if got != mode {
			t.Fatalf("parseMTUMode(%q) = %v, want %v", mode.String(), got, mode)
		}
	}
}

func TestMTUControllerModeOf(t *testing.T) {
	if got := newMTUController(mtuFixed, 1200, 548, 100).modeOf(); got != mtuFixed {
		t.Fatalf("modeOf = %v, want fixed", got)
	}
	if got := newMTUController(mtuProbe, 1200, 548, 100).modeOf(); got != mtuProbe {
		t.Fatalf("modeOf = %v, want probe", got)
	}
}

func TestSessionAndClientEventKindStrings(t *testing.T) {
	// These appear in operator-visible event output, so every kind must have a
	// readable name rather than a number.
	for kind := SessionEstablished; kind <= SessionTargetDenied; kind++ {
		if s := kind.String(); s == "" || strings.HasPrefix(s, "SessionEventKind(") {
			t.Fatalf("SessionEventKind(%d).String() = %q, want a readable name", kind, s)
		}
	}
	for kind := TunnelEstablished; kind <= HandshakeRetrying; kind++ {
		if s := kind.String(); s == "" || strings.HasPrefix(s, "ClientEventKind(") {
			t.Fatalf("ClientEventKind(%d).String() = %q, want a readable name", kind, s)
		}
	}
	// An out-of-range kind must degrade to a stable placeholder rather than
	// Go's default "%!SessionEventKind(99)" noise in an operator's log line.
	if got := SessionEventKind(99).String(); got != "unknown" {
		t.Fatalf("SessionEventKind(99).String() = %q, want \"unknown\"", got)
	}
	if got := ClientEventKind(99).String(); got != "unknown" {
		t.Fatalf("ClientEventKind(99).String() = %q, want \"unknown\"", got)
	}
}

func TestCarrierStateStrings(t *testing.T) {
	cases := map[CarrierState]string{
		CarrierInit:      "init",
		CarrierUp:        "up",
		CarrierThrottled: "throttled",
		CarrierBlocked:   "blocked",
		CarrierState(77): "unknown",
	}
	for state, want := range cases {
		if got := state.String(); got != want {
			t.Fatalf("CarrierState(%d).String() = %q, want %q", state, got, want)
		}
	}
}

func TestDiscardSinkDeadlines(t *testing.T) {
	s := newDiscardSink()
	defer s.Close()

	// Write deadlines are accepted and ignored: the sink never blocks a write,
	// so there is nothing to time out. It must still honour the read side.
	if err := s.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline = %v, want nil", err)
	}
	if _, err := s.Write([]byte("ignored")); err != nil {
		t.Fatalf("an expired WRITE deadline must not block a sink write: %v", err)
	}
	if err := s.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetDeadline = %v, want nil", err)
	}
	if _, err := s.Read(make([]byte, 8)); err == nil {
		t.Fatal("SetDeadline must apply to reads")
	}
	if got := s.RemoteAddr().String(); got != "discard" {
		t.Fatalf("RemoteAddr().String() = %q, want \"discard\"", got)
	}
}

func TestFixedIDProviderReturnsTheKernelAssignedIdentifier(t *testing.T) {
	// The Android ping socket does not get to choose: the Identifier IS the
	// socket's bound port. The provider therefore returns one value forever,
	// which is why spreading needs more sockets rather than more ids.
	p := fixedID{id: 4242}
	for i := 0; i < 5; i++ {
		if got := p.next(); got != 4242 {
			t.Fatalf("next() = %d, want the fixed 4242", got)
		}
	}
}

func TestPacerSetIntervalReplacesTheSpacing(t *testing.T) {
	p := newPacer(time.Hour)
	if got := p.currentInterval(); got != time.Hour {
		t.Fatalf("initial interval = %v", got)
	}
	p.setInterval(2 * time.Millisecond)
	if got := p.currentInterval(); got != 2*time.Millisecond {
		t.Fatalf("interval after setInterval = %v, want 2ms", got)
	}
	// A non-positive interval would busy-loop; it must fall back, not hang or
	// spin. newPacer's own clamp is 1ms.
	p.setInterval(0)
	if got := p.currentInterval(); got <= 0 {
		t.Fatalf("interval = %v, want a positive fallback", got)
	}
}

func TestPokeBookTracksOutstandingPolls(t *testing.T) {
	b := newPokeBook()
	if b.len() != 0 {
		t.Fatalf("a fresh book has %d entries", b.len())
	}
	b.add(1)
	b.add(2)
	if b.len() != 2 {
		t.Fatalf("len = %d, want 2", b.len())
	}
	// claim is one-shot: a second claim for the same sequence must fail so a
	// duplicated reply cannot be counted twice.
	if _, ok := b.claim(1); !ok {
		t.Fatal("claim must succeed for an outstanding poll")
	}
	if _, ok := b.claim(1); ok {
		t.Fatal("a second claim must fail: the poll is already answered")
	}
	if _, ok := b.claim(99); ok {
		t.Fatal("claiming an unknown sequence must fail")
	}
	if b.len() != 1 {
		t.Fatalf("len after one claim = %d, want 1", b.len())
	}
}

func TestICMPCoreMTUHelpers(t *testing.T) {
	resolved, err := (ICMPProfile{Family: "ipv4", MaxPayload: 1472, MTUMode: "probe", PaceMS: 1}).resolve()
	if err != nil {
		t.Fatal(err)
	}
	ids, err := newPooledIDs("")
	if err != nil {
		t.Fatal(err)
	}
	core := newICMPCore(resolved, testICMPPeer, ids, Nop{})

	if !core.mtuProbeWanted() {
		t.Fatal("mtu_mode=probe must request the active probe")
	}
	// A probe result is stronger than in-band guessing, so it is adopted
	// outright rather than stepped towards.
	core.adoptProbedBudget(1300)
	if got := core.maxRecordSize(); got != 1300 {
		t.Fatalf("budget after adoptProbedBudget = %d, want 1300", got)
	}
	// The kernel refusing a size is the same information, taken earlier.
	core.noteSendTooLarge(1300)
	if got := core.maxRecordSize(); got != 1200 {
		t.Fatalf("budget after noteSendTooLarge = %d, want 1200 (1300 - step)", got)
	}

	fixed, err := (ICMPProfile{Family: "ipv4", MaxPayload: 1472, MTUMode: "fixed", PaceMS: 1}).resolve()
	if err != nil {
		t.Fatal(err)
	}
	fixedCore := newICMPCore(fixed, testICMPPeer, ids, Nop{})
	if fixedCore.mtuProbeWanted() {
		t.Fatal("mtu_mode=fixed must not request the active probe")
	}
}

func TestNoiseCipherStateRoundTrip(t *testing.T) {
	// Two distinct transport keys: Noise splits the handshake into one key per
	// direction, so a cipher state must only ever open its peer's direction.
	sendKey := make([]byte, 32)
	recvKey := make([]byte, 32)
	for i := range sendKey {
		sendKey[i] = byte(i)
		recvKey[i] = byte(0x80 + i)
	}
	// The peer's session has the two keys the other way round, which is what
	// makes one side's send direction the other side's receive direction.
	local, err := newNoiseSession(sendKey, recvKey, [32]byte{})
	if err != nil {
		t.Fatalf("newNoiseSession: %v", err)
	}
	peer, err := newNoiseSession(recvKey, sendKey, [32]byte{})
	if err != nil {
		t.Fatalf("newNoiseSession: %v", err)
	}
	send, recv := local.SendCipher, peer.RecvCipher
	if send == nil || recv == nil {
		t.Fatal("newNoiseSession must build both directions")
	}
	if local.HandshakeHash != ([32]byte{}) {
		t.Fatal("the handshake hash must be carried through verbatim")
	}
	aad := []byte("record header")
	plain := []byte("payload bytes")

	ct := send.Encrypt(1, plain, aad)
	if len(ct) != len(plain)+RecordTagSize {
		t.Fatalf("ciphertext is %d bytes, want len(plain)+%d", len(ct), RecordTagSize)
	}
	got, err := recv.Decrypt(1, ct, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("round trip = %q, want %q", got, plain)
	}
	// The packet number is the nonce, so the wrong one must not open.
	if _, err := recv.Decrypt(2, ct, aad); err == nil {
		t.Fatal("decrypting under the wrong packet number must fail")
	}
	// The associated data is bound: a tampered header must not open either.
	if _, err := recv.Decrypt(1, ct, []byte("other header")); err == nil {
		t.Fatal("decrypting under different associated data must fail")
	}
	// Direction separation: the local receive direction carries the OTHER
	// transport key, so it must not be able to open what the send direction
	// sealed. If split() ever handed out one key for both directions this is
	// the test that catches it.
	if _, err := local.RecvCipher.Decrypt(1, ct, aad); err == nil {
		t.Fatal("the receive direction must not open what the send direction sealed")
	}
}

func TestSynCacheAbortReleasesAReservation(t *testing.T) {
	c := newSynCache()
	var nonce [ClientNonceSize]byte
	copy(nonce[:], "0123456789abcdef")
	key := makeSynCacheKey(nonce, [32]byte{7: 1})

	now := time.Now()
	if _, owner := c.Acquire(key, now); !owner {
		t.Fatal("the first Acquire must own the key")
	}
	if c.Len() != 1 {
		t.Fatalf("Len = %d, want 1", c.Len())
	}
	// A failed handshake must release the reservation, or the nonce would be
	// unusable for the rest of the TTL and the client could never reconnect.
	c.Abort(key)
	if c.Len() != 0 {
		t.Fatalf("Len after Abort = %d, want 0", c.Len())
	}
	if _, owner := c.Acquire(key, now); !owner {
		t.Fatal("a re-acquired key after Abort must own it again")
	}

	// Abort must never remove a COMPLETED entry: that ACK is the idempotency
	// record a retransmitted SYN is answered from.
	c.Complete(key, []byte("ack-frame"))
	c.Abort(key)
	if c.Len() != 1 {
		t.Fatalf("Abort removed a completed entry; Len = %d", c.Len())
	}
	if ack, _ := c.Acquire(key, now); string(ack) != "ack-frame" {
		t.Fatalf("Acquire returned %q, want the cached ack-frame", ack)
	}
}

func TestSynLimiterTracksAndPrunesSources(t *testing.T) {
	l := newSynLimiter(5, 2)
	now := time.Now()
	if !l.Allow("203.0.113.1", now) {
		t.Fatal("the first SYN from a source must be allowed")
	}
	if !l.Allow("203.0.113.2", now) {
		t.Fatal("a different source must be allowed")
	}
	if l.Len() != 2 {
		t.Fatalf("Len = %d, want 2", l.Len())
	}
	// A fresh bucket starts full at burst=2, so the first two SYNs from one
	// source in the same instant pass and the third is refused — that is the
	// whole point of the gate.
	if !l.Allow("203.0.113.1", now) {
		t.Fatal("the second SYN within the burst must be allowed")
	}
	if l.Allow("203.0.113.1", now) {
		t.Fatal("a third SYN within the burst must be refused")
	}
	// Nothing else learned a limit: the other source still has its own bucket.
	if l.Len() != 2 {
		t.Fatalf("Len = %d, want 2", l.Len())
	}
	// Time passing refills the bucket at 5 tokens/s.
	if !l.Allow("203.0.113.1", now.Add(time.Second)) {
		t.Fatal("the bucket must refill over time")
	}
	// A burst below 1 and a non-positive rate fall back to safe defaults
	// rather than refusing every SYN forever.
	d := newSynLimiter(0, 0)
	if d.rate != 5 || d.burst != 10 {
		t.Fatalf("newSynLimiter(0, 0) = rate %v burst %v, want 5 / 10", d.rate, d.burst)
	}
}

func TestAutoReconnectDeadlinesSurviveAReconnect(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cEp, _, _ := newTestServer(t, ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)

	ar := NewAutoReconnect(cli, DialOptions{}, nil)
	defer ar.Close()

	// RestartCount starts at zero and only advances when a live tunnel is
	// dropped and redialed.
	if got := ar.RestartCount(); got != 0 {
		t.Fatalf("RestartCount = %d, want 0 before any reconnect", got)
	}

	// Before the first tunnel exists the deadlines are remembered, not lost:
	// a caller that sets them then triggers a lazy dial must still see them.
	if err := ar.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline with no connection: %v", err)
	}
	if _, err := ar.Write([]byte("prime")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := ar.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := ar.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	// An expired deadline must surface as a timeout, not as silence.
	if err := ar.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := ar.Read(make([]byte, 1)); err == nil {
		t.Fatal("an expired read deadline must fail")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("Read after an expired deadline = %v, want a timeout", err)
	}

	// The placeholder addresses are what a caller sees before the first dial;
	// they must be non-nil or a logging caller panics.
	if ar.LocalAddr() == nil || ar.RemoteAddr() == nil {
		t.Fatal("AutoReconnect must never return a nil address")
	}
	if got := ar.LocalAddr().Network(); got != "icmp" {
		t.Fatalf("LocalAddr().Network() = %q, want \"icmp\"", got)
	}
	if got := ar.LocalAddr().String(); got != "icmp-tunnel" {
		t.Fatalf("LocalAddr().String() = %q, want \"icmp-tunnel\"", got)
	}
}

func TestClientServeConnReportsAHandshakeFailure(t *testing.T) {
	// serveConn is the accepted-connection path. A handshake that never
	// completes must close the connection instead of leaking it: the local end
	// would otherwise hang forever waiting for bytes that cannot come.
	cEp, _, _ := newTestServer(t, ServerConfig{
		TargetAddr:     "tcp://127.0.0.1:1",
		AllowedTargets: []string{"tcp://127.0.0.1:22"},
		Passwords:      []string{"secret"},
	}, nil)
	cli := newTestClient(t, ClientConfig{
		ServerAddr: "192.0.2.2",
		Passwords:  []string{"secret"},
		// One short attempt: the server drops the denied SYN silently, so the
		// handshake can only ever end by timeout. The default ladder would
		// keep this test busy for tens of seconds.
		HandshakeAttempts: 1,
		HandshakeBackoff:  50 * time.Millisecond,
	}, cEp)

	local, remote := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		cli.serveConn(remote, "tcp://127.0.0.1:23")
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveConn did not return for a handshake that can never complete")
	}
	// The local end must observe the close rather than block forever:
	// serveConn owns the remote end and must close it on the way out.
	readErr := make(chan error, 1)
	go func() {
		_, err := local.Read(make([]byte, 1))
		readErr <- err
	}()
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("the accepted connection must have been closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the accepted connection was left open after a failed handshake")
	}
	_ = local.Close()
}

func TestEventBusDropsRatherThanBlocks(t *testing.T) {
	// Producers run on hot receive paths and must never be slowed by a
	// consumer. Overflow is counted, and the counter is the only way an
	// operator learns the handler is too slow.
	b := newEventBus[int](2)
	defer b.close()

	release := make(chan struct{})
	b.setHandler(func(int) { <-release })

	for i := 0; i < 50; i++ {
		b.emit(i)
	}
	if got := b.droppedCount(); got == 0 {
		t.Fatal("a full event queue must drop and count rather than block")
	}
	if got := b.droppedCount(); got > 50 {
		t.Fatalf("droppedCount = %d, more than were emitted", got)
	}
	close(release)
}

func TestEventBusEmitAfterCloseIsSilent(t *testing.T) {
	b := newEventBus[int](4)
	b.close()
	// Emitting after close must be a no-op, not a panic on a closed channel:
	// session teardown races with in-flight emits by construction.
	for i := 0; i < 5; i++ {
		b.emit(i)
	}
	if got := b.droppedCount(); got != 0 {
		t.Fatalf("droppedCount = %d, want 0 (a closed bus discards silently)", got)
	}
}

func TestEventBusRecoversAHandlerPanic(t *testing.T) {
	b := newEventBus[int](8)
	defer b.close()

	got := make(chan int, 4)
	b.setHandler(func(v int) {
		if v == 1 {
			panic("embedder bug")
		}
		got <- v
	})
	b.emit(1) // panics inside the handler
	b.emit(2) // must still be delivered: one bad event cannot kill the stream

	select {
	case v := <-got:
		if v != 2 {
			t.Fatalf("delivered %d, want 2", v)
		}
	case <-time.After(time.Second):
		t.Fatal("a panicking handler took the whole event stream down")
	}
}

func TestPathIDAndPeerHelpers(t *testing.T) {
	// ipOf is the key the SYN rate limiter uses, and it must see through
	// IPv4-in-IPv6 so one host cannot get two buckets by alternating forms.
	v4 := netip.MustParseAddrPort("192.0.2.7:0").Addr()
	v4mapped := netip.MustParseAddrPort("[::ffff:192.0.2.7]:0").Addr()
	if got, want := ipOf(netip.AddrPortFrom(v4, 0)), ipOf(netip.AddrPortFrom(v4mapped, 0)); got != want {
		t.Fatalf("ipOf(v4)=%q but ipOf(v4-mapped)=%q; they must be one bucket", got, want)
	}
	if got := ipOf(netip.AddrPortFrom(v4, 0)); got != "192.0.2.7" {
		t.Fatalf("ipOf = %q, want \"192.0.2.7\"", got)
	}
}

func TestContextCancellationStopsThePacer(t *testing.T) {
	p := newPacer(time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	_ = p.wait(context.Background()) // first slot is free
	cancel()
	if err := p.wait(ctx); err == nil {
		t.Fatal("a cancelled context must stop the pacer")
	}
}
