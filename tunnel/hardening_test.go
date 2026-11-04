package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// Regression tests for the hardening review fixes. Each one pins a failure
// mode that was reachable in the wild:
//
//   - one unauthenticated oversized ICMP datagram used to end the session
//     layer's only receive loop (server AND client) permanently;
//   - an authenticated-but-hostile Ack near 2^64 used to drive handleAck's
//     cumulative retirement loop essentially forever while holding the
//     unacked mutex — on the single receive loop, freezing the whole end;
//   - the ping-socket pump used to queue Echo payloads above the receive
//     ceiling, where each one drained a queue slot before being rejected.

// injectOversizedJunk delivers one oversized (record-limit-plus) garbage
// datagram to an endpoint: exactly the shape an attacker's oversized Echo takes
// after the carrier hands it up.
func injectOversizedJunk(t *testing.T, ep *fakeEndpoint) {
	t.Helper()
	junk := make([]byte, testRecordLimit+128)
	for i := range junk {
		junk[i] = 0xA5
	}
	ep.deliver(fakePacket{data: junk, path: PathID{Peer: ep.addr}})
}

// readTestReply waits for one inbound record on the endpoint.
func readTestReply(t *testing.T, ep *fakeEndpoint, timeout time.Duration) *Record {
	t.Helper()
	raw := make([]byte, testRecordLimit)
	n, _ := ep.readWithin(t, raw, timeout) // fatals on timeout
	rec, err := ParseOwned(raw[:n], MagicDefault, testRecordLimit)
	if err != nil {
		t.Fatalf("%s: parse reply: %v", ep.name, err)
	}
	return rec
}

// TestServerReadLoopSurvivesOversizedRecord pins the receive-loop fix: junk
// that the carrier refuses to deliver (ErrRecordTooLarge) must be a dropped
// datagram, never the end of the server's only receive loop.
func TestServerReadLoopSurvivesOversizedRecord(t *testing.T) {
	cEp, sEp, _ := newTestServer(t, ServerConfig{TargetAddr: "discard://", Passwords: []string{"secret"}}, nil)

	// The junk is delivered to the SERVER's inbound endpoint before any
	// session exists: the worst case, where the loop has nothing else to do
	// but die.
	injectOversizedJunk(t, sEp)

	// A legitimate handshake right after must still establish.
	nonce := randomNonce(t)
	sendTestSYN(t, cEp, "secret", "", time.Now().Unix(), nonce)
	rec := readTestReply(t, cEp, 3*time.Second)
	if rec.Cmd != CmdHandshakeAck {
		t.Fatalf("cmd = %#02x, want handshake ACK", rec.Cmd)
	}
}

// TestClientReadLoopSurvivesOversizedRecord is the client mirror of the server
// fix: an oversized Echo Reply (spoofable off-path, no handshake needed) must
// not kill the client's receive loop; the next handshake must come up.
func TestClientReadLoopSurvivesOversizedRecord(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cEp, _, _ := newTestServer(t, ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}}, nil)
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}}, cEp)

	// Injected before the lazy receive loop starts, so it is the very first
	// thing the loop sees.
	injectOversizedJunk(t, cEp)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatalf("DialTunnel after oversized junk: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	want := []byte("still alive")
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

// newAckTestServerSession builds a minimal ServerSession in the state
// handleAck finds right after a DATA send: one outstanding record (seq 1).
func newAckTestServerSession(t *testing.T) *ServerSession {
	t.Helper()
	sess := &ServerSession{
		server:    &Server{},
		frameKeys: &FrameKeys{},
		rttEst:    newRTTEstimator(200*time.Millisecond, rtoFloorNet, 10*time.Second),
	}
	sess.sendSeq.Store(2)
	sess.unackedCond = sync.NewCond(&sess.unackedMu)
	sess.unacked = map[uint64]*unackedPkt{
		1: {wire: []byte("wire"), firstSent: time.Now(), sentTime: time.Now(), rto: time.Second},
	}
	sess.unackedLow = 1
	return sess
}

// newAckTestClientSession is the client mirror of newAckTestServerSession.
func newAckTestClientSession(t *testing.T) *clientSession {
	t.Helper()
	sess := &clientSession{
		client:     &Client{},
		frameKeys:  &FrameKeys{},
		rttEst:     newRTTEstimator(200*time.Millisecond, rtoFloorNet, 10*time.Second),
		lastActive: time.Now(),
	}
	sess.sendSeq.Store(2)
	sess.unackedCond = sync.NewCond(&sess.unackedMu)
	sess.unacked = map[uint64]*unackedPkt{
		1: {wire: []byte("wire"), firstSent: time.Now(), sentTime: time.Now(), rto: time.Second},
	}
	sess.unackedLow = 1
	return sess
}

// TestServerHandleAckClampsHostileAck pins the clamp: an authenticated-but-
// hostile Ack of 2^64-1 must retire the one outstanding record and return,
// not spin the receive loop for the age of the universe.
func TestServerHandleAckClampsHostileAck(t *testing.T) {
	sess := newAckTestServerSession(t)

	done := make(chan struct{})
	go func() {
		sess.handleAck(^uint64(0)) // must return, not hang
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleAck did not return for Ack=MaxUint64: the retirement loop is unbounded")
	}
	if len(sess.unacked) != 0 {
		t.Fatalf("unacked = %d entries, want the outstanding record retired", len(sess.unacked))
	}
	if sess.unackedLow != 2 {
		t.Fatalf("unackedLow = %d, want 2 (and definitely not a wrapped 0)", sess.unackedLow)
	}
}

// TestClientHandleAckClampsHostileAck is the client mirror: handleAck runs on
// the shared receive loop, so an unbounded loop would freeze every session.
func TestClientHandleAckClampsHostileAck(t *testing.T) {
	sess := newAckTestClientSession(t)

	done := make(chan struct{})
	go func() {
		sess.handleAck(^uint64(0))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleAck did not return for Ack=MaxUint64: the retirement loop is unbounded")
	}
	if len(sess.unacked) != 0 {
		t.Fatalf("unacked = %d entries, want the outstanding record retired", len(sess.unacked))
	}
	if sess.unackedLow != 2 {
		t.Fatalf("unackedLow = %d, want 2 (and definitely not a wrapped 0)", sess.unackedLow)
	}
}

// TestServerHandleAckClampsToHighestSent pins the clamp semantics: an Ack
// claiming a seq far beyond anything sent behaves exactly like an Ack for the
// highest sent seq — it retires what is outstanding (the legitimate cumulative
// reading of an over-large Ack), returns promptly, and never wraps unackedLow.
func TestServerHandleAckClampsToHighestSent(t *testing.T) {
	sess := newAckTestServerSession(t)
	sess.handleAck(1 << 40) // far beyond sendSeq-1: clamped to the highest sent
	if len(sess.unacked) != 0 {
		t.Fatalf("unacked = %d entries, want the outstanding record retired", len(sess.unacked))
	}
	if sess.unackedLow != 2 {
		t.Fatalf("unackedLow = %d, want 2 (and definitely not a wrapped 0)", sess.unackedLow)
	}
}

// TestPingPumpDropsOversizedPayload pins the ping-socket pump gate: an Echo
// payload above the receive ceiling is dropped in the pump and never reaches
// the session's receive loop, so it can neither wedge it nor drain queue slots.
func TestPingPumpDropsOversizedPayload(t *testing.T) {
	p, conn, _ := newMemPingCarrier(t, 0x4000)
	p.recvCeiling = 1400 // as the profile constructors set it

	// One oversized payload and one well-sized record, in that order. The
	// oversized one must vanish; the small one must come through.
	big := make([]byte, 8+2000)
	big[0] = pingTypeV4Reply
	small := make([]byte, 8+64)
	small[0] = pingTypeV4Reply
	conn.inbound <- big
	conn.inbound <- small

	timeout := time.After(2 * time.Second)
	for {
		select {
		case echo := <-p.in:
			if len(echo.Payload) > p.recvCeiling {
				t.Fatalf("pump delivered a %d-byte payload with ceiling %d", len(echo.Payload), p.recvCeiling)
			}
			if len(echo.Payload) == 64 {
				return // the small record arrived: the gate kept working
			}
		case <-timeout:
			t.Fatal("pump never delivered the well-sized record")
		}
	}
}

// TestPingPumpKeepsPayloadsWithoutCeiling documents the convention: a carrier
// built without a profile (ceiling 0) filters nothing, so hand-built carriers
// keep their current behaviour.
func TestPingPumpKeepsPayloadsWithoutCeiling(t *testing.T) {
	p, conn, _ := newMemPingCarrier(t, 0x4000)
	if p.recvCeiling != 0 {
		t.Fatalf("a hand-built carrier must start with ceiling 0, got %d", p.recvCeiling)
	}
	big := make([]byte, 8+2000)
	big[0] = pingTypeV4Reply
	conn.inbound <- big
	select {
	case echo := <-p.in:
		if len(echo.Payload) != 2000 {
			t.Fatalf("payload = %d bytes, want the full 2000 through an unset ceiling", len(echo.Payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pump never delivered with an unset ceiling")
	}
}

// TestSynCacheRemembersAndResetsSource pins the synRecord.src plumbing: a
// completed entry remembers the address it was issued to, and a re-serve after
// TTL expiry starts a fresh entry with the new address.
func TestSynCacheRemembersAndResetsSource(t *testing.T) {
	c := newSynCache()
	var nonce [ClientNonceSize]byte
	copy(nonce[:], "0123456789abcdef")
	key := makeSynCacheKey(nonce, [32]byte{7: 1})

	a := netip.MustParseAddr("203.0.113.1")
	b := netip.MustParseAddr("203.0.113.2")
	now := time.Now()

	if _, owner, src := c.Acquire(key, now, a); !owner || src.IsValid() {
		t.Fatalf("fresh Acquire: owner=%v src=%v, want owner with zero src", owner, src)
	}
	c.Complete(key, []byte("ack"))
	if _, _, src := c.Acquire(key, now, b); src != a {
		t.Fatalf("cached Acquire src = %v, want the original %v", src, a)
	}
	// TTL expiry starts a fresh entry owned by the new source.
	expired := now.Add(synCacheTTL + time.Minute)
	if _, owner, src := c.Acquire(key, expired, b); !owner || src.IsValid() {
		t.Fatalf("post-TTL Acquire: owner=%v src=%v, want a fresh reservation", owner, src)
	}
}

// ---------------------------------------------------------------------------
// Delivery / retransmission engine regression tests (arq.go, deliverLoop,
// enqueue watermark). Each pins a failure mode the redesign could reintroduce.
// ---------------------------------------------------------------------------

// newDeliveryTestServerSession builds a ServerSession wired for delivery-unit
// tests: a discard sink upstream, a tiny receive queue, and clean watermarks.
func newDeliveryTestServerSession(t *testing.T, queueCap int) *ServerSession {
	t.Helper()
	sess := &ServerSession{
		server:        &Server{maxRecvQueue: queueCap},
		targetNetwork: "discard",
		upstream:      newDiscardSink(),
		recvQueue:     make(map[uint64][]byte),
	}
	sess.nextDeliverSeq.Store(1)
	return sess
}

// dataRec builds a DATA-shaped record for the enqueue unit tests.
func dataRec(seq uint64, n int) *Record {
	return &Record{Cmd: CmdData, Seq: seq, Data: make([]byte, n)}
}

// TestEnqueueWatermarkAdvancesOnlyOnHoleFill pins the watermark rule: an
// out-of-order record must NEVER advance the enqueue watermark past the hole
// below it. Advancing would make the retransmission that fills the hole look
// like an already-enqueued duplicate — it would be re-ACKed forever and never
// delivered, stalling the session permanently.
func TestEnqueueWatermarkAdvancesOnlyOnHoleFill(t *testing.T) {
	sess := newDeliveryTestServerSession(t, 512)
	path := PathID{Peer: netip.MustParseAddrPort("192.0.2.7:40000")}

	// Out-of-order first: buffered, but the watermark stays at the hole (1).
	if !sess.enqueueDataFromPath(dataRec(2, 8), path) {
		t.Fatal("out-of-order record must be buffered")
	}
	if got := sess.nextDeliverSeq.Load(); got != 1 {
		t.Fatalf("nextDeliverSeq after out-of-order seq=2 is %d, want 1 (the hole below is still open)", got)
	}
	// The hole-filling record advances across the whole contiguous run.
	if !sess.enqueueDataFromPath(dataRec(1, 8), path) {
		t.Fatal("hole-filling record must be accepted")
	}
	if got := sess.nextDeliverSeq.Load(); got != 3 {
		t.Fatalf("nextDeliverSeq after filling seq=1 is %d, want 3 (1 and 2 are now contiguous)", got)
	}
	// And from here on, a retransmitted seq=1 classifies as a duplicate (the
	// re-ACK branch), never as something to enqueue again.
	if !sess.enqueueDataFromPath(dataRec(1, 8), path) {
		t.Fatal("duplicate of a delivered/enqueued record must be accepted")
	}
	if got := sess.nextDeliverSeq.Load(); got != 3 {
		t.Fatalf("duplicate moved the watermark to %d, want it untouched at 3", got)
	}
}

// TestDeliveryBackpressureRetainsData pins the queue-capacity semantics: a
// record beyond the next expected seq is refused when the queue is full (and
// its packet number is rolled back by the caller), while the hole-filling
// record always gets in — refusing it would stall the session forever with a
// queue full of records sitting after the hole.
func TestDeliveryBackpressureRetainsData(t *testing.T) {
	sess := newDeliveryTestServerSession(t, 4)
	path := PathID{Peer: netip.MustParseAddrPort("192.0.2.7:40000")}

	// Fill the reorder buffer to capacity with records after the hole.
	for seq := uint64(2); seq <= 5; seq++ {
		if !sess.enqueueDataFromPath(dataRec(seq, 8), path) {
			t.Fatalf("buffering seq=%d into an empty queue must succeed", seq)
		}
	}
	if sess.enqueueDataFromPath(dataRec(6, 8), path) {
		t.Fatal("a record beyond the hole must be refused when the queue is full")
	}
	// The hole-filler bypasses the cap: it completes the contiguous run, and
	// the overshoot (one record) is retired by the immediate drain.
	if !sess.enqueueDataFromPath(dataRec(1, 8), path) {
		t.Fatal("the hole-filling record must always be accepted")
	}
	if len(sess.recvQueue) != 5 {
		t.Fatalf("queue holds %d entries, want 5 (cap + the hole-filler)", len(sess.recvQueue))
	}
	// Delivery drains everything contiguously and advances the real progress.
	if !sess.deliverPending() {
		t.Fatal("deliverPending must report work after the hole filled")
	}
	if got := sess.ackedSeq.Load(); got != 5 {
		t.Fatalf("ackedSeq = %d, want 5 (seq 1..5 delivered in order)", got)
	}
	if len(sess.recvQueue) != 0 {
		t.Fatalf("queue holds %d entries after a full drain, want 0", len(sess.recvQueue))
	}
}

// TestEarliestRetransmitDelayTracksDueTime pins the shared deadline arithmetic
// the lazy retransmit loops arm their timers with.
func TestEarliestRetransmitDelayTracksDueTime(t *testing.T) {
	sent := time.Now().Add(-150 * time.Millisecond)
	unacked := map[uint64]*unackedPkt{
		1: {rto: 200 * time.Millisecond, sentTime: sent},
		2: {rto: 600 * time.Millisecond, sentTime: sent.Add(100 * time.Millisecond)},
	}
	d, ok := earliestRetransmitDelay(unacked, 0)
	if !ok {
		t.Fatal("a non-empty outstanding map must produce a deadline")
	}
	// Record 1 is due in 50ms; record 2 in ~550ms. The earliest governs.
	if d <= 0 || d > 100*time.Millisecond {
		t.Fatalf("earliest delay = %v, want ~50ms (record 1 is due first)", d)
	}
	// After the earliest retires, the next record governs.
	delete(unacked, 1)
	d, ok = earliestRetransmitDelay(unacked, 0)
	if !ok || d <= 400*time.Millisecond || d > 550*time.Millisecond {
		t.Fatalf("after retiring record 1, delay = %v (ok=%v), want ~550ms from record 2", d, ok)
	}
	// An empty map reports no deadline at all: the loop must park, not spin.
	delete(unacked, 2)
	if _, ok := earliestRetransmitDelay(unacked, 0); ok {
		t.Fatal("an empty outstanding map must report no deadline")
	}
}

// TestClientNextDeadlineCoversIdle pins that the client's lazy loop stays
// armed even with nothing outstanding: the idle timeout must still fire.
func TestClientNextDeadlineCoversIdle(t *testing.T) {
	s := newAckTestClientSession(t)

	// With the helper's one outstanding record (rto = 1s, just sent), the
	// record's deadline wins over the 75s idle deadline.
	s.unackedMu.Lock()
	pktRTO := s.unacked[1].rto
	d, ok := earliestRetransmitDelay(s.unacked, 0)
	s.unackedMu.Unlock()
	if !ok || d <= 0 || d > pktRTO {
		t.Fatalf("with an outstanding record, delay = %v (ok=%v), want ~%v", d, ok, pktRTO)
	}

	// With nothing outstanding, the idle deadline keeps the loop armed.
	s.unacked = map[uint64]*unackedPkt{}
	d, ok = s.nextDeadline()
	if !ok {
		t.Fatal("the idle deadline must keep the client loop armed")
	}
	if d < clientRecvTimeout-time.Minute || d > clientRecvTimeout {
		t.Fatalf("idle-only deadline = %v, want ~%v", d, clientRecvTimeout)
	}
}

// TestSlowTargetDoesNotStallOtherSessions is the head-of-line-blocking
// regression: a backend that stops reading must stall only its own session's
// delivery goroutine, never the server's single receive loop that every
// session shares. The slow target is a net.Pipe nobody reads, so the session's
// very first backend write blocks (until its own deadline) deterministically;
// meanwhile a healthy session on the same server must round-trip promptly.
func TestSlowTargetDoesNotStallOtherSessions(t *testing.T) {
	echoBackend, stopEcho := tcpEchoServer(t)
	defer stopEcho()

	cEp, _, _ := newTestServer(t, ServerConfig{
		TargetAddr:     "tcp://" + echoBackend,
		AllowedTargets: []string{"tcp://slow"},
		Passwords:      []string{"secret"},
		Logger:         Nop{},
	}, func(ctx context.Context, _ uint32, network, address string) (net.Conn, error) {
		if address == "slow" {
			// clientEnd is never read: the server's write into the pipe
			// blocks until its own backend write deadline.
			serverEnd, clientEnd := net.Pipe()
			t.Cleanup(func() { _ = serverEnd.Close(); _ = clientEnd.Close() })
			return serverEnd, nil
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	})
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}, Logger: Nop{}}, cEp)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	slowConn, err := cli.DialTunnel(ctx, DialOptions{Target: "tcp://slow"})
	if err != nil {
		t.Fatalf("slow dial: %v", err)
	}
	defer slowConn.Close()
	echoConn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatalf("echo dial: %v", err)
	}
	defer echoConn.Close()

	// Take the bait: one record is enough to park the slow session's
	// delivery goroutine inside its backend write.
	go func() { _ = writeAll(slowConn, make([]byte, 4096)) }()
	time.Sleep(200 * time.Millisecond)

	// The healthy session must not care.
	_ = echoConn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := echoConn.Write([]byte("ping")); err != nil {
		t.Fatalf("echo write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(echoConn, got); err != nil {
		t.Fatalf("echo round trip stalled behind the slow target: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("echo = %q, want ping", got)
	}
}
