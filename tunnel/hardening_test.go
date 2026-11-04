package tunnel

import (
	"bytes"
	"context"
	"io"
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
		client:    &Client{},
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
