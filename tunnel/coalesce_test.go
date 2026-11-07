package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// Behaviour and regression tests for the throughput work: receive-side record
// splitting (coalescing needs no wire change), send-side batch coalescing with
// its MTU-evidence stamping, and the adaptive pace (slow start + AIMD).

// sealTestRecord builds one structurally valid record for the splitter tests.
// Only the structure matters here — Parse performs no authentication.
func sealTestRecord(t *testing.T, cmd uint8, payload []byte) []byte {
	t.Helper()
	wire := SealMAC(&Record{
		Magic: MagicDefault, Version: Version, Cmd: cmd, Data: payload,
	}, &[32]byte{5: 1}, 0)
	if len(wire) == 0 {
		t.Fatal("failed to seal test record")
	}
	return wire
}

func concatBytes(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// TestForEachRecordSplitsConcatenatedRecords pins the receiver half of
// coalescing: a datagram holding several records is walked in order, a
// garbage-only datagram reports none, and garbage trailing valid records is
// dropped without invalidating the head records.
func TestForEachRecordSplitsConcatenatedRecords(t *testing.T) {
	r1 := sealTestRecord(t, CmdPing, []byte("one"))
	r2 := sealTestRecord(t, CmdPong, []byte("two"))
	r3 := sealTestRecord(t, CmdFin, nil)

	// All three, in wire order.
	var seen []uint8
	ok := forEachRecord(concatBytes(r1, r2, r3), MagicDefault, 65535, func(_ []byte, rec *Record) {
		seen = append(seen, rec.Cmd)
	})
	if !ok || len(seen) != 3 || seen[0] != CmdPing || seen[1] != CmdPong || seen[2] != CmdFin {
		t.Fatalf("forEachRecord = %v (ok=%v), want ping, pong, fin in order", seen, ok)
	}

	// A truncated tail after two valid records: the head records stand, the
	// tail is dropped, and the walk still reports "something was seen".
	seen = nil
	ok = forEachRecord(concatBytes(r1, r2, r3[:len(r3)-4]), MagicDefault, 65535, func(_ []byte, rec *Record) {
		seen = append(seen, rec.Cmd)
	})
	if !ok || len(seen) != 2 || seen[0] != CmdPing || seen[1] != CmdPong {
		t.Fatalf("split walk = %v (ok=%v), want the two head records then a stop", seen, ok)
	}

	// Junk from byte zero: nothing seen.
	ok = forEachRecord([]byte("not a record at all"), MagicDefault, 65535, func(_ []byte, _ *Record) {
		t.Fatal("junk must not reach fn")
	})
	if ok {
		t.Fatal("a junk datagram must report no records")
	}

	// A single record — the historical shape — is exactly one call.
	seen = nil
	ok = forEachRecord(r1, MagicDefault, 65535, func(_ []byte, rec *Record) {
		seen = append(seen, rec.Cmd)
	})
	if !ok || seen[len(seen)-1] != CmdPing {
		t.Fatal("a single-record datagram must parse as exactly one record")
	}
}

// stubBatcher is a RecordBatcher with a fixed budget, standing in for a
// coalescing carrier in the session-level batch tests.
type stubBatcher struct{ budget int }

func (b stubBatcher) BatchBudget() int { return b.budget }

// TestBatchSendCoalescesAndStampsMTU pins the sender half of coalescing at the
// session level: records accumulate into one datagram, an overflowing record
// flushes the batch first, and every constituent's MTU evidence is stamped
// with the batch's wire size.
func TestBatchSendCoalescesAndStampsMTU(t *testing.T) {
	ep, peer := newFakeLink("client", "server", 2048)
	defer ep.Close()
	s := &clientSession{
		client:     &Client{batcher: stubBatcher{budget: 8}, magic: MagicDefault, tr: ep},
		frameKeys:  &FrameKeys{},
		rttEst:     newRTTEstimator(200*time.Millisecond, rtoFloorNet, 10*time.Second),
		lastActive: time.Now(),
	}
	s.unacked = map[uint64]*unackedPkt{
		1: {wire: []byte("a")},
		2: {wire: []byte("b")},
		3: {wire: []byte("c")},
	}
	s.unackedCond = sync.NewCond(&s.unackedMu)

	// Two small records accumulate into one pending batch...
	s.batchSend([]byte("aa"), 1)
	s.batchSend([]byte("bb"), 2)
	s.batchMu.Lock()
	pending := len(s.batch)
	s.batchMu.Unlock()
	if pending != 4 {
		t.Fatalf("pending batch = %d bytes, want 4 (two records, not yet flushed)", pending)
	}

	// ...and flush as ONE datagram, stamping both constituents.
	s.flushBatch()
	got := <-peer.inbox
	if string(got.data) != "aabb" {
		t.Fatalf("flushed datagram = %q, want \"aabb\" (two records concatenated)", got.data)
	}
	for _, seq := range []uint64{1, 2} {
		s.unackedMu.Lock()
		mtuLen := s.unacked[seq].mtuLen
		s.unackedMu.Unlock()
		if mtuLen != 4 {
			t.Fatalf("unacked[%d].mtuLen = %d, want the batch size 4", seq, mtuLen)
		}
	}

	// A record that does not fit flushes the pending batch first. With an
	// 8-byte budget, the 7-byte record cannot join the 2-byte batch.
	s.batchSend([]byte("cc"), 3)
	s.batchSend([]byte("ddddddd"), 3)
	select {
	case got := <-peer.inbox:
		if string(got.data) != "cc" {
			t.Fatalf("overflow flush = %q, want \"cc\"", got.data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an overflowing record must flush the pending batch before appending")
	}
	s.batchMu.Lock()
	pending = len(s.batch)
	s.batchMu.Unlock()
	if pending != 7 {
		t.Fatalf("pending after overflow = %d bytes, want the 7-byte record that triggered the flush", pending)
	}
}

// TestE2ECoalescedDatagramDelivery drives a coalesced datagram — two valid
// AEAD DATA records concatenated — through the REAL server read loop, and
// pins that both records are authenticated, enqueued, delivered to the target
// in order, and echoed back to the client as one round trip.
func TestE2ECoalescedDatagramDelivery(t *testing.T) {
	backend, stop := tcpEchoServer(t)
	defer stop()

	cEp, sEp, _ := newTestServer(t, ServerConfig{TargetAddr: "tcp://" + backend, Passwords: []string{"secret"}, Logger: Nop{}}, nil)
	cli := newTestClient(t, ClientConfig{ServerAddr: "192.0.2.2", Passwords: []string{"secret"}, Logger: Nop{}}, cEp)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer conn.Close()

	// Craft two client DATA records with the session's own send cipher, then
	// hand them to the server as ONE datagram — exactly what a coalescing
	// sender emits.
	var sess *clientSession
	cli.sessions.Range(func(_, v any) bool {
		sess = v.(*clientSession)
		return false
	})
	if sess == nil {
		t.Fatal("no client session after DialTunnel")
	}
	r1 := sess.encodeRecord(&Record{Magic: MagicDefault, Version: Version, Cmd: CmdData, SessionID: sess.sid, Seq: 1, Data: []byte("hello ")})
	r2 := sess.encodeRecord(&Record{Magic: MagicDefault, Version: Version, Cmd: CmdData, SessionID: sess.sid, Seq: 2, Data: []byte("world")})
	if len(r1) == 0 || len(r2) == 0 {
		t.Fatal("failed to seal test records")
	}
	sEp.deliver(fakePacket{data: concatBytes(r1, r2), path: PathID{Peer: cEp.addr}})

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len("hello world"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, []byte("hello world")) {
		t.Fatalf("delivered = %q, want %q", got, "hello world")
	}
}

// TestPacerAdaptivePace pins the AIMD contract: slow start at 2ms, decay to
// the 1ms floor on healthy evidence, and a throttled backoff that never lands
// below the historical default spacing.
func TestPacerAdaptivePace(t *testing.T) {
	p := newPacer(20 * time.Millisecond)

	if got := p.adaptiveInterval(); got != icmpPaceSlowStart {
		t.Fatalf("slow-start pace = %v, want %v (not the 20ms ceiling)", got, icmpPaceSlowStart)
	}
	// Decay: each healthy step is ×4/5; eventually the floor pins it.
	for i := 0; i < 32; i++ {
		p.noteHealthyReply()
	}
	if got := p.adaptiveInterval(); got != icmpPaceFloor {
		t.Fatalf("decayed pace = %v, want the %v floor", got, icmpPaceFloor)
	}
	// Backoff: from the floor, one throttle doubles; sustained throttling
	// settles at the ceiling max(2*base, the historical 20ms) — for the
	// default base that is 40ms.
	p.backoff()
	if got := p.adaptiveInterval(); got != 2*icmpPaceFloor {
		t.Fatalf("backoff from floor = %v, want %v", got, 2*icmpPaceFloor)
	}
	for i := 0; i < 8; i++ {
		p.backoff()
	}
	if got := p.adaptiveInterval(); got != 2*20*time.Millisecond {
		t.Fatalf("sustained backoff = %v, want the %v throttle ceiling", got, 2*20*time.Millisecond)
	}

	// A conservative operator (pace_ms=100) gets a throttle ceiling above the
	// historical minimum: 2*base governs there.
	q := newPacer(100 * time.Millisecond)
	for i := 0; i < 8; i++ {
		q.backoff()
	}
	if got := q.adaptiveInterval(); got != 2*100*time.Millisecond {
		t.Fatalf("conservative base backoff = %v, want the 2*base ceiling", got)
	}
}

// TestICMPProfilePaceModeResolve pins the pace_mode vocabulary.
func TestICMPProfilePaceModeResolve(t *testing.T) {
	for _, mode := range []string{"", "auto", "adaptive", " AUTO "} {
		resolved, err := ICMPProfile{PaceMode: mode}.resolve()
		if err != nil {
			t.Fatalf("pace_mode %q: %v", mode, err)
		}
		if !resolved.paceAuto {
			t.Fatalf("pace_mode %q must resolve to adaptive", mode)
		}
	}
	for _, mode := range []string{"fixed", "static"} {
		resolved, err := ICMPProfile{PaceMode: mode}.resolve()
		if err != nil {
			t.Fatalf("pace_mode %q: %v", mode, err)
		}
		if resolved.paceAuto {
			t.Fatalf("pace_mode %q must resolve to fixed", mode)
		}
	}
	if _, err := (ICMPProfile{PaceMode: "turbo"}).resolve(); !errors.Is(err, ErrConfigRequired) {
		t.Fatalf("invalid pace_mode = %v, want ErrConfigRequired", err)
	}
}

// TestICMPTransportBatchBudgetGatesOnProfile pins the carrier gate: a profile
// without Coalesce disables batching (budget 0); with Coalesce the budget is
// the live record budget. The transport is assembled in-process because the
// platform carrier construction is Linux/Android only.
func TestICMPTransportBatchBudgetGatesOnProfile(t *testing.T) {
	off := &icmpTransport{core: &icmpCore{coalesce: false, mtu: newMTUController(mtuInBand, 1200, 548, 100)}}
	if got := off.BatchBudget(); got != 0 {
		t.Fatalf("BatchBudget without coalesce = %d, want 0", got)
	}
	if batcherOf(off) != nil {
		t.Fatal("batcherOf must return nil for a non-coalescing carrier")
	}

	on := &icmpTransport{core: &icmpCore{coalesce: true, mtu: newMTUController(mtuInBand, 1200, 548, 100)}}
	if got, want := on.BatchBudget(), on.MaxRecordSize(); got != want || got != 1200 {
		t.Fatalf("BatchBudget with coalesce = %d, want the live record budget %d", got, want)
	}
	if batcherOf(on) == nil {
		t.Fatal("batcherOf must return the carrier for a coalescing carrier")
	}
}
