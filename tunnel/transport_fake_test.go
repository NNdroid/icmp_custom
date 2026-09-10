package tunnel

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// In-memory fake transport.
//
// This is the infrastructure that lets the ENTIRE stack above the carrier
// (record layer, handshake, ARQ, session table, target forwarding) be tested
// end to end on a non-root machine: the project ships no UDP profile, so there
// is no unprivileged real-packet path to drive those tests with.
//
// It models the interesting carrier properties on purpose:
//
//   - records are copied, so a sender may reuse its buffer immediately;
//   - a receiving buffer that is too small is a hard error, mirroring the real
//     ReadRecord contract;
//   - request/reply asymmetry is representable (Poke → reply), so Poller-driven
//     downlink can be exercised;
//   - an inbound filter can drop packets, so loss, one-way paths and full
//     blockage can be simulated deterministically.
//
// It is intentionally in a _test.go file: it must never be shippable.

type fakePacket struct {
	data    []byte
	path    PathID
	isReply bool
	isPoke  bool
	isProbe bool
}

type fakeLink struct {
	a, b *fakeEndpoint
}

type fakeEndpoint struct {
	name  string
	addr  netip.AddrPort
	limit int
	peer  *fakeEndpoint

	inbox  chan fakePacket
	closed chan struct{}
	once   sync.Once

	mu          sync.Mutex
	ident       uint16
	nextSeq     uint16
	pokedSeqs   map[uint16]struct{}
	pollsSent   uint64
	repliesSeen uint64
	writesSent  uint64
	repliesSent uint64
	probesSent  uint64
	dropped     uint64
	filter      func(fakePacket) bool
}

// Compile-time proof that the fake satisfies every carrier capability the
// session layer can discover at runtime.
var (
	_ Transport      = (*fakeEndpoint)(nil)
	_ MaxRecordSizer = (*fakeEndpoint)(nil)
	_ Poller         = (*fakeEndpoint)(nil)
	_ Prober         = (*fakeEndpoint)(nil)
)

// newFakeLink builds a connected pair of endpoints. limit is the record budget
// both report through MaxRecordSize; pass 0 for "no carrier limit".
func newFakeLink(aName, bName string, limit int) (*fakeEndpoint, *fakeEndpoint) {
	a := &fakeEndpoint{
		name: aName, addr: netip.MustParseAddrPort("192.0.2.1:10001"), limit: limit,
		inbox: make(chan fakePacket, 1024), closed: make(chan struct{}),
		pokedSeqs: map[uint16]struct{}{}, ident: 0x7A01,
	}
	b := &fakeEndpoint{
		name: bName, addr: netip.MustParseAddrPort("192.0.2.2:10002"), limit: limit,
		inbox: make(chan fakePacket, 1024), closed: make(chan struct{}),
		pokedSeqs: map[uint16]struct{}{}, ident: 0x7B02,
	}
	a.peer, b.peer = b, a
	return a, b
}

func (e *fakeEndpoint) isClosed() bool {
	select {
	case <-e.closed:
		return true
	default:
		return false
	}
}

// deliver hands a packet to this endpoint, applying its inbound filter first.
func (e *fakeEndpoint) deliver(p fakePacket) {
	e.mu.Lock()
	fn := e.filter
	e.mu.Unlock()
	if fn != nil && fn(p) {
		e.mu.Lock()
		e.dropped++
		e.mu.Unlock()
		return
	}
	select {
	case e.inbox <- p:
	case <-e.closed:
	}
}

// ReadRecord implements Transport.
func (e *fakeEndpoint) ReadRecord(buf []byte) (int, PathID, error) {
	select {
	case <-e.closed:
		return 0, PathID{}, ErrClosed
	case p := <-e.inbox:
		if len(p.data) > len(buf) {
			return 0, PathID{}, fmt.Errorf("%w: record is %d bytes, buffer is %d", ErrRecordTooLarge, len(p.data), len(buf))
		}
		if p.isReply {
			e.mu.Lock()
			if _, ok := e.pokedSeqs[p.path.Seq]; ok {
				e.repliesSeen++
				delete(e.pokedSeqs, p.path.Seq)
			}
			e.mu.Unlock()
		}
		return copy(buf, p.data), p.path, nil
	}
}

// WriteRecord implements Transport. `to` is ignored: a fake link is
// point-to-point, which is exactly the topology the session layer assumes.
func (e *fakeEndpoint) WriteRecord(rec []byte, _ netip.AddrPort) error {
	if e.isClosed() {
		return ErrClosed
	}
	e.mu.Lock()
	e.writesSent++
	e.mu.Unlock()
	e.peer.deliver(fakePacket{data: append([]byte(nil), rec...), path: PathID{Peer: e.addr}})
	return nil
}

// ReplyRecord implements Transport: the path is mirrored verbatim.
func (e *fakeEndpoint) ReplyRecord(rec []byte, path PathID) error {
	if e.isClosed() {
		return ErrClosed
	}
	e.mu.Lock()
	e.repliesSent++
	e.mu.Unlock()
	e.peer.deliver(fakePacket{data: append([]byte(nil), rec...), path: path, isReply: true})
	return nil
}

// Poke implements Poller: it emits a request carrying payload and records the
// sequence so a later reply can be counted.
func (e *fakeEndpoint) Poke(payload []byte, _ netip.AddrPort) (uint16, error) {
	if e.isClosed() {
		return 0, ErrClosed
	}
	e.mu.Lock()
	e.nextSeq++
	if e.nextSeq == 0 {
		e.nextSeq = 1
	}
	seq := e.nextSeq
	e.pokedSeqs[seq] = struct{}{}
	e.pollsSent++
	ident := e.ident
	e.mu.Unlock()

	e.peer.deliver(fakePacket{
		data:   append([]byte(nil), payload...),
		path:   PathID{Peer: e.addr, Ident: ident, Seq: seq},
		isPoke: true,
	})
	return seq, nil
}

// PollStats implements Poller.
func (e *fakeEndpoint) PollStats() (uint64, uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.pollsSent, e.repliesSeen
}

// Probe implements Prober.
func (e *fakeEndpoint) Probe(payload []byte, _ netip.AddrPort) error {
	if e.isClosed() {
		return ErrClosed
	}
	e.mu.Lock()
	e.probesSent++
	ident := e.ident
	e.mu.Unlock()
	e.peer.deliver(fakePacket{
		data:    append([]byte(nil), payload...),
		path:    PathID{Peer: e.addr, Ident: ident},
		isProbe: true,
	})
	return nil
}

// MaxRecordSize implements MaxRecordSizer.
func (e *fakeEndpoint) MaxRecordSize() int { return e.limit }

// LocalID implements Transport.
func (e *fakeEndpoint) LocalID() string { return e.name }

// RemoteID implements Transport.
func (e *fakeEndpoint) RemoteID() string { return e.peer.name }

// Close implements Transport and unblocks a pending ReadRecord.
func (e *fakeEndpoint) Close() error {
	e.once.Do(func() { close(e.closed) })
	return nil
}

// NetAddr reports the synthetic address used in PathID.Peer.
func (e *fakeEndpoint) NetAddr() netip.AddrPort { return e.addr }

// SetInboundFilter installs a predicate that drops packets when it returns
// true. Passing nil removes the filter. It is the single knob tests use to
// simulate loss, one-way paths and complete blockage.
func (e *fakeEndpoint) SetInboundFilter(fn func(fakePacket) bool) {
	e.mu.Lock()
	e.filter = fn
	e.mu.Unlock()
}

// DropInbound drops every packet the endpoint would otherwise receive. It is
// the "peer is fully blocked" case.
func (e *fakeEndpoint) DropInbound() {
	e.SetInboundFilter(func(fakePacket) bool { return true })
}

// DropReplies drops only replies, i.e. a path on which requests get through but
// responses never come back. It is the "carrier throttled" case.
func (e *fakeEndpoint) DropReplies() {
	e.SetInboundFilter(func(p fakePacket) bool { return p.isReply })
}

// Counters exposes the endpoint's bookkeeping for assertions.
type fakeCounters struct {
	WritesSent  uint64
	RepliesSent uint64
	ProbesSent  uint64
	PollsSent   uint64
	RepliesSeen uint64
	Dropped     uint64
}

func (e *fakeEndpoint) Counters() fakeCounters {
	e.mu.Lock()
	defer e.mu.Unlock()
	return fakeCounters{
		WritesSent:  e.writesSent,
		RepliesSent: e.repliesSent,
		ProbesSent:  e.probesSent,
		PollsSent:   e.pollsSent,
		RepliesSeen: e.repliesSeen,
		Dropped:     e.dropped,
	}
}

// Pending reports how many packets are queued but not yet read.
func (e *fakeEndpoint) Pending() int { return len(e.inbox) }

// ----- test helpers -----

// readWithin reads one record, failing the test if nothing arrives in time.
func (e *fakeEndpoint) readWithin(t *testing.T, buf []byte, timeout time.Duration) (int, PathID) {
	t.Helper()
	type result struct {
		n    int
		path PathID
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		n, path, err := e.ReadRecord(buf)
		ch <- result{n, path, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("%s: ReadRecord: %v", e.name, r.err)
		}
		return r.n, r.path
	case <-time.After(timeout):
		t.Fatalf("%s: no record arrived within %v", e.name, timeout)
		return 0, PathID{}
	}
}

// assertSilent fails the test if any record arrives within the window.
func (e *fakeEndpoint) assertSilent(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case p := <-e.inbox:
		t.Fatalf("%s: expected silence, got a %d-byte packet", e.name, len(p.data))
	case <-time.After(timeout):
	}
}

// bareTransport implements Transport only — no MaxRecordSizer, Poller or
// Prober — so the capability-discovery helpers can be tested against a carrier
// that declares nothing.
type bareTransport struct{}

func (bareTransport) ReadRecord([]byte) (int, PathID, error) { return 0, PathID{}, ErrClosed }
func (bareTransport) WriteRecord([]byte, netip.AddrPort) error {
	return nil
}
func (bareTransport) ReplyRecord([]byte, PathID) error { return nil }
func (bareTransport) LocalID() string                  { return "bare" }
func (bareTransport) RemoteID() string                 { return "bare" }
func (bareTransport) Close() error                     { return nil }

var _ Transport = bareTransport{}

// ----- behaviour tests -----

func TestFakeTransportWriteReadRoundTrip(t *testing.T) {
	a, b := newFakeLink("client", "server", 1450)
	if a.LocalID() != "client" || a.RemoteID() != "server" {
		t.Fatalf("labels: local=%q remote=%q", a.LocalID(), a.RemoteID())
	}
	rec := []byte("a complete v2 record")
	if err := a.WriteRecord(rec, b.NetAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, path := b.readWithin(t, buf, time.Second)
	if string(buf[:n]) != string(rec) {
		t.Fatalf("read %q, want %q", buf[:n], rec)
	}
	if path.Peer != a.NetAddr() {
		t.Fatalf("path peer = %v, want %v", path.Peer, a.NetAddr())
	}
	if got := a.Counters().WritesSent; got != 1 {
		t.Fatalf("writesSent = %d, want 1", got)
	}
}

func TestFakeTransportCopiesSentBytes(t *testing.T) {
	a, b := newFakeLink("a", "b", 0)
	rec := []byte("original")
	if err := a.WriteRecord(rec, b.NetAddr()); err != nil {
		t.Fatal(err)
	}
	for i := range rec {
		rec[i] = 'X' // reuse the caller buffer immediately
	}
	buf := make([]byte, 64)
	n, _ := b.readWithin(t, buf, time.Second)
	if string(buf[:n]) != "original" {
		t.Fatalf("delivered bytes were mutated: %q", buf[:n])
	}
}

func TestFakeTransportReplyMirrorsPath(t *testing.T) {
	a, b := newFakeLink("a", "b", 0)
	if _, err := a.Poke(nil, b.NetAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_, observed := b.readWithin(t, buf, time.Second)
	if observed.Peer != a.NetAddr() || observed.Seq == 0 {
		t.Fatalf("observed path = %+v, want peer %v with a sequence", observed, a.NetAddr())
	}
	if err := b.ReplyRecord([]byte("reply"), observed); err != nil {
		t.Fatal(err)
	}
	_, echoed := a.readWithin(t, buf, time.Second)
	if echoed != observed {
		t.Fatalf("reply path = %+v, want the observed path mirrored verbatim %+v", echoed, observed)
	}
}

func TestFakeTransportReadBufferTooSmall(t *testing.T) {
	a, b := newFakeLink("a", "b", 0)
	if err := a.WriteRecord(make([]byte, 100), b.NetAddr()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.ReadRecord(make([]byte, 10)); err == nil {
		t.Fatal("a too-small read buffer must be a hard error")
	}
}

func TestFakeTransportCloseUnblocksReader(t *testing.T) {
	a, b := newFakeLink("a", "b", 0)
	done := make(chan error, 1)
	go func() {
		_, _, err := b.ReadRecord(make([]byte, 64))
		done <- err
	}()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != ErrClosed {
			t.Fatalf("ReadRecord after Close = %v, want ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock ReadRecord")
	}
	if err := a.WriteRecord([]byte("after close"), b.NetAddr()); err != nil {
		t.Fatalf("writing to a closed peer must not fail the sender: %v", err)
	}
}

func TestFakeTransportPokeAndPollStats(t *testing.T) {
	a, b := newFakeLink("a", "b", 0)
	seq, err := a.Poke([]byte("poll"), b.NetAddr())
	if err != nil || seq == 0 {
		t.Fatalf("Poke = (%d,%v)", seq, err)
	}
	buf := make([]byte, 64)
	_, observed := b.readWithin(t, buf, time.Second)
	if observed.Seq != seq {
		t.Fatalf("observed seq = %d, want %d", observed.Seq, seq)
	}
	if err := b.ReplyRecord([]byte("pong"), observed); err != nil {
		t.Fatal(err)
	}
	a.readWithin(t, buf, time.Second)

	polls, replies := a.PollStats()
	if polls != 1 || replies != 1 {
		t.Fatalf("PollStats = (%d,%d), want (1,1)", polls, replies)
	}
}

func TestFakeTransportPollStatsIgnoreUnrelatedReplies(t *testing.T) {
	a, b := newFakeLink("a", "b", 0)
	// A reply whose sequence was never poked must not count as a poll response.
	if err := b.ReplyRecord([]byte("unsolicited"), PathID{Peer: b.NetAddr(), Seq: 4242}); err != nil {
		t.Fatal(err)
	}
	a.readWithin(t, make([]byte, 64), time.Second)
	if polls, replies := a.PollStats(); polls != 0 || replies != 0 {
		t.Fatalf("PollStats = (%d,%d), want (0,0)", polls, replies)
	}
}

func TestFakeTransportInboundFilter(t *testing.T) {
	a, b := newFakeLink("a", "b", 0)
	// Drop replies *addressed to* a: the request gets through, the response
	// never comes back.
	a.DropReplies()

	if _, err := a.Poke(nil, b.NetAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	b.readWithin(t, buf, time.Second) // the request got through
	if err := b.ReplyRecord([]byte("dropped"), PathID{Peer: b.NetAddr()}); err != nil {
		t.Fatal(err)
	}
	a.assertSilent(t, 50*time.Millisecond)
	if got := a.Counters().Dropped; got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}

	// Now block b entirely.
	b.DropInbound()
	if err := a.WriteRecord([]byte("x"), b.NetAddr()); err != nil {
		t.Fatal(err)
	}
	b.assertSilent(t, 50*time.Millisecond)
}

func TestFakeTransportProbeDelivered(t *testing.T) {
	a, b := newFakeLink("server", "client", 0)
	if err := a.Probe([]byte("reverse"), b.NetAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, _ := b.readWithin(t, buf, time.Second)
	if string(buf[:n]) != "reverse" {
		t.Fatalf("probe payload = %q", buf[:n])
	}
	if got := a.Counters().ProbesSent; got != 1 {
		t.Fatalf("probesSent = %d, want 1", got)
	}
}

func TestTransportCapabilityDiscovery(t *testing.T) {
	_, fake := newFakeLink("a", "b", 1400)
	if got := maxRecordSizeOf(fake); got != 1400 {
		t.Fatalf("maxRecordSizeOf(fake) = %d, want 1400", got)
	}
	if pollerOf(fake) == nil {
		t.Fatal("pollerOf(fake) must find a Poller")
	}
	if proberOf(fake) == nil {
		t.Fatal("proberOf(fake) must find a Prober")
	}

	var bare Transport = bareTransport{}
	if got := maxRecordSizeOf(bare); got != 0 {
		t.Fatalf("maxRecordSizeOf(bare) = %d, want 0", got)
	}
	if pollerOf(bare) != nil {
		t.Fatal("pollerOf(bare) must be nil")
	}
	if proberOf(bare) != nil {
		t.Fatal("proberOf(bare) must be nil")
	}
}
