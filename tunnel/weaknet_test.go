package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// Weak-network transport simulator.
//
// It models the carrier properties a real ICMP/UDP path exposes but the
// synchronous in-memory fake link cannot: one-way delay, jitter (which is what
// makes packets arrive out of send order), independent per-record drops, and
// corruption. It is the substrate the CI weaknet benchmarks run on, because
// that is where ARQ recovery, the retransmit backoff and the cumulative-ACK
// drain behave measurably instead of assumed.
//
// The simulator WRAPS two unmodified fakeEndpoints: the peer's inbox, inbound
// filter, counters and ReadRecord are left exactly as the fake transport gives
// them, and only the OUTBOUND hop is replaced by a paced scheduler. Every
// outbound method is wrapped, so nothing can bypass the simulated path while
// still advertising the carrier capabilities the session layer discovers
// (MaxRecordSizer, Poller, Prober, the inbound drop filter).
//
// Reproducibility is partial, and worth being precise about. Drop, jitter and
// corruption decisions come from a SEEDED PRNG, so a profile is the same on
// every machine and a comparison between commits measures the code, not the
// RNG. But the exact RECORDS that get dropped is not pinned: the two direction
// schedulers draw concurrently, and one direction's draws depend on when the
// other direction's replies arrive. That is why the CI weaknet benchmark
// treats the delivery / carrier-drop / drain numbers as the gate and the
// timings as a trend signal rather than a fixed expectation.
//
// As with transport_fake_test.go, this lives in a _test.go file: it must never
// be shippable.
type WeaknetCondition struct {
	// DropPct is the per-record drop probability in percent, applied
	// independently to every record in every direction.
	DropPct float64
	// Delay is the base one-way propagation delay.
	Delay time.Duration
	// Jitter is the per-record delay variance, drawn from [0, Jitter]. It is
	// the source of reordering: packets that sleep different amounts arrive
	// out of send order, which is exactly what the reorder queues exist to
	// absorb. Jitter wider than Delay inverts send order outright.
	Jitter time.Duration
	// CorruptPct is the per-record corruption probability in percent. A
	// corrupted record is a byte-flip that the AEAD rejects on receive, so it
	// reaches the sender as a timeout rather than as a damaged payload.
	CorruptPct float64
	// Seed pins the PRNG so a profile reads the same on every machine. It does
	// not pin which records are dropped: see the type comment above.
	Seed int64
}

// DefaultWeaknetSeed keeps every cell's profiles pinned, so a CI comparison
// between a baseline and a candidate draws from the same distribution rather
// than from whatever the global RNG happens to be.
const DefaultWeaknetSeed = 1

// weakPacket is one scheduled record and the time it must arrive.
type weakPacket struct {
	at     time.Time
	pkt    fakePacket
	target *fakeEndpoint
}

// weaknetStats is one direction's own bookkeeping, separate from the carrier's
// so a benchmark can distinguish "the simulated path dropped it" from "the
// carrier dropped it".
//
// Offered counts every record handed to the simulated path, and is the right
// amplification numerator: on a Poller carrier the session layer sends through
// Poke rather than WriteRecord, so the carrier's writesSent alone undercounts
// the traffic a weak path has to carry. Offered == Delivered + Dropped +
// Corrupted.
type weaknetStats struct {
	Offered   uint64 // records handed to the simulated path
	Dropped   uint64 // records lost to DropPct
	Corrupted uint64 // records flipped to exercise the AEAD
	Delivered uint64 // records handed to the peer's inbox
}

// weaknet is one direction of a weak link: a paced scheduler that applies a
// condition to every outbound record before it reaches the peer's inbox.
//
// Delivery order is driven by each record's arrival time, so two packets with
// different drawn delays arrive out of send order: reordering is a property of
// the condition, not of this harness.
type weaknet struct {
	mu    sync.Mutex
	c     *WeaknetCondition
	rng   *rand.Rand
	done  chan struct{}
	wg    sync.WaitGroup
	queue []weakPacket
	// wake is signalled on enqueue so the scheduler can re-look at the queue
	// instead of sleeping through a record that just arrived sooner than the
	// timer it had armed. Buffered by one: a full buffer means the scheduler
	// has an unconsumed wake-up pending, so a send can never be lost.
	wake chan struct{}

	stats weaknetStats
}

func newWeaknet(c *WeaknetCondition, done chan struct{}) *weaknet {
	return &weaknet{
		c:    c,
		rng:  rand.New(rand.NewPCG(0, uint64(c.Seed))),
		done: done,
		wake: make(chan struct{}, 1),
	}
}

// send applies the condition to one outbound record. It never blocks on the
// simulated path: the scheduler goroutine owns the delay, so a weak path shows
// up as backpressure at the send window instead of as a sleep in the writer.
func (n *weaknet) send(pkt fakePacket, target *fakeEndpoint) {
	n.mu.Lock()
	defer n.mu.Unlock()

	c := n.c
	n.stats.Offered++
	delay := c.Delay
	if c.Jitter > 0 {
		delay += time.Duration(n.rng.Int64N(int64(c.Jitter)))
	}
	if c.DropPct > 0 && n.rng.Float64()*100 < c.DropPct {
		n.stats.Dropped++
		return
	}
	if c.CorruptPct > 0 && n.rng.Float64()*100 < c.CorruptPct {
		n.stats.Corrupted++
		return
	}
	n.queue = append(n.queue, weakPacket{at: time.Now().Add(delay), pkt: pkt, target: target})
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

// run owns the delay: it delivers every queued record once its arrival time is
// due.
func (n *weaknet) run() {
	defer n.wg.Done()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		wp, wait, empty := n.peekDue()
		if wp != nil {
			n.deliver(*wp)
			continue
		}
		if empty {
			wait = time.Second
		}
		rearmTimer(timer, wait)
		select {
		case <-n.done:
			return
		case <-timer.C:
		case <-n.wake:
			// A newly queued record can be due sooner than the timer just armed.
		}
	}
}

// peekDue removes and returns the soonest record whose arrival time has come,
// and reports how long the scheduler should sleep before the next decision.
// Caller must not hold n.mu.
func (n *weaknet) peekDue() (*weakPacket, time.Duration, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.queue) == 0 {
		return nil, 0, true
	}
	best := -1
	bestWait := time.Duration(0)
	for i := range n.queue {
		wait := time.Until(n.queue[i].at)
		if wait <= 0 {
			best = i
			break
		}
		if bestWait == 0 || wait < bestWait {
			bestWait = wait
		}
	}
	if best < 0 {
		return nil, bestWait, false
	}
	wp := n.queue[best]
	n.queue = append(n.queue[:best], n.queue[best+1:]...)
	return &wp, 0, false
}

// rearmTimer sets the timer to fire in `wait` seconds, draining any event the
// timer already delivered so a reset cannot observe a stale one.
func rearmTimer(timer *time.Timer, wait time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(wait)
}

func (n *weaknet) deliver(wp weakPacket) {
	n.mu.Lock()
	n.stats.Delivered++
	n.mu.Unlock()
	wp.target.deliver(wp.pkt)
}

// pending returns records still queued inside the scheduler.
func (n *weaknet) pending() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.queue)
}

// snapshot returns this direction's bookkeeping.
func (n *weaknet) snapshot() weaknetStats {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.stats
}

// weakLink is the pair of endpoints a benchmark dials. Both directions share one
// condition and one stop channel, so a profile reads the same in every direction.
type weakLink struct {
	client, server *weakEndpoint
	done           chan struct{}
	once           sync.Once
}

func newWeakLink(aName, bName string, limit int, c *WeaknetCondition) (*weakEndpoint, *weakEndpoint) {
	w := &weakLink{done: make(chan struct{})}
	a := &weakEndpoint{
		fakeEndpoint: &fakeEndpoint{
			name: aName, addr: netip.MustParseAddrPort("192.0.2.1:10001"), limit: limit,
			inbox: make(chan fakePacket, 1024), closed: make(chan struct{}),
			pokedSeqs: map[uint16]struct{}{}, ident: 0x7A01,
		},
		link: w, net: newWeaknet(c, w.done),
	}
	b := &weakEndpoint{
		fakeEndpoint: &fakeEndpoint{
			name: bName, addr: netip.MustParseAddrPort("192.0.2.2:10002"), limit: limit,
			inbox: make(chan fakePacket, 1024), closed: make(chan struct{}),
			pokedSeqs: map[uint16]struct{}{}, ident: 0x7B02,
		},
		link: w, net: newWeaknet(c, w.done),
	}
	a.peer, b.peer = b.fakeEndpoint, a.fakeEndpoint
	w.client, w.server = a, b
	a.net.wg.Add(1)
	go a.net.run()
	b.net.wg.Add(1)
	go b.net.run()
	return a, b
}

func (w *weakLink) Close() error {
	w.once.Do(func() {
		close(w.done)
		w.client.net.wg.Wait()
		w.server.net.wg.Wait()
	})
	return nil
}

// weakEndpoint is a fakeEndpoint whose outbound hop runs through weaknet. The
// fakeEndpoint is embedded, so ReadRecord, MaxRecordSize, the inbound filter
// and the counters are inherited untouched. Every outbound method is
// overridden to pace its records through the simulator: the Poller path
// included, because on a request-driven carrier that is where all of the
// session traffic actually flows.
type weakEndpoint struct {
	*fakeEndpoint
	net  *weaknet
	link *weakLink
}

// Compile-time proof the wrapper still advertises every carrier capability.
var (
	_ Transport      = (*weakEndpoint)(nil)
	_ MaxRecordSizer = (*weakEndpoint)(nil)
	_ Poller         = (*weakEndpoint)(nil)
	_ Prober         = (*weakEndpoint)(nil)
)

func (w *weakEndpoint) WriteRecord(rec []byte, to netip.AddrPort) error {
	if w.isClosed() {
		return ErrClosed
	}
	w.mu.Lock()
	w.writesSent++
	w.mu.Unlock()
	w.net.send(fakePacket{data: append([]byte(nil), rec...), path: PathID{Peer: w.addr}}, w.peer)
	return nil
}

func (w *weakEndpoint) ReplyRecord(rec []byte, path PathID) error {
	if w.isClosed() {
		return ErrClosed
	}
	w.mu.Lock()
	w.repliesSent++
	w.mu.Unlock()
	w.net.send(fakePacket{data: append([]byte(nil), rec...), path: path, isReply: true}, w.peer)
	return nil
}

// Poke must be overridden as well as WriteRecord. On a Poller carrier the
// session layer sends every session record through Poke, so leaving it
// inherited would route all of the client's traffic straight into the peer's
// inbox and the simulated path would degrade only the server's replies.
func (w *weakEndpoint) Poke(payload []byte, to netip.AddrPort) (uint16, error) {
	if w.isClosed() {
		return 0, ErrClosed
	}
	w.mu.Lock()
	w.nextSeq++
	if w.nextSeq == 0 {
		w.nextSeq = 1
	}
	seq := w.nextSeq
	w.pokedSeqs[seq] = struct{}{}
	w.pollsSent++
	ident := w.ident
	w.mu.Unlock()
	w.net.send(fakePacket{
		data:   append([]byte(nil), payload...),
		path:   PathID{Peer: w.addr, Ident: ident, Seq: seq},
		isPoke: true,
	}, w.peer)
	return seq, nil
}

func (w *weakEndpoint) Probe(payload []byte, to netip.AddrPort) error {
	if w.isClosed() {
		return ErrClosed
	}
	w.mu.Lock()
	w.probesSent++
	ident := w.ident
	w.mu.Unlock()
	w.net.send(fakePacket{
		data:    append([]byte(nil), payload...),
		path:    PathID{Peer: w.addr, Ident: ident},
		isProbe: true,
	}, w.peer)
	return nil
}

// Close stops both schedulers and then closes the endpoint, which unblocks a
// pending ReadRecord.
func (w *weakEndpoint) Close() error {
	if w.link != nil {
		w.link.Close()
	}
	return w.fakeEndpoint.Close()
}

// Pending reports records still in flight, whether queued inside the scheduler
// or already in the peer's inbox but unread. A drain check built on Pending()
// therefore sees both halves.
func (w *weakEndpoint) Pending() int {
	return w.fakeEndpoint.Pending() + w.net.pending()
}

// weaknetCounters pairs a direction's own bookkeeping with the carrier's, so a
// benchmark can assert carrier-drops stay zero while the simulated path is
// expected to drop records.
type weaknetCounters struct {
	WeaknetOffered uint64
	WeaknetDrops   uint64
	WeaknetCorrupt uint64
	WeaknetSent    uint64
	CarrierDrops   uint64
	WritesSent     uint64
	RepliesSent    uint64
	ProbesSent     uint64
	PollsSent      uint64
	RepliesSeen    uint64
}

func (w *weakEndpoint) WeaknetStats() weaknetCounters {
	c := w.Counters()
	n := w.net.snapshot()
	return weaknetCounters{
		WeaknetOffered: n.Offered,
		WeaknetDrops:   n.Dropped,
		WeaknetCorrupt: n.Corrupted,
		WeaknetSent:    n.Delivered,
		CarrierDrops:   c.Dropped,
		WritesSent:     c.WritesSent,
		RepliesSent:    c.RepliesSent,
		ProbesSent:     c.ProbesSent,
		PollsSent:      c.PollsSent,
		RepliesSeen:    c.RepliesSeen,
	}
}

// ----- simulator behaviour tests -----

func TestWeaknetDropsEveryRecord(t *testing.T) {
	a, b := newWeakLink("a", "b", 0, &WeaknetCondition{DropPct: 100, Delay: time.Millisecond, Seed: 1})
	defer a.Close()

	for i := 0; i < 20; i++ {
		if err := a.WriteRecord([]byte(fmt.Sprintf("rec %d", i)), b.NetAddr()); err != nil {
			t.Fatal(err)
		}
	}
	b.assertSilent(t, 30*time.Millisecond)
	if got := a.WeaknetStats().WeaknetDrops; got != 20 {
		t.Fatalf("weaknetDrops = %d, want 20", got)
	}
}

func TestWeaknetDropsAreProbabilistic(t *testing.T) {
	a, b := newWeakLink("a", "b", 0, &WeaknetCondition{DropPct: 50, Delay: time.Millisecond, Seed: 1})
	defer a.Close()

	const total = 100
	for i := 0; i < total; i++ {
		_ = a.WriteRecord([]byte{byte(i)}, b.NetAddr())
	}
	time.Sleep(20 * time.Millisecond)

	st := a.WeaknetStats()
	if st.WritesSent != total {
		t.Fatalf("writesSent = %d, want %d", st.WritesSent, total)
	}
	if st.WeaknetDrops == 0 || st.WeaknetDrops == total {
		t.Fatalf("a 50%% drop rate must lose some but not all records: dropped=%d", st.WeaknetDrops)
	}
}

func TestWeaknetDelaysRecords(t *testing.T) {
	a, b := newWeakLink("a", "b", 0, &WeaknetCondition{Delay: 15 * time.Millisecond, Seed: 1})
	defer a.Close()

	if err := a.WriteRecord([]byte("late"), b.NetAddr()); err != nil {
		t.Fatal(err)
	}
	b.assertSilent(t, 5*time.Millisecond)

	buf := make([]byte, 64)
	n, _, err := b.ReadRecord(buf)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if string(buf[:n]) != "late" {
		t.Fatalf("payload = %q, want %q", buf[:n], "late")
	}
}

func TestWeaknetJitterDeliversEachRecordOnce(t *testing.T) {
	// Jitter wider than the base delay inverts send order outright. Every
	// record must still arrive exactly once.
	a, b := newWeakLink("a", "b", 0, &WeaknetCondition{
		Delay: 2 * time.Millisecond, Jitter: 12 * time.Millisecond, Seed: 7,
	})
	defer a.Close()

	const total = 30
	seen := make([]int, 0, total)
	for i := 0; i < total; i++ {
		_ = a.WriteRecord([]byte{byte(i)}, b.NetAddr())
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(seen) < total {
		if time.Now().After(deadline) {
			t.Fatalf("received %d/%d records before deadline", len(seen), total)
		}
		select {
		case pkt := <-b.inbox:
			if len(pkt.data) != 1 {
				t.Fatalf("record %d has %d bytes", len(seen), len(pkt.data))
			}
			seen = append(seen, int(pkt.data[0]))
		case <-time.After(time.Millisecond):
		}
	}
	dup := make(map[int]bool, total)
	for _, v := range seen {
		if dup[v] {
			t.Fatalf("record %d delivered twice", v)
		}
		dup[v] = true
	}
}

func TestWeaknetCorruptsSomeRecords(t *testing.T) {
	a, b := newWeakLink("a", "b", 0, &WeaknetCondition{CorruptPct: 50, Delay: time.Millisecond, Seed: 1})
	defer a.Close()

	const total = 100
	for i := 0; i < total; i++ {
		_ = a.WriteRecord([]byte{byte(i)}, b.NetAddr())
	}
	time.Sleep(20 * time.Millisecond)

	st := a.WeaknetStats()
	if st.WritesSent != total {
		t.Fatalf("writesSent = %d, want %d", st.WritesSent, total)
	}
	if st.WeaknetCorrupt == 0 || st.WeaknetCorrupt == total {
		t.Fatalf("a 50%% corrupt rate must flip some but not all: corrupt=%d", st.WeaknetCorrupt)
	}
}

// TestWeakLinkDeliversThroughWeaknet proves a weak path still moves records end
// to end, so a benchmark failure can only come from the tunnel and never from
// the simulator refusing to deliver.
func TestWeakLinkDeliversThroughWeaknet(t *testing.T) {
	a, b := newWeakLink("a", "b", 1500, &WeaknetCondition{
		DropPct: 5, Delay: 2 * time.Millisecond, Jitter: time.Millisecond, Seed: 3,
	})
	defer a.Close()

	const total = 200
	const expect = 190
	for i := 0; i < total; i++ {
		if err := a.WriteRecord([]byte{byte(i % 251)}, b.NetAddr()); err != nil {
			t.Fatal(err)
		}
	}
	got := 0
	deadline := time.Now().Add(2 * time.Second)
	for got < expect {
		if time.Now().After(deadline) {
			t.Fatalf("received %d/%d records before deadline", got, expect)
		}
		select {
		case <-b.inbox:
			got++
		case <-time.After(time.Millisecond):
		}
	}
}

// TestWeaknetPacesPokes proves the Poller and Prober paths are degraded too.
// On a request-driven carrier the session layer sends every session record
// through Poke, so a simulator that left Poke inherited from fakeEndpoint would
// route all of the client's traffic straight into the peer's inbox and degrade
// only the server's replies — measuring a path that was never weak.
func TestWeaknetPacesPokes(t *testing.T) {
	a, b := newWeakLink("a", "b", 0, &WeaknetCondition{DropPct: 100, Seed: 1})
	defer a.Close()

	if _, err := a.Poke([]byte("poll"), b.NetAddr()); err != nil {
		t.Fatal(err)
	}
	if err := a.Probe([]byte("probe"), b.NetAddr()); err != nil {
		t.Fatal(err)
	}
	b.assertSilent(t, 20*time.Millisecond)

	st := a.WeaknetStats()
	if st.WeaknetOffered != 2 || st.WeaknetDrops != 2 {
		t.Fatalf("pokes and probes were not routed through the simulated path: offered=%d drops=%d",
			st.WeaknetOffered, st.WeaknetDrops)
	}
	if got := a.Counters().PollsSent; got != 1 {
		t.Fatalf("pollsSent = %d, want 1", got)
	}
	if got := a.Counters().ProbesSent; got != 1 {
		t.Fatalf("probesSent = %d, want 1", got)
	}
	if got := st.CarrierDrops; got != 0 {
		t.Fatalf("carrierDrops = %d, want 0: the drop must be attributed to the simulated path", got)
	}
}

// TestTunnelCompletesUnderWeakLink is the end-to-end guarantee the benchmarks
// assert on: over a lossy, delayed and jittery path the tunnel still hands the
// application back exactly the bytes it wrote. It runs on every `go test`
// because a benchmark that only runs in CI would not catch a break here.
func TestTunnelCompletesUnderWeakLink(t *testing.T) {
	a, b := newWeakLink("client", "server", 1500, &WeaknetCondition{
		DropPct: 5, Delay: 2 * time.Millisecond, Jitter: time.Millisecond, Seed: 11,
	})
	defer a.Close()

	backends := make(chan net.Conn, 1)
	srv, err := NewServerWithTransport(ServerConfig{
		TargetAddr: "tcp://weak.invalid:1", Passwords: []string{"weaknet-psk"}, Logger: Nop{},
	}, b, func(context.Context, uint32, string, string) (net.Conn, error) {
		target, backend := net.Pipe()
		backends <- backend
		return target, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() { _ = srv.Start() }()

	cli, err := NewClientWithTransport(ClientConfig{
		ServerAddr: "192.0.2.2", Passwords: []string{"weaknet-psk"}, Logger: Nop{},
		PollInterval: time.Millisecond, IdlePollInterval: time.Second, KeepAlive: time.Second,
	}, a)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer conn.Close()
	target := <-backends
	defer target.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	_ = target.SetDeadline(time.Now().Add(30 * time.Second))

	payload := []byte("weaknet end-to-end payload")
	// net.Pipe is synchronous: the server's write into the backend blocks until
	// something reads the other end, and the server bounds that write at 5s.
	// Read the backend in parallel with the tunnel write, or the server tears
	// the session down before the payload has gone anywhere.
	echoed := make(chan []byte, 1)
	go func() {
		buf := make([]byte, len(payload))
		n, _ := io.ReadFull(target, buf)
		got := make([]byte, n)
		copy(got, buf[:n])
		echoed <- got
	}()

	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case got := <-echoed:
		if !bytes.Equal(got, payload) {
			t.Fatalf("payload differs: got %q want %q", got, payload)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("payload was never echoed through the weak link")
	}
}
