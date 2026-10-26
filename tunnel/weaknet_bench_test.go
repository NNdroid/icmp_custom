package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// weaknetBenchmarkBlock is the payload each worker delivers, and weaknetBenchmarkBlocks
// is how many blocks make one cell.
//
// Twenty blocks of 32KiB is 640KiB: about two full send windows at the smallest
// record size, which is enough for the window, the reorder queue and the
// cumulative-ACK drain to all be exercised, but still short enough that a cell
// finishes inside the CI job's timeout even when the tail record pays the full
// retransmit backoff. The cell size is the workload; -benchtime 1x runs it
// once.
const (
	weaknetBenchmarkBlock  = 32 << 10
	weaknetBenchmarkBlocks = 20
)

// weaknetProfile is one degraded-path profile the tunnel is measured against.
type weaknetProfile struct {
	name string
	cond *WeaknetCondition
}

// weaknetProfiles are the conditions CI measures. Each is chosen to break a
// different part of the send path, so a regression that only shows up under one
// mode still fails the job:
//
//   - lossy: the ARQ recovery and the exponential retransmit backoff.
//   - latency: a high-RTT path where the send window, not the loss, is the
//     ceiling.
//   - severe: both at once, plus enough jitter to reorder records. This is the
//     profile the reorder queues and the cumulative-ACK drain have to survive.
var weaknetProfiles = []weaknetProfile{
	{name: "lossy", cond: &WeaknetCondition{
		DropPct: 5, Delay: 2 * time.Millisecond, Jitter: time.Millisecond, Seed: DefaultWeaknetSeed,
	}},
	{name: "latency", cond: &WeaknetCondition{
		Delay: 25 * time.Millisecond, Jitter: 8 * time.Millisecond, Seed: DefaultWeaknetSeed,
	}},
	{name: "severe", cond: &WeaknetCondition{
		DropPct: 10, Delay: 15 * time.Millisecond, Jitter: 10 * time.Millisecond, Seed: DefaultWeaknetSeed,
	}},
}

// BenchmarkTunnelWeaknet measures established encrypted/ARQ sessions over the
// weak-network simulator in weaknet_test.go. Unlike BenchmarkTunnelBulkTransfer
// it runs un-gated, because CI only proves a benchmark runs when it runs the
// benchmark.
//
// The gate here is the assertion at the end of the cell, not the timing: 100%
// payload delivery, zero carrier drops and a fully drained ARQ and reorder
// state. Those are exactly what loss, latency and reordering threaten, and they
// hold or they do not regardless of how fast the runner is. The profiles are
// pinned by seed so a cell draws from the same distribution on every machine;
// which specific records are dropped still varies with scheduler interleaving,
// so the timings are a trend signal rather than a fixed expectation.
//
// `-benchtime 1x` gives one fixed workload per cell. The workload size is the
// variable here, not the iteration count.
func BenchmarkTunnelWeaknet(b *testing.B) {
	for _, p := range weaknetProfiles {
		b.Run(p.name, func(b *testing.B) {
			for _, record := range []int{512, 1460} {
				b.Run(fmt.Sprintf("record%d", record), func(b *testing.B) {
					benchmarkTunnelWeaknet(b, p, record)
				})
			}
		})
	}
}

func benchmarkTunnelWeaknet(b *testing.B, p weaknetProfile, record int) {
	// The carrier budget is the full record, not the payload: the simulator
	// drops and reorders COMPLETE records, which is what a real path does.
	cEp, sEp := newWeakLink("weak-client", "weak-server", RecordMinSize+record, p.cond)
	backends := make(chan net.Conn, 1)
	srv, err := NewServerWithTransport(ServerConfig{
		TargetAddr: "tcp://weak.invalid:1", Passwords: []string{"weaknet-bench-psk"}, Logger: Nop{},
	}, sEp, func(context.Context, uint32, string, string) (net.Conn, error) {
		target, backend := net.Pipe()
		backends <- backend
		return target, nil
	})
	if err != nil {
		b.Fatal(err)
	}
	defer srv.Close()
	go func() { _ = srv.Start() }()

	// A weak path delays every control record too, so the handshake needs a
	// wide timeout. The poll interval is what caps the downlink ceiling.
	cli, err := NewClientWithTransport(ClientConfig{
		ServerAddr: "192.0.2.2", Passwords: []string{"weaknet-bench-psk"}, Logger: Nop{},
		PollInterval: time.Millisecond, IdlePollInterval: time.Second, KeepAlive: 15 * time.Second,
	}, cEp)
	if err != nil {
		b.Fatal(err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	target := <-backends
	defer target.Close()
	deadline := time.Now().Add(60 * time.Second)
	_ = conn.SetDeadline(deadline)
	_ = target.SetDeadline(deadline)

	payload := make([]byte, weaknetBenchmarkBlock)
	blocks := weaknetBenchmarkBlocks
	b.SetBytes(int64(blocks) * int64(weaknetBenchmarkBlock))
	b.ReportAllocs()

	var delivered atomic.Uint64
	var workers sync.WaitGroup
	errors := make(chan error, 4)
	start := make(chan struct{})
	var abort sync.Once
	launch := func(fn func() error) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			if err := fn(); err != nil {
				errors <- err
				abort.Do(func() {
					_ = cEp.Close()
					_ = sEp.Close()
					_ = conn.Close()
					_ = target.Close()
				})
			}
		}()
	}
	launch(func() error {
		buf := make([]byte, weaknetBenchmarkBlock)
		for i := 0; i < blocks; i++ {
			if _, err := io.ReadFull(target, buf); err != nil {
				return fmt.Errorf("bulk read: %w", err)
			}
			delivered.Add(uint64(weaknetBenchmarkBlock))
		}
		return nil
	})
	launch(func() error {
		for i := 0; i < blocks; i++ {
			if err := writeAll(conn, payload); err != nil {
				return fmt.Errorf("bulk write: %w", err)
			}
		}
		return nil
	})

	b.ResetTimer()
	close(start)
	workers.Wait()
	b.StopTimer()
	close(errors)
	for err := range errors {
		b.Fatal(err)
	}
	offered := uint64(blocks) * uint64(weaknetBenchmarkBlock)
	if got := delivered.Load(); got != offered {
		b.Fatalf("delivered %d bytes, offered %d", got, offered)
	}
	b.ReportMetric(100*float64(delivered.Load())/float64(offered), "delivery-%")

	// Payload receipt precedes the last ACK. Require the retained send and
	// reorder queues and the carrier inboxes to drain before accepting a
	// sample. The bound is far wider than the clean-path benchmark's because a
	// tail-loss record pays the full retransmit backoff: 200ms, then 300ms,
	// then 450ms ... The point of the metric is the DURATION, so the bound
	// only has to be wide enough not to make a correct protocol look broken.
	drainStart := time.Now()
	var remaining int
	for {
		remaining = 0
		cli.sessions.Range(func(_, value any) bool {
			sess := value.(*clientSession)
			sess.unackedMu.Lock()
			remaining += len(sess.unacked)
			sess.unackedMu.Unlock()
			sess.recvMu.Lock()
			remaining += len(sess.recvQueue)
			sess.recvMu.Unlock()
			return true
		})
		srv.sessions.Range(func(_, value any) bool {
			sess := value.(*ServerSession)
			sess.unackedMu.Lock()
			remaining += len(sess.unacked)
			sess.unackedMu.Unlock()
			sess.recvMu.Lock()
			remaining += len(sess.recvQueue)
			sess.recvMu.Unlock()
			return true
		})
		remaining += cEp.Pending() + sEp.Pending()
		if remaining == 0 || time.Since(drainStart) >= 30*time.Second {
			break
		}
		time.Sleep(time.Millisecond)
	}
	b.ReportMetric(float64(time.Since(drainStart).Microseconds())/1000, "drain-ms")
	b.ReportMetric(float64(remaining), "undrained-records")

	// Carrier drops must stay zero: any loss in this sample comes from the
	// simulator, never from the fake transport. Non-zero carrier drops mean the
	// measurement is measuring backpressure, not the weak path.
	carrier := cEp.Counters().Dropped + sEp.Counters().Dropped + srv.Stats().QueueFullDrops
	b.ReportMetric(float64(carrier), "carrier-drops")

	// Simulated drops are how much loss the path actually took. Reported so a
	// profile that silently stops losing records is visible; the simulator
	// itself is covered by TestWeaknetDropsAreProbabilistic and friends.
	sim := cEp.WeaknetStats().WeaknetDrops + sEp.WeaknetStats().WeaknetDrops
	b.ReportMetric(float64(sim), "simulated-drops")

	// Amplification: carrier records pushed into the simulated path in BOTH
	// directions, per application block delivered. Includes the handshake,
	// every ACK, every poll and every ARQ retransmission, so it is the honest
	// wire cost of moving a block over a weak path. Counted at the simulator,
	// not from the carrier's writesSent: on a Poller carrier the session layer
	// sends through Poke, which the carrier counter does not see.
	wire := cEp.WeaknetStats().WeaknetOffered + sEp.WeaknetStats().WeaknetOffered
	b.ReportMetric(float64(wire)/float64(blocks), "writes/block")

	if remaining != 0 || carrier != 0 {
		b.Fatalf("sample did not drain cleanly: remaining=%d carrierDrops=%d", remaining, carrier)
	}
}
