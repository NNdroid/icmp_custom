package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const throughputBlock = 64 << 10

// BenchmarkTunnelBulkTransfer measures established encrypted/ARQ sessions over
// the memory carrier and net.Pipe targets. Setup and final ACK drain are reported
// separately. It is a session throughput measurement, not raw ICMP/WAN evidence.
// Run only on CI so local scheduling cannot be mistaken for the acceptance data.
func BenchmarkTunnelBulkTransfer(b *testing.B) {
	if os.Getenv("ICMP_CI_THROUGHPUT") != "1" {
		b.Skip("throughput measurements are enabled only in remote CI")
	}
	for _, direction := range []string{"upload", "download", "duplex"} {
		b.Run(direction, func(b *testing.B) {
			for _, mss := range []int{256, 1400} {
				b.Run(fmt.Sprintf("MSS%d", mss), func(b *testing.B) {
					for _, sessions := range []int{1, 4} {
						b.Run(fmt.Sprintf("sessions%d", sessions), func(b *testing.B) {
							benchmarkTunnelBulk(b, direction, mss, sessions)
						})
					}
				})
			}
		})
	}
}

func benchmarkTunnelBulk(b *testing.B, direction string, mss, sessions int) {
	cEp, sEp := newFakeLink("bulk-client", "bulk-server", RecordMinSize+mss)
	// A blocking memory carrier needs room for both DATA and its ACKs. At four
	// sessions the generic test rig's 1024 slots equal the DATA window alone;
	// both receive loops can then block sending ACKs into the opposite inbox.
	// Keep production send windows unchanged and give both revisions the same
	// bounded carrier headroom before any goroutine starts.
	carrierCapacity := 2*sessions*defaultSendWindow + 128
	cEp.inbox = make(chan fakePacket, carrierCapacity)
	sEp.inbox = make(chan fakePacket, carrierCapacity)
	backends := make(chan net.Conn, sessions)
	srv, err := NewServerWithTransport(ServerConfig{
		TargetAddr: "tcp://bulk.invalid:1", Passwords: []string{"ci-throughput-psk"}, Logger: Nop{},
	}, sEp, func(context.Context, uint32, string, string) (net.Conn, error) {
		target, backend := net.Pipe()
		backends <- backend
		return target, nil
	})
	if err != nil {
		b.Fatal(err)
	}
	go func() { _ = srv.Start() }()
	cli, err := NewClientWithTransport(ClientConfig{
		ServerAddr: "192.0.2.2", Passwords: []string{"ci-throughput-psk"}, Logger: Nop{},
		PollInterval: time.Millisecond, IdlePollInterval: time.Second, KeepAlive: 15 * time.Second,
	}, cEp)
	if err != nil {
		srv.Close()
		b.Fatal(err)
	}
	defer srv.Close()
	defer cli.Close()
	apps := make([]net.Conn, 0, sessions)
	targets := make([]net.Conn, 0, sessions)
	defer func() {
		// Unblock a full fake-carrier queue before closing sessions, whose FIN
		// would otherwise wait behind records when a failed sample tears down.
		_ = cEp.Close()
		_ = sEp.Close()
		for _, conn := range apps {
			_ = conn.Close()
		}
		for _, conn := range targets {
			_ = conn.Close()
		}
	}()
	for i := 0; i < sessions; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := cli.DialTunnel(ctx, DialOptions{})
		cancel()
		if err != nil {
			b.Fatal(err)
		}
		apps = append(apps, conn)
		targets = append(targets, <-backends)
		deadline := time.Now().Add(30 * time.Second)
		_ = conn.SetDeadline(deadline)
		_ = targets[i].SetDeadline(deadline)
	}

	upload := bytes.Repeat([]byte{0xA5}, throughputBlock)
	download := bytes.Repeat([]byte{0x5A}, throughputBlock)
	bytesPerOp := throughputBlock
	if direction == "duplex" {
		bytesPerOp *= 2
	}
	b.SetBytes(int64(bytesPerOp))
	b.ReportAllocs()
	var delivered atomic.Uint64
	var workers sync.WaitGroup
	errors := make(chan error, sessions*4)
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
					_ = pprof.Lookup("goroutine").WriteTo(os.Stderr, 2)
					_ = cEp.Close()
					_ = sEp.Close()
					for _, conn := range apps {
						_ = conn.Close()
					}
					for _, conn := range targets {
						_ = conn.Close()
					}
				})
			}
		}()
	}
	write := func(conn net.Conn, payload []byte, count int) func() error {
		return func() error {
			for i := 0; i < count; i++ {
				if err := writeAll(conn, payload); err != nil {
					return fmt.Errorf("bulk write: %w", err)
				}
			}
			return nil
		}
	}
	read := func(conn net.Conn, payload []byte, count int) func() error {
		return func() error {
			buf := make([]byte, throughputBlock)
			for i := 0; i < count; i++ {
				if _, err := io.ReadFull(conn, buf); err != nil {
					return fmt.Errorf("bulk read: %w", err)
				}
				if !bytes.Equal(buf, payload) {
					return fmt.Errorf("bulk payload differs at block %d", i)
				}
				delivered.Add(throughputBlock)
			}
			return nil
		}
	}
	for i := 0; i < sessions; i++ {
		count := b.N / sessions
		if i < b.N%sessions {
			count++
		}
		if direction != "download" {
			launch(read(targets[i], upload, count))
			launch(write(apps[i], upload, count))
		}
		if direction != "upload" {
			launch(read(apps[i], download, count))
			launch(write(targets[i], download, count))
		}
	}
	b.ResetTimer()
	close(start)
	workers.Wait()
	b.StopTimer()
	close(errors)
	for err := range errors {
		b.Fatal(err)
	}
	offered := uint64(b.N) * uint64(bytesPerOp)
	if delivered.Load() != offered {
		b.Fatalf("delivered %d bytes, offered %d", delivered.Load(), offered)
	}
	b.ReportMetric(float64(delivered.Load())/float64(b.N), "delivered-B/op")
	b.ReportMetric(100*float64(delivered.Load())/float64(offered), "delivery-%")

	// Payload receipt precedes the last ACK. Require the retained send and
	// reorder queues and the carrier inboxes to drain before accepting a sample.
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
		if remaining == 0 || time.Since(drainStart) >= 5*time.Second {
			break
		}
		time.Sleep(time.Millisecond)
	}
	b.ReportMetric(float64(time.Since(drainStart).Microseconds())/1000, "drain-ms")
	b.ReportMetric(float64(remaining), "undrained-records")
	drops := cEp.Counters().Dropped + sEp.Counters().Dropped + srv.Stats().QueueFullDrops
	b.ReportMetric(float64(drops), "carrier-drops")
	if remaining != 0 || drops != 0 {
		b.Fatalf("sample did not drain cleanly: remaining=%d drops=%d", remaining, drops)
	}
}
