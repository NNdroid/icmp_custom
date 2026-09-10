package tunnel

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

// Benchmarks.
//
// They are split into two layers on purpose:
//
//   - MICRO benchmarks pin the per-packet costs the tunnel cannot avoid:
//     framing, AEAD, the replay window, the RTO estimator, pacing, the MTU
//     controller and the carrier classifier. These are the numbers to watch
//     when a change claims to be "just bookkeeping".
//
//   - INTEGRATION benchmarks drive the real session layer over the in-memory
//     fake transport, so they include the handshake, ARQ, the reorder buffers
//     and the poll loop. A micro benchmark cannot catch an accidental O(n^2) in
//     the receive path; this one can.
//
// All of them report allocations: the receive path is supposed to be
// allocation-light, and an alloc that creeps in is invisible in wall-clock
// time until the GC starts thrashing under load.

// ---------------------------------------------------------------------------
// Framing and record layer
// ---------------------------------------------------------------------------

func BenchmarkEncodeMessage(b *testing.B) {
	for _, size := range []int{64, 1200, 16 << 10} {
		msg := make([]byte, size)
		b.Run(sizeName(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := EncodeMessage(msg); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkMessageAssemblerFeed measures the steady-state receive path: one
// complete frame arriving per Feed call. This is the code that runs for every
// byte a stream target sends, so an accidental re-copy anywhere in it matters.
func BenchmarkMessageAssemblerFeed(b *testing.B) {
	for _, size := range []int{64, 1200, 16 << 10} {
		frame, err := EncodeMessage(make([]byte, size))
		if err != nil {
			b.Fatal(err)
		}
		b.Run(sizeName(size), func(b *testing.B) {
			asm := NewMessageAssembler(MaxFramedMessage)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				msgs, err := asm.Feed(frame)
				if err != nil {
					b.Fatal(err)
				}
				if len(msgs) != 1 {
					b.Fatalf("Feed returned %d messages, want 1", len(msgs))
				}
			}
		})
	}
}

func BenchmarkRecordMarshal(b *testing.B) {
	for _, size := range []int{0, 256, 1200} {
		rec := &Record{
			Magic: MagicDefault, Version: Version, Cmd: CmdData,
			SessionID: 0xDEADBEEF, PacketNo: 1, Seq: 2, Data: make([]byte, size),
		}
		b.Run(sizeName(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := rec.Marshal(0); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkRecordParse(b *testing.B) {
	for _, size := range []int{0, 256, 1200} {
		rec := &Record{
			Magic: MagicDefault, Version: Version, Cmd: CmdData,
			SessionID: 0xDEADBEEF, PacketNo: 1, Seq: 2, Data: make([]byte, size),
		}
		wire, err := rec.Marshal(0)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(sizeName(size), func(b *testing.B) {
			var out Record
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := Parse(wire, MagicDefault, 0, &out); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AEAD: the per-record confidentiality cost
// ---------------------------------------------------------------------------

func benchFrameKeys(b *testing.B) (*FrameKeys, *FrameKeys) {
	b.Helper()
	var clientNonce [ClientNonceSize]byte
	var serverNonce [ServerNonceSize]byte
	keys := DerivePSKSessionKeys("bench-psk", clientNonce, serverNonce, 0x12345678)
	client, err := keys.ClientFrameCiphers()
	if err != nil {
		b.Fatal(err)
	}
	server, err := keys.ServerFrameCiphers()
	if err != nil {
		b.Fatal(err)
	}
	return client, server
}

func BenchmarkSealRecordAEAD(b *testing.B) {
	for _, size := range []int{0, 256, 1200} {
		client, _ := benchFrameKeys(b)
		plain := make([]byte, size)
		b.Run(sizeName(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rec := &Record{
					Magic: MagicDefault, Version: Version, Cmd: CmdData,
					SessionID: 1, PacketNo: uint64(i + 1), Seq: 1,
				}
				if wire := SealRecordAEAD(rec, client.Send, plain, 0); wire == nil {
					b.Fatal("SealRecordAEAD returned nil")
				}
			}
		})
	}
}

// BenchmarkOpenRecordAEAD measures the full receive-side protection step:
// parse + authenticate + decrypt, exactly as a session does it.
func BenchmarkOpenRecordAEAD(b *testing.B) {
	for _, size := range []int{0, 256, 1200} {
		client, server := benchFrameKeys(b)
		plain := make([]byte, size)
		// Pre-seal a batch of distinct packet numbers so each iteration opens
		// a record it has not seen; reusing one wire form would measure the
		// replay window, not the AEAD.
		const batch = 1024
		wires := make([][]byte, batch)
		for i := 0; i < batch; i++ {
			rec := &Record{
				Magic: MagicDefault, Version: Version, Cmd: CmdData,
				SessionID: 1, PacketNo: uint64(i + 1), Seq: 1,
			}
			wires[i] = SealRecordAEAD(rec, client.Send, plain, 0)
		}
		b.Run(sizeName(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var rec Record
				if err := Parse(wires[i%batch], MagicDefault, 0, &rec); err != nil {
					b.Fatal(err)
				}
				if _, err := OpenRecordAEAD(&rec, server.Recv); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Replay window, RTO estimator
// ---------------------------------------------------------------------------

func BenchmarkReplayFilterCheckAndAdd(b *testing.B) {
	// CheckAndAdd returns TRUE for a replay or a too-old packet and FALSE for
	// a newly accepted one, so "accepted" is the false branch.
	b.Run("in-order", func(b *testing.B) {
		var rf ReplayFilter
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if rf.CheckAndAdd(uint64(i + 1)) {
				b.Fatal("an in-order sequence was rejected as a replay")
			}
		}
	})
	// A strictly increasing sequence only ever shifts the window by one. The
	// strided variant forces the multi-word shift, which is the expensive
	// branch of acceptLocked.
	b.Run("window-sliding", func(b *testing.B) {
		var rf ReplayFilter
		const stride = 64
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if rf.CheckAndAdd(uint64(i*stride + 1)) {
				b.Fatal("a sliding sequence was rejected as a replay")
			}
		}
	})
	b.Run("replay-rejected", func(b *testing.B) {
		var rf ReplayFilter
		rf.Accept(1000)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if !rf.CheckAndAdd(1000) {
				b.Fatal("a replay was accepted")
			}
		}
	})
}

func BenchmarkRTTEstimatorSample(b *testing.B) {
	e := newRTTEstimator(200*time.Millisecond, 10*time.Millisecond, 3*time.Second)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e.Sample(time.Duration(20+i%40) * time.Millisecond)
		_ = e.RTO()
	}
}

// ---------------------------------------------------------------------------
// Pacing, MTU controller, carrier classifier
// ---------------------------------------------------------------------------

// BenchmarkPacerAdmission measures the admission bookkeeping: the mutex, the
// slot arithmetic and the debt cap. It is NOT a wall-clock pacing benchmark,
// and deliberately so — arming a real timer would fold the host's timer
// resolution (milliseconds on Windows) into the number and hide the code's own
// cost. An already-cancelled context makes every call take the "would have to
// wait" branch without ever arming a timer, which is exactly the arithmetic on
// the hot path.
func BenchmarkPacerAdmission(b *testing.B) {
	p := newPacer(time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the wait must observe this and return without sleeping
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// The first call departs immediately (the pacer starts idle); every
		// later call finds itself behind the schedule and returns ctx.Err().
		_ = p.wait(ctx)
	}
	if p.currentInterval() != time.Millisecond {
		b.Fatal("the pacer lost its configured interval")
	}
}

func BenchmarkMTUController(b *testing.B) {
	b.Run("record-acked", func(b *testing.B) {
		m := newMTUController(mtuProbe, 1400, icmpMinPayload, 100)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			m.recordAcked(1200)
		}
	})
	b.Run("shrink-for-oversize", func(b *testing.B) {
		m := newMTUController(mtuProbe, 1400, icmpMinPayload, 100)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			m.shrinkForOversize(1400)
		}
	})
	b.Run("budget-read", func(b *testing.B) {
		m := newMTUController(mtuProbe, 1400, icmpMinPayload, 100)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = m.budget()
		}
	})
}

// BenchmarkCarrierMonitor measures the per-poll and per-reply bookkeeping that
// sits on the hot receive/send paths.
func BenchmarkCarrierMonitor(b *testing.B) {
	peer := netip.MustParseAddrPort("192.0.2.2:0")

	b.Run("note-poll", func(b *testing.B) {
		m := newCarrierMonitor(peer, 20*time.Millisecond, time.Minute, Nop{})
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			m.notePoll()
		}
	})
	b.Run("note-poll-reply", func(b *testing.B) {
		m := newCarrierMonitor(peer, 20*time.Millisecond, time.Minute, Nop{})
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			m.notePoll()
			m.noteReply(20 * time.Millisecond)
		}
	})
	b.Run("rto-floor", func(b *testing.B) {
		m := newCarrierMonitor(peer, 20*time.Millisecond, time.Minute, Nop{})
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = m.RTOFloor()
		}
	})
}

func BenchmarkPokeBook(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var book pokeBook
		book.open = make(map[uint16]time.Time, 8)
		book.add(uint16(i))
		if _, ok := book.claim(uint16(i)); !ok {
			b.Fatal("claim missed a just-added sequence")
		}
	}
}

// ---------------------------------------------------------------------------
// Integration: the real receive/send path over the fake carrier
// ---------------------------------------------------------------------------

// BenchmarkFakeLinkRecordRoundTrip measures one write+read through the fake
// transport with no session layer involved. It is the baseline the integration
// benchmark below is compared against: the difference between the two is what
// ARQ, AEAD and the reorder buffer actually cost.
//
// The link is built inside b.Run because a benchmark body is invoked more than
// once (calibration, then the measured run): a link built outside would be
// closed by the first invocation and the second would fail with ErrClosed.
func BenchmarkFakeLinkRecordRoundTrip(b *testing.B) {
	for _, size := range []int{256, 1200} {
		b.Run(sizeName(size), func(b *testing.B) {
			a, c := newFakeLink("a", "b", 2048)
			defer a.Close()
			defer c.Close()
			payload := make([]byte, size)
			buf := make([]byte, 4096)

			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := a.WriteRecord(payload, c.NetAddr()); err != nil {
					b.Fatal(err)
				}
				n, _, err := c.ReadRecord(buf)
				if err != nil {
					b.Fatal(err)
				}
				if n != size {
					b.Fatalf("read %d bytes, want %d", n, size)
				}
			}
		})
	}
}

// BenchmarkTunnelEchoRoundTrip is the end-to-end number: a fresh handshake,
// a payload out through a real TCP echo backend and back, then teardown, all
// over the in-memory carrier. It is the closest thing to "how fast can this
// tunnel move data" that can run without root and without a network.
//
// The poll interval is tightened well below the production default (20ms): at
// the default the downlink would be paced at ~50 records/s and the benchmark
// would measure the poll schedule rather than the code.
func BenchmarkTunnelEchoRoundTrip(b *testing.B) {
	backend, stop := tcpEchoServer(b)
	defer stop()

	cEp, _, _ := newTestServer(b, ServerConfig{
		TargetAddr: "tcp://" + backend,
		Passwords:  []string{"bench-psk"},
		Logger:     Nop{},
	}, nil)
	cli := newTestClient(b, ClientConfig{
		ServerAddr:        "192.0.2.2",
		Passwords:         []string{"bench-psk"},
		Logger:            Nop{},
		HandshakeBackoff:  time.Millisecond,
		HandshakeAttempts: 8,
		PollsInFlight:     8,
		PollInterval:      200 * time.Microsecond,
		IdlePollInterval:  200 * time.Microsecond,
		KeepAlive:         time.Second,
	}, cEp)

	payload := make([]byte, 4<<10)
	for i := range payload {
		payload[i] = byte(i)
	}
	got := make([]byte, len(payload))
	ctx := context.Background()

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		conn, err := cli.DialTunnel(dialCtx, DialOptions{})
		if err != nil {
			cancel()
			b.Fatalf("DialTunnel: %v", err)
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(payload); err != nil {
			cancel()
			b.Fatalf("write: %v", err)
		}
		if _, err := io.ReadFull(conn, got); err != nil {
			cancel()
			b.Fatalf("read: %v", err)
		}
		if !bytes.Equal(got, payload) {
			cancel()
			b.Fatal("round-tripped payload differs")
		}
		_ = conn.Close()
		cancel()
	}
}

// BenchmarkHandshakeOnly isolates tunnel establishment (SYN/ACK + target
// dial), so a regression in the handshake is not hidden by the data path.
func BenchmarkHandshakeOnly(b *testing.B) {
	backend, stop := tcpEchoServer(b)
	defer stop()

	cEp, _, _ := newTestServer(b, ServerConfig{
		TargetAddr: "tcp://" + backend,
		Passwords:  []string{"bench-psk"},
		Logger:     Nop{},
	}, nil)
	cli := newTestClient(b, ClientConfig{
		ServerAddr:        "192.0.2.2",
		Passwords:         []string{"bench-psk"},
		Logger:            Nop{},
		HandshakeBackoff:  time.Millisecond,
		HandshakeAttempts: 8,
		PollInterval:      200 * time.Microsecond,
		IdlePollInterval:  200 * time.Microsecond,
		KeepAlive:         time.Second,
	}, cEp)

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		conn, err := cli.DialTunnel(dialCtx, DialOptions{})
		if err != nil {
			cancel()
			b.Fatalf("DialTunnel: %v", err)
		}
		_ = conn.Close()
		cancel()
	}
}

// sizeName keeps benchmark sub-names stable and readable.
func sizeName(n int) string {
	switch {
	case n == 0:
		return "empty"
	case n < 1024:
		return strconv.Itoa(n) + "B"
	default:
		return strconv.Itoa(n/1024) + "KiB"
	}
}
