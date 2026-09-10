package tunnel

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// The built-in `discard://` target.
//
// `discard://` is not a network service and not an outbound dial: it is an
// in-process sink the server can forward a session to. It exists so the ICMP
// profile's active MTU probe (DESIGN_ICMP.md §4.8, option A′) can measure a
// real path with real records while keeping the "every ICMP payload is a
// complete, well-formed v2 record" invariant completely intact — no padding,
// no synthetic probe packets, no new wire format.
//
// It understands exactly two things:
//
//  1. Any framed message that is not a length request is discarded. That is
//     the UPLINK probe: the client sends a record of size N and learns from the
//     ACK whether N survived the path.
//  2. A framed message whose payload is exactly 4 bytes big-endian N is a
//     length request: the sink queues N bytes of filler, which the session
//     ships back down as ordinary DATA. That is the DOWNLINK probe.
//
// The wire format is therefore literally `framing.go`'s existing length
// prefix — the sink adds nothing to the protocol.
//
// It never dials, never stores anything the peer sent, and never reflects
// peer-supplied bytes (the filler is generated locally). The fill size is
// capped so a misbehaving client cannot make the server allocate on demand.
const (
	// discardMaxFill caps one length request. A real path MTU is two orders of
	// magnitude below this; the cap only exists so a bogus request cannot ask
	// for gigabytes.
	discardMaxFill = 1 << 16

	// discardMaxQueued bounds the undelivered filler. The reader is the
	// session's upstream pump, so a full queue means the downlink is stalled;
	// dropping the request is strictly better than growing without bound.
	discardMaxQueued = 1 << 20
)

// discardSink is a net.Conn-backed in-process backend. It is safe for one
// concurrent reader (the session's upstream pump) and one concurrent writer
// (the session's record handler).
//
// A closed sink reads io.EOF rather than a private sentinel, because the
// session's upstream pump treats any read error as "target is done" — which is
// exactly right when the sink is torn down.
type discardSink struct {
	mu     sync.Mutex
	asm    *MessageAssembler
	out    []byte
	wake   chan struct{}
	closed bool
	once   sync.Once

	readDeadline time.Time

	// Observability: a length request answered, and a message dropped.
	fills   uint64
	dropped uint64
}

func newDiscardSink() *discardSink {
	return &discardSink{
		asm:  NewMessageAssembler(discardMaxFill),
		wake: make(chan struct{}, 1),
	}
}

// Compile-time proof the sink is a usable target connection.
var _ net.Conn = (*discardSink)(nil)

// Read implements net.Conn. It blocks until the sink has filler to hand back,
// the read deadline expires, or the sink is closed.
func (s *discardSink) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		s.mu.Lock()
		if len(s.out) > 0 {
			n := copy(p, s.out)
			s.out = s.out[n:]
			s.mu.Unlock()
			return n, nil
		}
		if s.closed {
			s.mu.Unlock()
			return 0, io.EOF
		}
		deadline := s.readDeadline
		s.mu.Unlock()

		var timeout <-chan time.Time
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer := time.NewTimer(remaining)
			timeout = timer.C
			defer timer.Stop()
		}

		select {
		case <-s.wake:
			// Re-check: the queue may have been drained by another reader, or
			// the wake may be a stale token.
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

// Write implements net.Conn. Every complete framed message is consumed; a
// 4-byte payload is a length request and everything else is discarded.
func (s *discardSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	msgs, err := s.asm.Feed(p)
	if err != nil {
		// A desynced probe stream is not worth recovering: the probe is
		// best-effort and the client will restart it. Reset and carry on so a
		// single corrupt probe cannot wedge the sink forever.
		s.asm.Reset()
	}
	wake := false
	for _, msg := range msgs {
		if len(msg) != 4 {
			s.dropped++
			continue
		}
		want := int(binary.BigEndian.Uint32(msg))
		switch {
		case want <= 0:
			s.dropped++
			continue
		case want > discardMaxFill:
			want = discardMaxFill
		case len(s.out)+want > discardMaxQueued:
			s.dropped++
			continue
		}
		s.out = append(s.out, make([]byte, want)...)
		s.fills++
		wake = true
	}
	s.mu.Unlock()

	if wake {
		s.signal()
	}
	// A sink never applies backpressure to the session: it always consumes.
	return len(p), nil
}

func (s *discardSink) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Close implements net.Conn and unblocks a pending Read.
func (s *discardSink) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		s.signal()
	})
	return nil
}

// SetDeadline implements net.Conn. Write deadlines are accepted and ignored:
// the sink never blocks a write, so there is nothing to time out.
func (s *discardSink) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.mu.Unlock()
	return nil
}

// SetReadDeadline implements net.Conn.
func (s *discardSink) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.mu.Unlock()
	s.signal()
	return nil
}

// SetWriteDeadline implements net.Conn.
func (s *discardSink) SetWriteDeadline(time.Time) error { return nil }

// LocalAddr implements net.Conn.
func (s *discardSink) LocalAddr() net.Addr { return discardAddr{} }

// RemoteAddr implements net.Conn.
func (s *discardSink) RemoteAddr() net.Addr { return discardAddr{} }

// discardStats reports what the sink has done, for tests and diagnostics.
type discardStats struct {
	Fills   uint64
	Dropped uint64
	Queued  int
}

func (s *discardSink) stats() discardStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return discardStats{Fills: s.fills, Dropped: s.dropped, Queued: len(s.out)}
}

// discardAddr labels the sink in logs. It is not a routable address and is
// never resolved.
type discardAddr struct{}

func (discardAddr) Network() string { return "discard" }
func (discardAddr) String() string  { return "discard" }

// isDiscardNetwork reports whether a parsed target network names the built-in
// sink. The server consults it before the injected TargetDialer so the sink
// works identically with a real dialer, a test stub, or none at all.
func isDiscardNetwork(network string) bool { return network == "discard" }
