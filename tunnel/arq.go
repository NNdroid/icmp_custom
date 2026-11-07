package tunnel

import (
	"sync"
	"time"
)

// Shared ARQ machinery.
//
// The server session and the client session keep byte-identical outstanding-
// record state (unackedPkt) and run byte-identical retransmission policy; only
// their endpoints differ (carrier floor, MTU feedback, send outlet, retry
// ceiling, and what abandoning a record means). The deadline arithmetic and
// the sweep are therefore written ONCE here and driven by both sides, so the
// two mirrors cannot drift apart again — the drift that previously produced a
// different RTO cap and a missing empty-map guard on one side only.
//
// The retransmit loops themselves are also shared in shape: each session owns
// one goroutine that sleeps until the EARLIEST outstanding deadline (or a
// state change) instead of ticking on a fixed interval. A quiet session with
// nothing outstanding costs zero wake-ups; a busy one wakes at the rate of
// actual retransmission events, not 20 times per second.

// nudge wakes a loop that selects on ch. Non-blocking by design: one pending
// token is enough, because the loop re-reads the state it guards every time
// it wakes — a second nudge while one is queued carries no information.
func nudge(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// evidenceLen is the wire size this record reports as MTU evidence: the
// coalesced datagram that carried it when one did, else its own length. Under
// coalescing a small record riding a full-budget datagram IS full-budget
// evidence; the record's own size would blind the MTU search.
func (pkt *unackedPkt) evidenceLen() int {
	if pkt.mtuLen > 0 {
		return pkt.mtuLen
	}
	return len(pkt.wire)
}

// payloadPool recycles the receive-side payload buffers: a record's bytes are
// copied out of the carrier's read buffer at enqueue time, held in recvQueue,
// written to the target, and only then dead. Get returns an empty buffer to
// append into; the delivery loop Puts each payload back after its write.
var payloadPool = sync.Pool{
	New: func() any { return make([]byte, 0, 1536) },
}

// payloadGet returns an empty buffer ready to append a received payload into.
func payloadGet() []byte {
	return payloadPool.Get().([]byte)[:0]
}

// payloadPut returns a delivered payload buffer. Oversized buffers are
// dropped rather than pinned in the pool.
func payloadPut(p []byte) {
	if cap(p) <= 64<<10 {
		payloadPool.Put(p[:0])
	}
}

// earliestRetransmitDelay reports how long until the earliest outstanding
// record is due for retransmission, or false when nothing is outstanding.
//
// The carrier's RTO floor is applied per record exactly as the sweep applies
// it, so arming a timer to this delay lands the wake when work is actually
// due. A later floor change (a carrier reclassifying the path) simply causes
// one early wake whose sweep finds nothing due and re-arms — the same
// "re-read the floor each wake" behaviour the fixed ticker had, minus the
// twenty wake-ups per second that paid for it.
func earliestRetransmitDelay(unacked map[uint64]*unackedPkt, floor time.Duration) (time.Duration, bool) {
	var best time.Duration
	found := false
	now := time.Now()
	for _, pkt := range unacked {
		wait := pkt.rto
		if wait < floor {
			wait = floor
		}
		due := pkt.sentTime.Add(wait)
		if d := due.Sub(now); !found || d < best {
			best, found = d, true
		}
	}
	if !found {
		return 0, false
	}
	if best < 0 {
		best = 0
	}
	return best, true
}

// retransmitSweep carries what one sweep of the outstanding records needs
// from its owning session.
//
// The sweep collects the records due for retransmission under the unacked
// mutex and sends them OUTSIDE it: a send can block on the carrier, and
// holding the mutex across it would stall every sender parked on the send
// window (and, on the client, the single shared receive loop).
type retransmitSweep struct {
	// mu guards unacked and every pkt field it holds.
	mu *sync.Mutex
	// floor is the carrier's retransmit floor right now. A throttled path
	// cannot answer faster than its own pace, and a blocked one must not be
	// probed faster than its block timeout, so a record's effective wait is
	// max(rto, floor).
	floor time.Duration
	// fed receives one RecordLost per timed-out record, as MTU evidence.
	fed MTUFeedback
	// unacked is the outstanding map; run deletes records it abandons.
	unacked map[uint64]*unackedPkt
	// rttMax caps the exponential RTO growth.
	rttMax time.Duration
	// maxRetries is the retry ceiling; a record past it tears the session.
	maxRetries int
	// onAbandon fires once, when a record exhausted its retries. The owner
	// logs with its own identity and tears the session down; run reports
	// false afterwards and the owner stops sweeping.
	onAbandon func(seq uint64)
	// onRetransmit sends one due record. Called outside mu.
	onRetransmit func(pkt *unackedPkt)
}

// run performs one sweep. It reports false when a record exhausted its
// retries and onAbandon has fired: the owning loop must exit (its session is
// being torn down), not merely re-arm.
func (p *retransmitSweep) run() bool {
	now := time.Now()
	var toSend []*unackedPkt
	abandoned := uint64(0)
	abandon := false
	p.mu.Lock()
	for seq, pkt := range p.unacked {
		wait := pkt.rto
		if wait < p.floor {
			wait = p.floor
		}
		if now.Sub(pkt.sentTime) < wait {
			continue
		}
		// Feed the timeout as MTU evidence now, not only on abandon. The
		// record has already been told it was too big by the time the
		// retries run out, and the carrier's classifier suppresses this
		// while the path is throttled.
		if p.fed != nil {
			p.fed.RecordLost(pkt.evidenceLen())
		}
		pkt.retries++
		if pkt.retries > p.maxRetries {
			abandoned = seq
			abandon = true
			delete(p.unacked, seq)
			break
		}
		pkt.sentTime = now
		pkt.rto = minDuration(pkt.rto*3/2, p.rttMax)
		toSend = append(toSend, pkt)
	}
	p.mu.Unlock()
	if abandon {
		p.onAbandon(abandoned)
		return false
	}
	for _, pkt := range toSend {
		p.onRetransmit(pkt)
	}
	return true
}
