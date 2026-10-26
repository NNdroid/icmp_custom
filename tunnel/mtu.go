package tunnel

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Automatic path-MTU discovery for the ICMP profile.
//
// Classic PMTUD is not usable here. It depends on ICMP `fragmentation needed` /
// `Packet Too Big` messages surviving the reverse path, and they routinely do
// not (RFC 2923's PMTUD black hole), which shows up as a tunnel that hangs for
// no visible reason. Probing for the answer also means sending oversized
// packets, exactly the traffic CGNATs drop first and that eats the host's
// global ICMP allowance.
//
// So the profile uses PLPMTUD-style in-band discovery (RFC 8899's approach):
// the probe IS a real data record, and the verdict IS its acknowledgement. No
// new wire format, and nothing that looks unlike ordinary traffic.
//
// In-band adaptation runs for the life of a session. It grows the budget after
// a run of acknowledged full-budget records, and shrinks it after repeated
// losses — but a frag-needed message, when one does arrive, is applied
// immediately because it is the only precise signal in the whole system.
//
// There was also an active probe (method A′): a one-shot binary search over a
// dedicated session to the built-in `discard://` sink. It never got wired to a
// caller, so it is gone; the search was pure but driving it needs a send path
// that bypasses the session's own record chunking, which does not exist. In-band
// adaptation alone is not slower in practice — it converges on the first
// sustained upload, which is exactly when a bigger budget is wanted.
//
// Per-direction is fundamental: a path MTU is asymmetric in practice, and the
// budget belongs to the SENDER. Each end therefore searches its own outbound
// direction, and the discovered value is a property of that end's socket.

// mtuMode selects how the send budget is allowed to move.
type mtuMode int

const (
	// mtuFixed trusts the configured budget and never adapts. It is the escape
	// hatch for a path whose behaviour the operator already knows.
	mtuFixed mtuMode = iota
	// mtuInBand runs in-band adaptation only. It is the default, and the only
	// mode that adapts.
	mtuInBand
)

func (m mtuMode) String() string {
	switch m {
	case mtuFixed:
		return "fixed"
	case mtuInBand:
		return "auto"
	}
	return "unknown"
}

func parseMTUMode(s string) (mtuMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto", "in-band", "inband":
		return mtuInBand, nil
	// "probe" is a deprecated alias. The active probe it named was never wired
	// to a caller, so it always behaved exactly like "auto"; accepting it keeps
	// configs written for older releases valid instead of failing at startup.
	case "probe":
		return mtuInBand, nil
	case "fixed", "off", "none":
		return mtuFixed, nil
	}
	return mtuInBand, fmt.Errorf("%w: icmp.mtu_mode = %q (want auto or fixed)", ErrConfigRequired, s)
}

const (
	// mtuAcksToGrow is how many consecutive full-budget records must be
	// acknowledged before the budget grows one step. Acknowledgements, not
	// sends: a record that was retransmitted proves the path is marginal, not
	// that it is roomy.
	mtuAcksToGrow = 8
	// mtuLossesToShrink is how many consecutive FULL-BUDGET failures are
	// tolerated before stepping down. A single loss is noise, and a small
	// record failing says the path is lossy rather than narrow, so it does not
	// count at all (see recordLost).
	mtuLossesToShrink = 3
	// mtuFrozenRetry is how long a shrunken budget is trusted before the search
	// is allowed to try growing again. It exists to stop a marginal path
	// oscillating between shrink and grow, and it must therefore be longer than
	// the time it takes to accumulate mtuAcksToGrow. Sixty seconds is well
	// beyond that on any busy path, while a false shrink recovers in a minute
	// instead of ten minutes.
	mtuFrozenRetry = 60 * time.Second
)

// mtuController owns the live send budget: the complete-record size the session
// may emit right now. It is both the source of MaxRecordSize and the sink of
// MTUFeedback, which is how the session's acknowledgements become MTU evidence
// without the session knowing anything about MTUs.
type mtuController struct {
	mu      sync.Mutex
	mode    mtuMode
	ceiling int // configured maximum; never exceeded
	floor   int // configured minimum; never stepped below
	step    int
	cur     int

	acks   int
	losses int

	frozen   bool
	frozenAt time.Time

	suspended bool
}

func newMTUController(mode mtuMode, ceiling, floor, step int) *mtuController {
	if floor < 1 {
		floor = icmpDefaultMTUMin
	}
	if ceiling < floor {
		ceiling = floor
	}
	if step < 1 {
		step = 1
	}

	start := ceiling
	if mode != mtuFixed {
		// Start at min(max_payload, icmpSafeStartPayload): that value never
		// fragments on either family, so the worst case is no worse than not
		// adapting at all. Anything above it is reached only with evidence.
		if start > icmpSafeStartPayload {
			start = icmpSafeStartPayload
		}
		if start < floor {
			start = floor
		}
	}
	return &mtuController{mode: mode, ceiling: ceiling, floor: floor, step: step, cur: start}
}

// budget is the live complete-record budget.
func (m *mtuController) budget() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur
}

// receiveCeiling is the largest complete record this end must accept from the
// peer: the configured ceiling, never the adaptive send budget.
//
// The two numbers are different on purpose. The send budget is THIS end's
// measured path MTU; the receive ceiling is how large the PEER's records may
// legitimately be, which is bounded by the peer's own configuration and can
// never be learned from here. Sizing a receive buffer from a shrunken send
// budget would reject a peer's perfectly valid record the moment the outbound
// path narrowed — a tunnel that works one way and dies with "record too large"
// the other. Only the fixed ceiling is safe.
func (m *mtuController) receiveCeiling() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ceiling
}

// modeOf reports the configured mode.
func (m *mtuController) modeOf() mtuMode {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mode
}

// setSuspended freezes adaptation while the carrier is unhealthy. Signals are
// untrustworthy then: loss caused by a rate limit says nothing about the path
// MTU, and burning probe packets into a throttled path makes the limit worse.
func (m *mtuController) setSuspended(v bool) {
	m.mu.Lock()
	m.suspended = v
	m.mu.Unlock()
}

// recordAcked feeds one acknowledged record's wire size.
func (m *mtuController) recordAcked(size int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mode == mtuFixed || m.suspended {
		return
	}
	if size < m.cur {
		// Only a full-budget record is evidence about the ceiling.
		m.acks = 0
		return
	}
	m.acks++
	m.losses = 0
	if m.acks < mtuAcksToGrow {
		return
	}
	m.acks = 0

	if m.cur >= m.ceiling {
		m.freezeLocked()
		return
	}
	if m.frozen {
		if time.Since(m.frozenAt) < mtuFrozenRetry {
			return
		}
		m.frozen = false
	}
	m.cur = m.growLocked()
	if m.cur >= m.ceiling {
		m.freezeLocked()
	}
}

// recordLost feeds one record that failed to get through: a retransmission
// timeout, or one that exhausted its retries.
//
// Only a loss AT OR ABOVE THE CURRENT BUDGET is evidence about the ceiling,
// mirroring recordAcked's gate. A small record failing says the path is lossy,
// not narrow, so it is ignored rather than fed - otherwise a merely lossy path
// would shrink a wide budget toward the floor and pin it there.
//
// The step is always taken from the CURRENT budget, never from the size of the
// record that was lost. Stepping from the lost size lets a record sent under a
// larger, since-shrunk budget grow the budget as a side effect of its own
// failure, which is the exact opposite of what this signal means.
//
// The carrier's classifier suspends the controller while the path is throttled
// or blocked, so a rate-limited path cannot be mistaken for a narrow one. A
// lossy-but-responsive path IS classified healthy, which is why the size gate
// above carries this one: loss and narrowness have to be told apart, and the
// only evidence that distinguishes them is whether the record that failed was
// full size.
func (m *mtuController) recordLost(size int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mode == mtuFixed || m.suspended {
		return
	}
	if size < m.cur {
		// Below the current budget: this is evidence about loss, not width.
		return
	}
	m.losses++
	m.acks = 0
	if m.losses < mtuLossesToShrink {
		return
	}
	m.losses = 0

	next := m.cur - m.step
	if next < m.floor {
		next = m.floor
	}
	if next == m.cur {
		// Already at the floor and still failing: there is nothing left to
		// give, so stop burning probe traffic.
		m.freezeLocked()
		return
	}
	m.cur = next
	m.freezeLocked()
}

// adoptPathBudget applies a frag-needed / Packet Too Big report. The platform
// has already converted the next hop's MTU into a record budget.
//
// It only ever moves DOWN. Such a message is authoritative evidence that
// something was too big; it is not evidence that a larger size is possible, and
// treating it as a target would oscillate.
func (m *mtuController) adoptPathBudget(recordBudget int) {
	if recordBudget <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mode == mtuFixed {
		return
	}
	if recordBudget < m.floor {
		recordBudget = m.floor
	}
	if recordBudget >= m.cur {
		return
	}
	m.cur = recordBudget
	m.acks = 0
	m.losses = 0
	m.freezeLocked()
}

// shrinkForOversize applies "the kernel refused this exact size". With
// IP_MTU_DISCOVER in "do not fragment" mode that is an authoritative downward
// signal — the same information a frag-needed message would carry, obtained
// without waiting for anyone to send one — so it steps the budget down at once
// instead of waiting for a run of losses.
func (m *mtuController) shrinkForOversize(attempted int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mode == mtuFixed || m.suspended {
		return
	}
	next := attempted - m.step
	if next >= m.cur {
		next = m.cur - m.step
	}
	if next < m.floor {
		next = m.floor
	}
	if next >= m.cur {
		m.freezeLocked()
		return
	}
	m.cur = next
	m.acks = 0
	m.losses = 0
}

// growLocked returns the next budget, halving the step as the ceiling nears so
// the search converges instead of overshooting repeatedly.
func (m *mtuController) growLocked() int {
	remaining := m.ceiling - m.cur
	if remaining <= 0 {
		return m.ceiling
	}
	delta := m.step
	if remaining < 2*delta {
		delta = remaining / 2
	}
	if delta < 1 {
		delta = 1
	}
	next := m.cur + delta
	if next > m.ceiling {
		next = m.ceiling
	}
	return next
}

func (m *mtuController) freezeLocked() {
	if !m.frozen {
		m.frozen = true
		m.frozenAt = time.Now()
	}
}
