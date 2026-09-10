package tunnel

import (
	"context"
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
// There are two cooperating mechanisms:
//
//   - In-band adaptation (method B) runs for the life of a session. It grows
//     the budget after a run of acknowledged full-budget records, and shrinks
//     it after repeated losses — but a frag-needed message, when one does
//     arrive, is applied immediately because it is the only precise signal in
//     the whole system.
//   - The active probe (method A′) runs once, at session setup, over a
//     dedicated session to the built-in `discard://` sink (discard.go). It
//     binary-searches both directions with real records and then gets out of
//     the way. If it cannot run — the sink is not allowed, the peer is an older
//     build, the carrier is already throttled — it fails quietly and method B
//     carries on, which is strictly better than not having a budget at all.
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
	// mtuInBand runs in-band adaptation (method B) only.
	mtuInBand
	// mtuProbe runs the active probe (method A′) and then keeps adapting
	// in-band. It is the default.
	mtuProbe
)

func (m mtuMode) String() string {
	switch m {
	case mtuFixed:
		return "fixed"
	case mtuInBand:
		return "auto"
	case mtuProbe:
		return "probe"
	}
	return "unknown"
}

func parseMTUMode(s string) (mtuMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "probe":
		return mtuProbe, nil
	case "auto", "in-band", "inband":
		return mtuInBand, nil
	case "fixed", "off", "none":
		return mtuFixed, nil
	}
	return mtuProbe, fmt.Errorf("%w: icmp.mtu_mode = %q (want probe, auto or fixed)", ErrConfigRequired, s)
}

const (
	// mtuAcksToGrow is how many consecutive full-budget records must be
	// acknowledged before the budget grows one step. Acknowledgements, not
	// sends: a record that was retransmitted proves the path is marginal, not
	// that it is roomy.
	mtuAcksToGrow = 8
	// mtuLossesToShrink is how many consecutive failures at the current budget
	// are tolerated before stepping down. A single loss is noise.
	mtuLossesToShrink = 3
	// mtuFrozenRetry is how long a shrunken budget is trusted before the
	// search is allowed to try growing again. Without it a transient black
	// spot would shrink a path permanently.
	mtuFrozenRetry = 10 * time.Minute
	// mtuProbeBudget is the total number of probe records the active search
	// may spend, split evenly between the two directions.
	mtuProbeBudget = 12
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
		// Start at min(max_payload, 1200): the documented default never
		// fragments on either family, so the worst case is no better and no
		// worse than not adapting at all.
		if start > icmpDefaultMaxPayload {
			start = icmpDefaultMaxPayload
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

// recordLost feeds one record that exhausted its retransmissions.
func (m *mtuController) recordLost(int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mode == mtuFixed || m.suspended {
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

// adoptProbed applies an active-probe result. A probe is stronger evidence than
// in-band guessing, so it sets the budget outright — still clamped to
// [floor, ceiling], and still never above the configured maximum.
func (m *mtuController) adoptProbed(recordBudget int) {
	if recordBudget <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mode != mtuProbe {
		return
	}
	if recordBudget < m.floor {
		recordBudget = m.floor
	}
	if recordBudget > m.ceiling {
		recordBudget = m.ceiling
	}
	m.cur = recordBudget
	m.acks = 0
	m.losses = 0
	m.frozen = false
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

// ---------------------------------------------------------------------------
// Method A': the active probe
// ---------------------------------------------------------------------------

// mtuProbeLink is the narrow view of a dedicated probe session that the active
// search needs.
//
// It is expressed in RECORD terms on purpose. A probe built on a byte stream
// cannot answer the only question that matters — "did one record of exactly N
// bytes make it?" — because the session is free to split a write into smaller
// records. Sizes below are plaintext payload bytes, so the link owns the
// header and tag arithmetic.
type mtuProbeLink interface {
	// ProbeUplink ships exactly one record carrying payloadBytes of plaintext
	// and reports whether the peer acknowledged it.
	ProbeUplink(ctx context.Context, payloadBytes int) (bool, error)
	// ProbeDownlink asks the peer for payloadBytes of downlink filler and
	// reports whether a SINGLE record of at least that payload arrived.
	//
	// This measures the peer's send budget rather than the raw path, because
	// the peer cannot emit a record larger than its own budget. That is exactly
	// the number this end needs: it is the ceiling on downlink record size, and
	// it is what the receiving session must be able to accept.
	ProbeDownlink(ctx context.Context, payloadBytes int) (bool, error)
	// Close tears the probe session down. It is safe to call twice.
	Close() error
}

// mtuProbeResult is the outcome of one active search. Payload fields are
// plaintext bytes; zero means "no usable size found in that direction".
type mtuProbeResult struct {
	UplinkPayload   int
	DownlinkPayload int
	Probes          int
	CeilingHit      bool
}

// mtuProbeSearch runs the active search. It is pure: it never touches a socket
// directly, only the link, so it can be driven by a fake in tests.
type mtuProbeSearch struct {
	ceiling int // plaintext ceiling
	floor   int // plaintext floor
	step    int // plaintext step
	budget  int // total probe records
	log     Logger
}

func newMTUProbeSearch(prof resolvedProfile, logger Logger) mtuProbeSearch {
	payFloor := MaxPayloadFor(prof.mtuMin)
	if payFloor < 1 {
		payFloor = 1
	}
	payCeiling := MaxPayloadFor(prof.maxPayload)
	if payCeiling < payFloor {
		payCeiling = payFloor
	}
	payStep := prof.mtuStep
	if payStep < 1 {
		payStep = 1
	}
	return mtuProbeSearch{
		ceiling: payCeiling,
		floor:   payFloor,
		step:    payStep,
		budget:  mtuProbeBudget,
		log:     logger,
	}
}

// Run searches both directions over the link. It never fails the tunnel: an
// error here means "no usable probe result", and method B takes over.
func (s mtuProbeSearch) Run(ctx context.Context, link mtuProbeLink) mtuProbeResult {
	var res mtuProbeResult

	// Split the packet budget evenly; the uplink is searched first because it
	// is the direction this end actually controls.
	upBudget := s.budget / 2
	if upBudget < 1 {
		upBudget = 1
	}
	downBudget := s.budget - upBudget
	if downBudget < 1 {
		downBudget = 1
	}

	start := s.ceiling
	if start > MaxPayloadFor(icmpDefaultMaxPayload) {
		start = MaxPayloadFor(icmpDefaultMaxPayload)
	}
	if start < s.floor {
		start = s.floor
	}

	up, upProbes, upCeiling := searchMaxPayload(ctx, s.floor, start, s.ceiling, upBudget,
		func(size int) (bool, error) { return link.ProbeUplink(ctx, size) })
	res.UplinkPayload = up
	res.Probes += upProbes
	res.CeilingHit = res.CeilingHit || upCeiling

	down, downProbes, downCeiling := searchMaxPayload(ctx, s.floor, start, s.ceiling, downBudget,
		func(size int) (bool, error) { return link.ProbeDownlink(ctx, size) })
	res.DownlinkPayload = down
	res.Probes += downProbes
	res.CeilingHit = res.CeilingHit || downCeiling

	s.log.Infof("[ICMP] mtu probe done uplink=%d downlink=%d probes=%d ceiling_hit=%t",
		res.UplinkPayload, res.DownlinkPayload, res.Probes, res.CeilingHit)
	return res
}

// searchMaxPayload finds the largest payload size in [floor, ceiling] for which
// probe reports success, assuming the property is monotone: if a size succeeds,
// every smaller size succeeds too. That assumption is what makes a binary search
// valid, and it holds for both directions here — a smaller record is never
// harder to deliver than a larger one.
//
// It spends at most budget probes, returns the best size known to work, and
// reports whether it reached the ceiling.
func searchMaxPayload(
	ctx context.Context,
	floor, start, ceiling, budget int,
	probe func(int) (bool, error),
) (best, probes int, ceilingHit bool) {
	if ceiling < floor {
		ceiling = floor
	}
	if start < floor {
		start = floor
	}
	if start > ceiling {
		start = ceiling
	}
	try := func(size int) bool {
		probes++
		ok, err := probe(size)
		// A probe error is indistinguishable from "too big" for search
		// purposes: either way this size is not usable, and the caller has
		// method B to fall back on.
		return err == nil && ok
	}

	// The floor must work; if it does not, no size does and there is nothing to
	// search. Returning zero tells the caller to keep its in-band budget.
	if !try(floor) {
		return 0, probes, false
	}
	best = floor
	if floor >= ceiling || probes >= budget {
		return best, probes, floor >= ceiling
	}

	// Phase 1: probe the safe start, then grow geometrically so the failure
	// point is hit in O(log n) probes rather than one step at a time.
	if !try(start) {
		// Worse than assumed: refine downward between the known-good floor and
		// the failed start.
		low, high := floor, start
		for probes < budget && high-low > 1 {
			mid := low + (high-low)/2
			if try(mid) {
				best = mid
				low = mid
			} else {
				high = mid
			}
		}
		return best, probes, false
	}
	best = start
	if start >= ceiling || probes >= budget {
		return best, probes, start >= ceiling
	}

	low := start
	step := start - floor
	if step < 1 {
		step = 1
	}
	high := 0
	for probes < budget {
		next := low + step
		if next > ceiling {
			next = ceiling
		}
		if next <= low {
			break
		}
		if try(next) {
			best = next
			if next >= ceiling {
				return best, probes, true
			}
			low = next
			step *= 2
			continue
		}
		high = next
		break
	}
	if high == 0 {
		return best, probes, false
	}

	// Phase 2: halve the remaining gap.
	for probes < budget && high-low > 1 {
		mid := low + (high-low)/2
		if try(mid) {
			best = mid
			low = mid
		} else {
			high = mid
		}
	}
	return best, probes, best >= ceiling
}
