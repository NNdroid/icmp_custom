package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The ICMP transport profile.
//
// This file is the carrier-agnostic half of the ICMP profile: the configuration
// and its validation, the Echo Identifier pool, the pacing token bucket, the
// carrier health state machine, and the adapter that turns a platform socket
// backend into a Transport. The socket handling itself lives in
// icmp_linux.go (raw dual-stack) and icmp_android.go (unprivileged ping
// socket), and nothing here knows which of them is underneath.
//
// The split matters for one concrete reason: `GOOS=android` also satisfies a
// bare `linux` build constraint, so a raw-socket implementation guarded only by
// `//go:build linux` would be compiled into the Android binary and fail on the
// device. Each platform file therefore declares its own constraint and only the
// seam below is shared.

// ---------------------------------------------------------------------------
// Defaults and per-family bounds
// ---------------------------------------------------------------------------

const (
	// icmpDefaultMaxPayload is the largest complete v2 record carried by
	// default. 1200 is deliberately conservative: it sits below the IPv6
	// guaranteed floor (1232) and far below the IPv4 ceiling (1472), so the
	// default path never fragments on either family. Not fragmenting matters
	// because CGNATs commonly drop fragments outright, and because IPv6 routers
	// never fragment at all.
	icmpDefaultMaxPayload = 1200

	// Per-family ceilings for the complete-record budget:
	//   IPv4: 1500 - 20 (IPv4 header) - 8 (ICMP header)   = 1472
	//   IPv6: 1500 - 40 (IPv6 header) - 8 (ICMPv6 header) = 1452
	icmpV4MaxPayload = 1472
	icmpV6MaxPayload = 1452

	// icmpMinPayload is the floor for both families. IPv4 guarantees
	// reassembly of a 576-byte datagram (576 - 20 - 8 = 548); an IP path that
	// cannot carry 548 bytes is not a usable path at all.
	icmpMinPayload = 548

	icmpDefaultMTUMin   = 548
	icmpDefaultMTUStep  = 100
	icmpDefaultPaceMS   = 20
	icmpDefaultBlockTO  = 60 * time.Second
	icmpDefaultMTUMode  = "probe"
	icmpDefaultPollsIF  = 4
	icmpDefaultIdleMS   = 1000
	icmpDefaultKeepMS   = 15000
	icmpMinPaceMS       = 1
	icmpPaceBurstFactor = 4
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// ICMPProfile is the user-facing ICMP transport configuration, populated from
// the `icmp` object of a config file. Its zero value is exactly the documented
// default profile, so an omitted `icmp` block means "defaults".
//
// Note what is NOT here, and cannot be: `port_range`, `origdst`,
// `sendsock_max`, `receive_sockets`. Those describe the UDP profile's
// port-spreading machinery, which has no ICMP counterpart and belongs to
// another project. Because encoding/json ignores unknown keys, a config file
// that still carries them is accepted and simply not read. `family` is not
// here either, for the same reason a client does not configure it: there is no
// meaningful choice. A server binds both families; a client follows its peer.
// A leftover `family` key in an existing config is therefore ignored, not an
// error.
type ICMPProfile struct {
	// MaxPayload is the largest complete v2 record to carry. It is both the
	// starting point and the hard ceiling of the automatic MTU search.
	MaxPayload int `json:"max_payload"`
	// MTUMode is "probe" (handshake-time active probe plus in-band
	// adaptation), "auto" (in-band adaptation only) or "fixed" (trust
	// MaxPayload and never adapt).
	MTUMode string `json:"mtu_mode"`
	// MTUMin is the floor the search will never step below.
	MTUMin int `json:"mtu_min"`
	// MTUStep is the upward step, halved as the ceiling approaches.
	MTUStep int `json:"mtu_step"`
	// PaceMS spaces outbound packets. Both ends need it: a client that floods
	// Echo Requests trips the host's global ICMP allowance, and the resulting
	// loss is indistinguishable from a broken path.
	PaceMS int `json:"pace_ms"`
	// IDRange restricts Echo Identifiers to a pool, e.g. "1000-1999".
	//
	// It does NOT buy throughput the way the UDP profile's `port_range` does:
	// UDP rate limits are charged per (destination, port) while ICMP limits are
	// charged per destination IP against a global allowance. Spreading ids
	// diversifies NAT and middlebox flow keys; it cannot multiply an allowance.
	IDRange string `json:"id_range"`
	// Probe enables the optional server-initiated reverse probe. It is
	// best-effort by nature (see DESIGN_ICMP.md §4.9) and degrades to
	// client-driven polling after repeated failure. nil means enabled.
	Probe *bool `json:"probe"`
	// PollsInFlight is the client's sliding request window, i.e. the hard
	// ceiling on downlink throughput (~ window / RTT).
	PollsInFlight int `json:"polls_in_flight"`
	// IdlePollMS is the poll spacing once the tunnel is quiet.
	IdlePollMS int `json:"idle_poll_ms"`
	// KeepAliveMS is the poll spacing once the tunnel is deeply idle.
	KeepAliveMS int `json:"keepalive_ms"`
	// BlockTimeout is how long a fully blocked carrier is tolerated before the
	// session is torn down. It is also the retransmit spacing while blocked,
	// so a black hole is probed slowly instead of being amplified.
	BlockTimeout string `json:"block_timeout"`
}

// icmpFamily is the address family of one socket. The profile no longer asks
// the operator for it: a server binds both, a client follows its peer — the
// only two choices that ever made sense. The type stays because the socket
// layer is still per-family.
type icmpFamily int

const (
	// familyAuto means "both" for a server and is resolved to the peer's
	// family for a client.
	familyAuto icmpFamily = iota
	familyV4
	familyV6
)

func (f icmpFamily) String() string {
	switch f {
	case familyV4:
		return "ipv4"
	case familyV6:
		return "ipv6"
	default:
		return "auto"
	}
}

// budgetBounds reports the config acceptance interval for the complete-record
// budget. It is family-independent and equals what "auto" always demanded: the
// smaller of the two per-family ceilings. A dual-stack server binds both
// families, and a budget that only fits IPv4 would silently oversized its
// IPv6 half; the peer's own profile can put records up to this same bound on
// the wire, so it is also the receive ceiling.
func budgetBounds() (lo, hi int) {
	return icmpMinPayload, icmpV6MaxPayload
}

// resolvedProfile is a validated ICMPProfile with every default applied.
type resolvedProfile struct {
	maxPayload    int
	mtuMode       mtuMode
	mtuMin        int
	mtuStep       int
	pace          time.Duration
	idSpec        string
	probe         bool
	pollsInFlight int
	idlePoll      time.Duration
	keepAlive     time.Duration
	blockTimeout  time.Duration
}

// resolve validates the profile and fills in defaults. Every rejection names
// the field, the offending value and the accepted range: a transport that
// cannot exist must fail loudly at configuration time, never silently at the
// first packet.
func (p ICMPProfile) resolve() (resolvedProfile, error) {
	var out resolvedProfile
	var err error

	lo, hi := budgetBounds()
	out.maxPayload = p.MaxPayload
	if out.maxPayload == 0 {
		out.maxPayload = icmpDefaultMaxPayload
	}
	if out.maxPayload < lo || out.maxPayload > hi {
		return out, fmt.Errorf("%w: icmp.max_payload = %d, want %d..%d",
			ErrConfigRequired, out.maxPayload, lo, hi)
	}

	if out.mtuMode, err = parseMTUMode(p.MTUMode); err != nil {
		return out, err
	}

	out.mtuMin = p.MTUMin
	if out.mtuMin == 0 {
		out.mtuMin = icmpDefaultMTUMin
	}
	if out.mtuMin < icmpMinPayload || out.mtuMin > out.maxPayload {
		return out, fmt.Errorf("%w: icmp.mtu_min = %d, want %d..%d (<= max_payload)",
			ErrConfigRequired, out.mtuMin, icmpMinPayload, out.maxPayload)
	}

	out.mtuStep = p.MTUStep
	if out.mtuStep == 0 {
		out.mtuStep = icmpDefaultMTUStep
	}
	if out.mtuStep < 1 || out.mtuStep > out.maxPayload {
		return out, fmt.Errorf("%w: icmp.mtu_step = %d, want 1..%d", ErrConfigRequired, out.mtuStep, out.maxPayload)
	}

	paceMS := p.PaceMS
	if paceMS == 0 {
		paceMS = icmpDefaultPaceMS
	}
	if paceMS < icmpMinPaceMS {
		return out, fmt.Errorf("%w: icmp.pace_ms = %d, want >= %d", ErrConfigRequired, p.PaceMS, icmpMinPaceMS)
	}
	out.pace = time.Duration(paceMS) * time.Millisecond

	if out.idSpec, err = validateIDRange(p.IDRange); err != nil {
		return out, err
	}

	out.probe = p.Probe == nil || *p.Probe

	out.pollsInFlight = p.PollsInFlight
	if out.pollsInFlight == 0 {
		out.pollsInFlight = icmpDefaultPollsIF
	}
	if out.pollsInFlight < 1 {
		return out, fmt.Errorf("%w: icmp.polls_in_flight = %d, want >= 1", ErrConfigRequired, p.PollsInFlight)
	}

	idleMS := p.IdlePollMS
	if idleMS == 0 {
		idleMS = icmpDefaultIdleMS
	}
	if idleMS < 1 {
		return out, fmt.Errorf("%w: icmp.idle_poll_ms = %d, want >= 1", ErrConfigRequired, p.IdlePollMS)
	}
	out.idlePoll = time.Duration(idleMS) * time.Millisecond

	keepMS := p.KeepAliveMS
	if keepMS == 0 {
		keepMS = icmpDefaultKeepMS
	}
	if keepMS < 1 {
		return out, fmt.Errorf("%w: icmp.keepalive_ms = %d, want >= 1", ErrConfigRequired, p.KeepAliveMS)
	}
	out.keepAlive = time.Duration(keepMS) * time.Millisecond

	out.blockTimeout = icmpDefaultBlockTO
	if s := strings.TrimSpace(p.BlockTimeout); s != "" {
		if out.blockTimeout, err = time.ParseDuration(s); err != nil {
			return out, fmt.Errorf("%w: icmp.block_timeout = %q: %v", ErrConfigRequired, p.BlockTimeout, err)
		}
		if out.blockTimeout <= 0 {
			return out, fmt.Errorf("%w: icmp.block_timeout must be positive", ErrConfigRequired)
		}
	}
	return out, nil
}

// Validate reports whether the profile is internally consistent, applying the
// same defaults the carrier will apply. It exists so a CLI or an embedder can
// reject a bad `icmp` block before a socket is opened, rather than discovering
// it on the first packet. The returned error is always an ErrConfigRequired
// chain naming the offending field and its accepted range.
func (p ICMPProfile) Validate() error {
	_, err := p.resolve()
	return err
}

// ---------------------------------------------------------------------------
// Echo Identifier pool
// ---------------------------------------------------------------------------

// idProvider supplies the Echo Identifier stamped on an outbound request.
//
// It is an interface because the two production carriers differ fundamentally:
// a raw socket chooses a fresh Identifier for every packet, which spreads the
// tunnel across as many NAT and conntrack keys as the pool allows, while a ping
// socket does not get to choose at all — the kernel assigns one Identifier per
// socket. Same interface, two very different capabilities.
type idProvider interface {
	next() uint16
}

// pooledIDs is the raw-socket provider. With a configured range it hands out
// ids round-robin from a random starting point; without one it draws a fresh
// random id for every packet.
type pooledIDs struct {
	mu     sync.Mutex
	ranged bool
	lo, hi uint16
	nextID uint16
}

// maxEchoID is the largest Identifier we will choose. 65535 is reserved as
// "unset" so an id can never be confused with a zero-valued PathID field.
const maxEchoID = 65534

func newPooledIDs(spec string) (*pooledIDs, error) {
	lo, hi, ranged, err := parseIDRange(spec)
	if err != nil {
		return nil, err
	}
	return &pooledIDs{ranged: ranged, lo: lo, hi: hi}, nil
}

func (p *pooledIDs) next() uint16 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ranged {
		return randomEchoID()
	}
	if p.nextID < p.lo || p.nextID > p.hi {
		p.nextID = p.lo + uint16(randomUint32()%uint32(p.hi-p.lo+1))
	}
	id := p.nextID
	if p.nextID >= p.hi {
		p.nextID = p.lo
	} else {
		p.nextID++
	}
	return id
}

// fixedID is the ping-socket provider: whatever Identifier the kernel bound to
// this socket. Spreading therefore needs more sockets, not more ids.
type fixedID struct{ id uint16 }

func (f fixedID) next() uint16 { return f.id }

func randomEchoID() uint16 { return uint16(randomUint32()%maxEchoID) + 1 }

func randomUint32() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail on supported platforms; if it somehow
		// does, a time-derived value is still better than a constant that
		// would collide across every tunnel.
		return uint32(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint32(b[:])
}

// validateIDRange checks an `id_range` value and returns it normalised.
func validateIDRange(spec string) (string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", nil
	}
	if _, _, ranged, err := parseIDRange(spec); err != nil {
		return "", err
	} else if !ranged {
		return "", fmt.Errorf("%w: icmp.id_range = %q should look like \"1000-1999\"", ErrConfigRequired, spec)
	}
	return spec, nil
}

func parseIDRange(spec string) (lo, hi uint16, ranged bool, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, 0, false, nil
	}
	dash := strings.IndexByte(spec, '-')
	if dash <= 0 || dash == len(spec)-1 {
		return 0, 0, false, fmt.Errorf("%w: icmp.id_range = %q (want \"lo-hi\")", ErrConfigRequired, spec)
	}
	loN, errLo := strconv.ParseUint(strings.TrimSpace(spec[:dash]), 10, 32)
	hiN, errHi := strconv.ParseUint(strings.TrimSpace(spec[dash+1:]), 10, 32)
	if errLo != nil || errHi != nil {
		return 0, 0, false, fmt.Errorf("%w: icmp.id_range = %q is not numeric", ErrConfigRequired, spec)
	}
	if loN < 1 || hiN > 65535 || loN > hiN {
		return 0, 0, false, fmt.Errorf("%w: icmp.id_range = %q must satisfy 1 <= lo <= hi <= 65535", ErrConfigRequired, spec)
	}
	return uint16(loN), uint16(hiN), true, nil
}

// ---------------------------------------------------------------------------
// Pacing
// ---------------------------------------------------------------------------

// pacer spaces outbound carrier packets.
//
// Both ends need one. A client that floods Echo Requests exhausts the host's
// global ICMP allowance and the kernel silently drops the excess; the tunnel
// then sees "loss" that no amount of retransmitting can fix, because the
// retransmits are themselves what is being dropped. Pacing is not politeness,
// it is what keeps the loss signal meaningful.
type pacer struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newPacer(interval time.Duration) *pacer {
	if interval <= 0 {
		interval = time.Millisecond
	}
	return &pacer{interval: interval}
}

func (p *pacer) setInterval(d time.Duration) {
	if d <= 0 {
		d = time.Millisecond
	}
	p.mu.Lock()
	p.interval = d
	p.mu.Unlock()
}

func (p *pacer) currentInterval() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.interval
}

// wait blocks until this caller's slot arrives, or ctx is done. A caller that
// finds the pacer idle departs immediately and opens the next slot one interval
// later, so a quiet tunnel resumes without a burst.
func (p *pacer) wait(ctx context.Context) error {
	p.mu.Lock()
	now := time.Now()
	if p.next.IsZero() || now.After(p.next) {
		p.next = now
	}
	delay := p.next.Sub(now)
	p.next = p.next.Add(p.interval)
	// Cap accumulated debt at a few intervals: a burst of callers that were
	// all blocked must not translate into a stall that outlives the burst.
	if cap := now.Add(icmpPaceBurstFactor * p.interval); p.next.After(cap) {
		p.next = cap
	}
	p.mu.Unlock()

	if delay <= 0 {
		return nil
	}
	// Fail before arming a timer when the caller is already gone. A paced send
	// runs once per packet, so the shutdown path must not allocate a timer it
	// is about to abandon — and a caller that is cancelling wants the prompt
	// answer, not a sleep it will never use.
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ---------------------------------------------------------------------------
// Carrier health
// ---------------------------------------------------------------------------

const (
	// carrierWindow is the classification window. Two buckets of half the
	// window approximate a sliding window without keeping per-event history.
	carrierWindow    = 10 * time.Second
	carrierBucketLen = carrierWindow / 2
	// carrierMinPolls is the evidence threshold: below it, "no replies" is
	// just "nothing happened yet".
	carrierMinPolls = 5
	// carrierHealthyLogEvery throttles the healthy heartbeat while UP.
	carrierHealthyLogEvery = 60 * time.Second
	// carrierRTTBalloon is the multiple of the best observed RTT that counts
	// as "the path has degraded" even when replies still arrive.
	carrierRTTBalloon = 3
)

type carrierBucket struct {
	polls   uint64
	replies uint64
	auth    uint64
}

// carrierMonitor classifies a request/reply path into the states the operator
// needs to tell apart, and emits exactly one log line per transition.
//
// The reason this exists at all: "my packet was not acknowledged" is the same
// observation whether the path is being rate-limited or is dead, and the
// correct reaction is opposite. Answering a rate limit with retransmits is how
// a temporary limit becomes a permanent one.
type carrierMonitor struct {
	mu   sync.Mutex
	peer netip.AddrPort
	log  Logger
	now  func() time.Time

	baseFloor    time.Duration
	blockTimeout time.Duration
	pace         time.Duration

	state CarrierState

	bucketAt time.Time
	cur      carrierBucket
	prev     carrierBucket

	rttEWMA time.Duration
	minRTT  time.Duration

	// forcedBlock is set by a fatal socket error, which is not loss at all:
	// the carrier itself is gone.
	forcedBlock bool
	lastLine    time.Time
}

func newCarrierMonitor(peer netip.AddrPort, pace, blockTimeout time.Duration, logger Logger) *carrierMonitor {
	base := defaultRTOFloor
	if floor := pace * icmpPaceBurstFactor; floor > base {
		base = floor
	}
	if blockTimeout <= 0 {
		blockTimeout = icmpDefaultBlockTO
	}
	return &carrierMonitor{
		peer:         peer,
		log:          logger,
		now:          time.Now,
		baseFloor:    base,
		blockTimeout: blockTimeout,
		pace:         pace,
		state:        CarrierInit,
		bucketAt:     time.Now(),
	}
}

// rollLocked advances the bucket clock. A caller that has been quiet for
// several buckets must not keep stale counts, so the loop zeroes each skipped
// bucket rather than collapsing them.
func (m *carrierMonitor) rollLocked(now time.Time) {
	for !now.Before(m.bucketAt.Add(carrierBucketLen)) {
		m.prev = m.cur
		m.cur = carrierBucket{}
		m.bucketAt = m.bucketAt.Add(carrierBucketLen)
	}
}

func (m *carrierMonitor) notePace(d time.Duration) {
	m.mu.Lock()
	m.pace = d
	m.mu.Unlock()
}

func (m *carrierMonitor) notePoll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rollLocked(m.now())
	m.cur.polls++
	m.evaluateLocked()
}

func (m *carrierMonitor) noteReply(rtt time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rollLocked(m.now())
	m.cur.replies++
	if rtt > 0 {
		if m.rttEWMA == 0 {
			m.rttEWMA = rtt
		} else {
			m.rttEWMA = (m.rttEWMA*7 + rtt) / 8
		}
		if m.minRTT == 0 || rtt < m.minRTT {
			m.minRTT = rtt
		}
	}
	m.evaluateLocked()
}

// noteAuthenticated records that a record passed AEAD verification. It is the
// one signal that unblocks a BLOCKED path: it proves a round trip happened.
func (m *carrierMonitor) noteAuthenticated() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rollLocked(m.now())
	m.cur.auth++
	m.forcedBlock = false
	if m.state == CarrierBlocked {
		m.transitionLocked(CarrierUp)
		return
	}
	m.evaluateLocked()
}

// noteSocketError records a fatal socket condition. ENETUNREACH, EHOSTUNREACH
// and EACCES are not loss — no amount of retransmitting will help, so the
// carrier is declared blocked immediately.
func (m *carrierMonitor) noteSocketError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.forcedBlock = true
	m.transitionLocked(CarrierBlocked)
}

// State reports the current classification.
func (m *carrierMonitor) State() CarrierState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// RTOFloor is the smallest retransmit timeout worth using right now.
func (m *carrierMonitor) RTOFloor() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch m.state {
	case CarrierThrottled:
		return 2 * m.baseFloor
	case CarrierBlocked:
		// While blocked, retransmitting at the normal RTO is pure
		// amplification. One slow probe per block timeout is all we allow, and
		// it is also what eventually retires a session whose path never comes
		// back (the session's retry ceiling is reached at that cadence).
		return m.blockTimeout
	default:
		return m.baseFloor
	}
}

func (m *carrierMonitor) evaluateLocked() {
	if m.forcedBlock {
		m.transitionLocked(CarrierBlocked)
		return
	}
	// BLOCKED is sticky: only authenticated traffic clears it, and that is
	// handled by noteAuthenticated.
	if m.state == CarrierBlocked {
		return
	}

	polls := m.cur.polls + m.prev.polls
	replies := m.cur.replies + m.prev.replies
	auth := m.cur.auth + m.prev.auth
	if polls == 0 && auth == 0 {
		return
	}

	lossPct := 0
	if polls > 0 {
		lossPct = int(100 * (polls - replies) / polls)
	}

	switch {
	case polls >= carrierMinPolls && replies == 0:
		m.transitionLocked(CarrierBlocked)
	case polls >= carrierMinPolls && replies*2 < polls:
		m.transitionLocked(CarrierThrottled)
	case m.minRTT > 0 && m.rttEWMA > carrierRTTBalloon*m.minRTT:
		m.transitionLocked(CarrierThrottled)
	case auth > 0 && lossPct < 20:
		m.transitionLocked(CarrierUp)
	}
}

func (m *carrierMonitor) transitionLocked(next CarrierState) {
	if next == m.state {
		if next == CarrierUp && m.now().Sub(m.lastLine) >= carrierHealthyLogEvery {
			m.logHealthyLocked()
		}
		return
	}
	m.state = next
	switch next {
	case CarrierUp:
		m.logHealthyLocked()
	case CarrierThrottled:
		m.logThrottledLocked()
	case CarrierBlocked:
		m.logBlockedLocked()
	}
}

func (m *carrierMonitor) lossLocked() (polls, replies uint64, lossPct int) {
	polls = m.cur.polls + m.prev.polls
	replies = m.cur.replies + m.prev.replies
	if polls > 0 {
		lossPct = int(100 * (polls - replies) / polls)
	}
	return
}

// The three log signatures are the acceptance contract: an operator must be
// able to tell a healthy path, a rate-limited one and a blocked one apart
// without guessing.
func (m *carrierMonitor) logHealthyLocked() {
	polls, replies, loss := m.lossLocked()
	m.log.Infof("[ICMP] path healthy peer=%s polls=%d replies=%d loss=%d%% rtt_ewma=%s",
		m.peer, polls, replies, loss, m.rttEWMA)
	m.lastLine = m.now()
}

func (m *carrierMonitor) logThrottledLocked() {
	polls, replies, loss := m.lossLocked()
	rto := 2 * m.baseFloor
	m.log.Warnf("[ICMP] carrier throttled (kernel/middlebox rate limit?) peer=%s loss=%d%% replies=%d/%d rto=%s pace=%s",
		m.peer, loss, replies, polls, rto, m.pace)
	m.lastLine = m.now()
}

func (m *carrierMonitor) logBlockedLocked() {
	polls, _, _ := m.lossLocked()
	m.log.Errorf("[ICMP] carrier blocked: polls=%d replies=0 window=%s peer=%s hint=allow ICMP echo request+reply in BOTH directions",
		polls, carrierWindow, m.peer)
	m.lastLine = m.now()
}

// ---------------------------------------------------------------------------
// Outstanding-poll bookkeeping
// ---------------------------------------------------------------------------

// pokeBook remembers which Echo sequence numbers are unanswered polls, and when
// they were sent, so a reply can be attributed to the poll it answers — and
// timed. Without it, replies to data records would be miscounted as poll answers
// and a throttled path would look healthy, which is the one mistake that turns a
// temporary rate limit into an apparent outage.
type pokeBook struct {
	mu   sync.Mutex
	open map[uint16]time.Time
}

func newPokeBook() *pokeBook { return &pokeBook{open: make(map[uint16]time.Time, 8)} }

func (b *pokeBook) add(seq uint16) {
	b.mu.Lock()
	if len(b.open) >= 512 {
		// The window stalled long enough that every entry is stale; keeping
		// them would only mis-attribute future replies.
		b.open = make(map[uint16]time.Time, 8)
	}
	b.open[seq] = time.Now()
	b.mu.Unlock()
}

// claim reports whether seq answered an outstanding poll, removing it and
// returning when it was sent.
func (b *pokeBook) claim(seq uint16) (time.Time, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	sent, ok := b.open[seq]
	if !ok {
		return time.Time{}, false
	}
	delete(b.open, seq)
	return sent, true
}

func (b *pokeBook) len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.open)
}

// ---------------------------------------------------------------------------
// Shared carrier core
// ---------------------------------------------------------------------------

// icmpCore is everything the ICMP profile does that is independent of how a
// packet leaves the machine: id selection, pacing, the health classifier, and
// the automatic MTU controller. Both platform carriers delegate to it.
type icmpCore struct {
	ids    idProvider
	pace   *pacer
	mtu    *mtuController
	mon    *carrierMonitor
	book   *pokeBook
	logger Logger

	probeEnabled bool
	probeFails   atomic.Int32
	probeOff     atomic.Bool

	pollsSent   atomic.Uint64
	repliesSeen atomic.Uint64
	seq         atomic.Uint32
}

func newICMPCore(prof resolvedProfile, peer netip.AddrPort, ids idProvider, logger Logger) *icmpCore {
	return &icmpCore{
		ids:          ids,
		pace:         newPacer(prof.pace),
		mtu:          newMTUController(prof.mtuMode, prof.maxPayload, prof.mtuMin, prof.mtuStep),
		mon:          newCarrierMonitor(peer, prof.pace, prof.blockTimeout, logger),
		book:         newPokeBook(),
		logger:       logger,
		probeEnabled: prof.probe,
	}
}

func (c *icmpCore) nextID() uint16 { return c.ids.next() }

func (c *icmpCore) nextSeq() uint16 {
	for {
		v := c.seq.Add(1)
		if s := uint16(v); s != 0 {
			return s
		}
	}
}

func (c *icmpCore) waitPace(ctx context.Context) error {
	if err := c.pace.wait(ctx); err != nil {
		return err
	}
	// The classifier must not be lulled by an actively faster pace.
	c.mon.notePace(c.pace.currentInterval())
	// Freeze MTU adaptation while the path is unhealthy: loss caused by a rate
	// limit says nothing about the path MTU, and probing a throttled path makes
	// the limit worse.
	switch c.mon.State() {
	case CarrierThrottled, CarrierBlocked:
		c.mtu.setSuspended(true)
	default:
		c.mtu.setSuspended(false)
	}
	return nil
}

// notePoll records an outstanding poll so its answer can be recognised.
func (c *icmpCore) notePoll(seq uint16) {
	c.pollsSent.Add(1)
	c.book.add(seq)
	c.mon.notePoll()
}

// noteReply attributes an inbound Echo Reply to the poll it answers, and times
// it. A reply whose sequence number we never sent — a NAT that rewrites
// sequence numbers, say — is ignored rather than guessed at: miscounting it
// would corrupt the loss estimate, which is the one number the health
// classifier cannot afford to get wrong.
func (c *icmpCore) noteReply(seq uint16, now time.Time) {
	sent, ok := c.book.claim(seq)
	if !ok {
		return
	}
	c.repliesSeen.Add(1)
	c.mon.noteReply(now.Sub(sent))
}

// noteInboundRequest records that the peer polled us. An inbound Echo Request
// is itself proof that the path carries traffic in the peer's direction, so it
// keeps a path from being declared blocked while the peer is demonstrably
// reaching us.
func (c *icmpCore) noteInboundRequest() { c.mon.noteAuthenticated() }

// noteSendOutcome turns a send failure into MTU evidence. Exactly one failure
// carries information about the path MTU: an oversized-packet refusal, which
// with IP_MTU_DISCOVER in "do not fragment" mode means the path is narrower
// than our budget.
func (c *icmpCore) noteSendOutcome(rec []byte, err error) {
	if err == nil || len(rec) == 0 {
		return
	}
	if errors.Is(err, ErrRecordTooLarge) {
		c.mtu.shrinkForOversize(len(rec))
	}
}

// noteSendTooLarge applies the "the kernel refused this size" signal.
func (c *icmpCore) noteSendTooLarge(size int) { c.mtu.shrinkForOversize(size) }

func (c *icmpCore) noteAuthenticated() { c.mon.noteAuthenticated() }

func (c *icmpCore) noteSocketError() { c.mon.noteSocketError() }

func (c *icmpCore) maxRecordSize() int { return c.mtu.budget() }

// receiveCeiling is the fixed upper bound on a record the peer may send us. It
// is the configured ceiling, deliberately independent of the adaptive budget.
func (c *icmpCore) receiveCeiling() int { return c.mtu.receiveCeiling() }

func (c *icmpCore) recordAcked(size int) { c.mtu.recordAcked(size) }

func (c *icmpCore) recordLost(size int) { c.mtu.recordLost(size) }

func (c *icmpCore) adoptPathBudget(budget int) { c.mtu.adoptPathBudget(budget) }

// adoptProbedBudget applies an active-probe result, which is stronger evidence
// than in-band guessing.
func (c *icmpCore) adoptProbedBudget(budget int) { c.mtu.adoptProbed(budget) }

// mtuProbeWanted reports whether the active probe should be attempted at all.
func (c *icmpCore) mtuProbeWanted() bool { return c.mtu.modeOf() == mtuProbe }

func (c *icmpCore) carrierState() CarrierState { return c.mon.State() }

func (c *icmpCore) rtoFloor() time.Duration { return c.mon.RTOFloor() }

func (c *icmpCore) pollStats() (uint64, uint64) {
	return c.pollsSent.Load(), c.repliesSeen.Load()
}

// probeAvailable reports whether the reverse probe may still be attempted.
func (c *icmpCore) probeAvailable() bool { return c.probeEnabled && !c.probeOff.Load() }

// noteProbeResult degrades the reverse probe after repeated failure. It is
// best-effort by nature: whether an Echo Request reaches a raw socket at all
// depends on the kernel, so three failures means "stop trying", not "error".
func (c *icmpCore) noteProbeResult(ok bool) {
	if ok {
		c.probeFails.Store(0)
		return
	}
	if c.probeFails.Add(1) >= 3 && !c.probeOff.Swap(true) {
		c.logger.Infof("[ICMP] reverse probe disabled after repeated failure; client polling carries the downlink")
	}
}

// ---------------------------------------------------------------------------
// Platform seam
// ---------------------------------------------------------------------------

// icmpRole tells a platform constructor which end it is building for. The
// server binds the family's sockets and accepts from anyone; the client
// connects to exactly one peer.
type icmpRole int

const (
	icmpRoleServer icmpRole = iota
	icmpRoleClient
)

// inboundEcho is one received ICMP message after a platform has stripped its
// envelope. Exactly one of Payload and PathMTU is meaningful.
type inboundEcho struct {
	// Payload is the ICMP body. For an Echo Request or Reply it is a complete
	// v2 record, byte for byte.
	Payload []byte
	// Path is the channel key to mirror on a reply.
	Path PathID
	// IsRequest is true for an Echo Request: the peer is polling us and
	// expects a Reply. False means this is the answer to something we sent.
	IsRequest bool
	// PathBudget, when non-zero, is the largest complete v2 record the next
	// hop can carry, derived by the platform from a frag-needed (IPv4 type 3
	// code 4) or Packet Too Big (ICMPv6 type 2) message. Such a message carries
	// no record, and is the ONLY precise downward signal the automatic MTU
	// search ever gets.
	//
	// It is a record budget rather than a raw MTU because only the platform
	// knows which family's header overhead applies.
	PathBudget int
}

// platformICMP is the socket side of the carrier: put an Echo on the wire, read
// one back. Everything else — pacing, id selection, MTU search, health
// classification — is shared, in icmpCore.
type platformICMP interface {
	// sendEcho emits one Echo Request carrying payload toward to, stamping the
	// given Identifier and sequence number.
	sendEcho(payload []byte, to netip.AddrPort, ident, seq uint16) error
	// sendEchoReply emits one Echo Reply, mirroring path exactly: the same
	// Identifier and sequence number the peer (and any NAT) expects to see.
	sendEchoReply(payload []byte, path PathID) error
	// readEcho blocks for one inbound ICMP message. A returned Payload aliases
	// buf; a payload that does not fit is a hard error, never a truncation.
	readEcho(buf []byte) (inboundEcho, error)

	localLabel() string
	remoteLabel() string
	close() error
}

// icmpConfig is the fully-resolved, platform-facing carrier configuration.
type icmpConfig struct {
	role   icmpRole
	family icmpFamily
	// peer is the client's target. When family is auto the client derives the
	// socket family from it; the server ignores it and binds in.bindV4/in.bindV6.
	peer netip.Addr
	// bindV4/bindV6 apply to the server: "auto" binds both, a forced family
	// binds one. A forced IPv6 server on a host without usable IPv6 fails
	// loudly rather than silently serving IPv4.
	bindV4 bool
	bindV6 bool
	// core carries the shared profile behaviour. It is built by the caller so
	// the record budget it publishes is the same object the session reads.
	core *icmpCore
	// protectFD, when set, is called with each carrier socket descriptor so an
	// Android VpnService can exempt it from its own tunnel. It is never set on
	// desktop platforms.
	protectFD func(fd int) error
}

// newPlatformICMPTransport builds the carrier this platform can actually
// provide: a raw dual-stack carrier on Linux, an unprivileged ping-socket
// carrier on Android, and an explicit, actionable error everywhere else.
//
// It is DEFINED once per platform file rather than here, so that
// `GOOS=android` — which also satisfies a bare `linux` constraint — picks the
// ping socket rather than the raw socket, which would fail on the device:
//
//	icmp_linux.go    //go:build linux && !android   raw, IPv4 + IPv6
//	icmp_android.go  //go:build android             ping socket, no privileges
//	icmp_other.go    //go:build !linux && !android  unsupported, with a hint
//
// The three files agree on the signature below and on nothing else; all shared
// behaviour lives in this file.
//
//	func newPlatformICMPTransport(cfg *icmpConfig) (platformICMP, error)

// icmpTransport adapts a platformICMP to the Transport contract. There is
// exactly one implementation of the ICMP carrier; the platform files only
// supply sockets.
type icmpTransport struct {
	platform  platformICMP
	core      *icmpCore
	closeOnce sync.Once
}

var (
	_ Transport             = (*icmpTransport)(nil)
	_ MaxRecordSizer        = (*icmpTransport)(nil)
	_ MaxReceiveSizer       = (*icmpTransport)(nil)
	_ Poller                = (*icmpTransport)(nil)
	_ Prober                = (*icmpTransport)(nil)
	_ CarrierCondition      = (*icmpTransport)(nil)
	_ MTUFeedback           = (*icmpTransport)(nil)
	_ AuthenticatedFeedback = (*icmpTransport)(nil)
)

// icmpReadSlack caps how long ReadRecord will sit on a socket error before
// giving up, so a transient send failure cannot wedge the receive loop.
const icmpReadSlack = 4 * time.Second

// ReadRecord implements Transport.
func (t *icmpTransport) ReadRecord(buf []byte) (int, PathID, error) {
	for {
		echo, err := t.platform.readEcho(buf)
		if err != nil {
			if isClosedTransportErr(err) {
				return 0, PathID{}, err
			}
			t.core.noteSocketError()
			return 0, PathID{}, err
		}
		if echo.PathBudget > 0 {
			// A frag-needed message is not a record; it is the one precise
			// downward signal in the whole MTU search. Adopt it and keep
			// listening.
			t.core.adoptPathBudget(echo.PathBudget)
			continue
		}
		if echo.IsRequest {
			// The peer is polling us. Its arrival is itself evidence that the
			// path works, independent of anything the records say.
			t.core.noteInboundRequest()
		} else {
			t.core.noteReply(echo.Path.Seq, time.Now())
		}
		if len(echo.Payload) == 0 {
			// A bare Echo with no record (a peer keepalive, or someone else's
			// ping). Nothing to deliver.
			continue
		}
		return len(echo.Payload), echo.Path, nil
	}
}

// WriteRecord implements Transport: one record carried by one Echo Request.
func (t *icmpTransport) WriteRecord(rec []byte, to netip.AddrPort) error {
	ctx, cancel := context.WithTimeout(context.Background(), icmpReadSlack)
	defer cancel()
	if err := t.core.waitPace(ctx); err != nil {
		return err
	}
	err := t.platform.sendEcho(rec, to, t.core.nextID(), t.core.nextSeq())
	t.core.noteSendOutcome(rec, err)
	return err
}

// ReplyRecord implements Transport: mirror the observed path exactly.
func (t *icmpTransport) ReplyRecord(rec []byte, path PathID) error {
	ctx, cancel := context.WithTimeout(context.Background(), icmpReadSlack)
	defer cancel()
	if err := t.core.waitPace(ctx); err != nil {
		return err
	}
	err := t.platform.sendEchoReply(rec, path)
	t.core.noteSendOutcome(rec, err)
	return err
}

// Poke implements Poller. The poll is an Echo Request carrying whatever the
// session wants to say (normally a v2 PING); its reply is the only channel the
// downlink has.
func (t *icmpTransport) Poke(payload []byte, to netip.AddrPort) (uint16, error) {
	ctx, cancel := context.WithTimeout(context.Background(), icmpReadSlack)
	defer cancel()
	if err := t.core.waitPace(ctx); err != nil {
		return 0, err
	}
	seq := t.core.nextSeq()
	err := t.platform.sendEcho(payload, to, t.core.nextID(), seq)
	t.core.noteSendOutcome(payload, err)
	if err != nil {
		return seq, err
	}
	t.core.notePoll(seq)
	return seq, nil
}

// PollStats implements Poller.
func (t *icmpTransport) PollStats() (uint64, uint64) { return t.core.pollStats() }

// Probe implements Prober. It is best-effort: the kernel decides whether an
// Echo Request even reaches a raw socket, so a failure is reported as a plain
// error and repeated failures retire the capability rather than the tunnel.
func (t *icmpTransport) Probe(payload []byte, to netip.AddrPort) error {
	if !t.core.probeAvailable() {
		return fmt.Errorf("%w: reverse probe is unavailable", ErrTransportUnsupported)
	}
	ctx, cancel := context.WithTimeout(context.Background(), icmpReadSlack)
	defer cancel()
	if err := t.core.waitPace(ctx); err != nil {
		return err
	}
	// A reverse probe is an Echo Request TO the peer, and its answer will come
	// back as an Echo Reply we observe on the normal receive path. There is no
	// separate acknowledgement here, so success is reported by the caller.
	err := t.platform.sendEcho(payload, to, t.core.nextID(), t.core.nextSeq())
	t.core.noteProbeResult(err == nil)
	return err
}

// MaxRecordSize implements MaxRecordSizer and is the LIVE value: the automatic
// MTU search moves it, and the session re-reads it on every send.
func (t *icmpTransport) MaxRecordSize() int { return t.core.maxRecordSize() }

// MaxReceiveSize implements MaxReceiveSizer: the configure-time ceiling, which
// is fixed. It is NOT the live send budget — see mtuController.receiveCeiling.
// The session sizes its receive buffer and its Parse limit from this, so a peer
// emitting at its own ceiling is always accepted, whatever this end's outbound
// path happens to be doing.
func (t *icmpTransport) MaxReceiveSize() int { return t.core.receiveCeiling() }

// RecordAcked implements MTUFeedback.
func (t *icmpTransport) RecordAcked(size int) { t.core.recordAcked(size) }

// RecordLost implements MTUFeedback.
func (t *icmpTransport) RecordLost(size int) { t.core.recordLost(size) }

// RecordAuthenticated implements AuthenticatedFeedback: the session tells the
// carrier that a record verified, which is the only evidence that clears a
// blocked path.
func (t *icmpTransport) RecordAuthenticated() { t.core.noteAuthenticated() }

// CarrierState implements CarrierCondition.
func (t *icmpTransport) CarrierState() CarrierState { return t.core.carrierState() }

// RTOFloor implements CarrierCondition.
func (t *icmpTransport) RTOFloor() time.Duration { return t.core.rtoFloor() }

// LocalID implements Transport.
func (t *icmpTransport) LocalID() string { return t.platform.localLabel() }

// RemoteID implements Transport.
func (t *icmpTransport) RemoteID() string { return t.platform.remoteLabel() }

// Close implements Transport and is idempotent.
func (t *icmpTransport) Close() error {
	var err error
	t.closeOnce.Do(func() { err = t.platform.close() })
	return err
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

// newICMPClientTransport builds the client-side ICMP carrier for one peer.
//
// protectFD is only meaningful on Android; desktop callers pass nil. The peer's
// address determines the socket family — an IPv4 peer is reached over an IPv4
// socket, an IPv6 peer over IPv6. There is no configuration for this because
// there is no meaningful choice: the peer is where the packets go.
func newICMPClientTransport(prof ICMPProfile, peer netip.Addr, logger Logger, protectFD func(fd int) error) (Transport, error) {
	resolved, err := prof.resolve()
	if err != nil {
		return nil, err
	}
	if !peer.IsValid() {
		return nil, fmt.Errorf("%w: client icmp transport needs a peer address", ErrConfigRequired)
	}

	fam := familyV4
	if peer.Is6() && !peer.Is4In6() {
		fam = familyV6
	}

	ids, err := newPooledIDs(resolved.idSpec)
	if err != nil {
		return nil, err
	}
	core := newICMPCore(resolved, netip.AddrPortFrom(peer, 0), ids, logger)

	cfg := &icmpConfig{
		role:      icmpRoleClient,
		family:    fam,
		peer:      peer,
		core:      core,
		protectFD: protectFD,
	}
	cfg.bindV4 = fam == familyV4
	cfg.bindV6 = fam == familyV6

	platform, err := newPlatformICMPTransport(cfg)
	if err != nil {
		return nil, err
	}
	logger.Infof("[ICMP] carrier ready family=%s budget=%d peer=%s pace=%s mtu_mode=%s",
		fam, core.maxRecordSize(), peer, resolved.pace, resolved.mtuMode)
	return &icmpTransport{platform: platform, core: core}, nil
}

// newICMPServerTransport builds the server-side ICMP carrier. A server has no
// peer to follow, so it binds BOTH families and serves whichever arrives on
// either from one Transport.
func newICMPServerTransport(prof ICMPProfile, logger Logger) (Transport, error) {
	resolved, err := prof.resolve()
	if err != nil {
		return nil, err
	}
	ids, err := newPooledIDs(resolved.idSpec)
	if err != nil {
		return nil, err
	}
	core := newICMPCore(resolved, netip.AddrPort{}, ids, logger)

	cfg := &icmpConfig{
		role:   icmpRoleServer,
		family: familyAuto,
		core:   core,
	}
	cfg.bindV4 = true
	cfg.bindV6 = true

	platform, err := newPlatformICMPTransport(cfg)
	if err != nil {
		return nil, err
	}
	logger.Infof("[ICMP] carrier ready family=%s v4=%t v6=%t budget=%d pace=%s mtu_mode=%s",
		familyAuto, cfg.bindV4, cfg.bindV6, core.maxRecordSize(), resolved.pace, resolved.mtuMode)
	return &icmpTransport{platform: platform, core: core}, nil
}
