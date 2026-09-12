package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Shared test rig for the ICMP profile
//
// Everything in this file runs WITHOUT root. The platform seam (platformICMP)
// is replaced with an in-memory fake, so the entire shared carrier — pacing,
// id selection, health classification, the automatic MTU controller, the
// capability surface — is exercised on any machine. Only icmp_linux.go's
// socket code needs root, and it lives in icmp_linux_test.go behind a skip.
// ---------------------------------------------------------------------------

// captureLogger keeps every line so the three carrier-health signatures (the
// acceptance contract) can be asserted by substring.
type captureLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *captureLogger) record(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *captureLogger) Debugf(f string, a ...any) { l.record(f, a...) }
func (l *captureLogger) Infof(f string, a ...any)  { l.record(f, a...) }
func (l *captureLogger) Warnf(f string, a ...any)  { l.record(f, a...) }
func (l *captureLogger) Errorf(f string, a ...any) { l.record(f, a...) }

func (l *captureLogger) find(substr string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.lines {
		if strings.Contains(s, substr) {
			return s
		}
	}
	return ""
}

// fakeSentEcho is one request the carrier handed to the platform.
type fakeSentEcho struct {
	payload []byte
	to      netip.AddrPort
	ident   uint16
	seq     uint16
}

// fakePlatform is an in-memory platformICMP. It records what was sent and lets a
// test inject inbound messages and send failures.
type fakePlatform struct {
	mu       sync.Mutex
	requests []fakeSentEcho
	replies  []PathID
	sendErr  error
	closed   bool
	once     sync.Once

	incoming chan inboundEcho
}

func newFakePlatform() *fakePlatform {
	return &fakePlatform{incoming: make(chan inboundEcho, 64)}
}

func (p *fakePlatform) sendEcho(payload []byte, to netip.AddrPort, ident, seq uint16) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sendErr != nil {
		return p.sendErr
	}
	p.requests = append(p.requests, fakeSentEcho{
		payload: append([]byte(nil), payload...),
		to:      to, ident: ident, seq: seq,
	})
	return nil
}

func (p *fakePlatform) sendEchoReply(payload []byte, path PathID) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sendErr != nil {
		return p.sendErr
	}
	p.replies = append(p.replies, path)
	return nil
}

func (p *fakePlatform) readEcho(buf []byte) (inboundEcho, error) {
	echo, ok := <-p.incoming
	if !ok {
		return inboundEcho{}, ErrClosed
	}
	if len(echo.Payload) > len(buf) {
		return inboundEcho{}, fmt.Errorf("%w: record is %d bytes, buffer is %d",
			ErrRecordTooLarge, len(echo.Payload), len(buf))
	}
	// Mirror rawICMP.readEcho exactly: the returned payload aliases buf, because
	// that is the contract the record layer relies on (a real socket would not
	// hand out a fresh allocation per packet).
	n := copy(buf, echo.Payload)
	if n > 0 {
		echo.Payload = buf[:n]
	} else {
		echo.Payload = nil
	}
	return echo, nil
}

func (p *fakePlatform) localLabel() string  { return "fake-icmp" }
func (p *fakePlatform) remoteLabel() string { return "fake-peer" }

func (p *fakePlatform) close() error {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.mu.Unlock()
		close(p.incoming)
	})
	return nil
}

func (p *fakePlatform) setSendErr(err error) {
	p.mu.Lock()
	p.sendErr = err
	p.mu.Unlock()
}

func (p *fakePlatform) requestCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.requests)
}

func (p *fakePlatform) lastRequest() (fakeSentEcho, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.requests) == 0 {
		return fakeSentEcho{}, false
	}
	return p.requests[len(p.requests)-1], true
}

// testICMPPeer is an arbitrary valid peer address; the carrier never inspects
// it beyond choosing a family.
var testICMPPeer = netip.MustParseAddrPort("192.0.2.9:0")

// newTestICMPTransport builds the real icmpTransport over the fake platform.
// Every knob is set explicitly so the profile under test is the profile the
// assertions describe.
func newTestICMPTransport(t *testing.T, prof ICMPProfile, log Logger) (*icmpTransport, *fakePlatform) {
	t.Helper()
	resolved, err := prof.resolve()
	if err != nil {
		t.Fatalf("profile resolve: %v", err)
	}
	ids, err := newPooledIDs(resolved.idSpec)
	if err != nil {
		t.Fatalf("id pool: %v", err)
	}
	core := newICMPCore(resolved, testICMPPeer, ids, log)
	plat := newFakePlatform()
	return &icmpTransport{platform: plat, core: core}, plat
}

// ---------------------------------------------------------------------------
// Profile resolution
// ---------------------------------------------------------------------------

func TestICMPProfileDefaults(t *testing.T) {
	got, err := (ICMPProfile{}).resolve()
	if err != nil {
		t.Fatalf("the zero profile must resolve: %v", err)
	}
	if got.maxPayload != icmpDefaultMaxPayload {
		t.Fatalf("max_payload = %d, want %d", got.maxPayload, icmpDefaultMaxPayload)
	}
	if got.mtuMode != mtuProbe {
		t.Fatalf("mtu_mode = %v, want probe", got.mtuMode)
	}
	if got.mtuMin != icmpDefaultMTUMin || got.mtuStep != icmpDefaultMTUStep {
		t.Fatalf("mtu_min/step = %d/%d, want %d/%d",
			got.mtuMin, got.mtuStep, icmpDefaultMTUMin, icmpDefaultMTUStep)
	}
	if got.pace != time.Duration(icmpDefaultPaceMS)*time.Millisecond {
		t.Fatalf("pace = %v, want %dms", got.pace, icmpDefaultPaceMS)
	}
	if !got.probe {
		t.Fatal("probe must default to enabled")
	}
	if got.pollsInFlight != icmpDefaultPollsIF {
		t.Fatalf("polls_in_flight = %d, want %d", got.pollsInFlight, icmpDefaultPollsIF)
	}
	if got.idlePoll != time.Duration(icmpDefaultIdleMS)*time.Millisecond {
		t.Fatalf("idle_poll = %v", got.idlePoll)
	}
	if got.keepAlive != time.Duration(icmpDefaultKeepMS)*time.Millisecond {
		t.Fatalf("keepalive = %v", got.keepAlive)
	}
	if got.blockTimeout != icmpDefaultBlockTO {
		t.Fatalf("block_timeout = %v, want %v", got.blockTimeout, icmpDefaultBlockTO)
	}
	if got.idSpec != "" {
		t.Fatalf("id_range = %q, want empty (unrestricted)", got.idSpec)
	}
}

func TestICMPProfileAcceptsExplicitValues(t *testing.T) {
	probe := false
	got, err := (ICMPProfile{
		MaxPayload: 1400, MTUMode: "fixed", MTUMin: 600, MTUStep: 32,
		PaceMS: 7, IDRange: "1000-1999", Probe: &probe, PollsInFlight: 2,
		IdlePollMS: 250, KeepAliveMS: 5000, BlockTimeout: "30s",
	}).resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.maxPayload != 1400 || got.mtuMode != mtuFixed {
		t.Fatalf("max/mode = %d/%v", got.maxPayload, got.mtuMode)
	}
	if got.mtuMin != 600 || got.mtuStep != 32 {
		t.Fatalf("mtu_min/step = %d/%d", got.mtuMin, got.mtuStep)
	}
	if got.pace != 7*time.Millisecond || got.idSpec != "1000-1999" {
		t.Fatalf("pace/id_range = %v/%q", got.pace, got.idSpec)
	}
	if got.probe {
		t.Fatal("probe=false must be honoured")
	}
	if got.pollsInFlight != 2 || got.idlePoll != 250*time.Millisecond {
		t.Fatalf("polls/idle = %d/%v", got.pollsInFlight, got.idlePoll)
	}
	if got.keepAlive != 5*time.Second || got.blockTimeout != 30*time.Second {
		t.Fatalf("keepalive/block = %v/%v", got.keepAlive, got.blockTimeout)
	}
}

// TestICMPProfileRejectsInvalid is the "fail loudly at configuration time"
// contract: every rejection must name the field and the accepted range.
func TestICMPProfileRejectsInvalid(t *testing.T) {
	cases := []struct {
		name    string
		prof    ICMPProfile
		wantSub string
	}{
		{"max_payload below floor", ICMPProfile{MaxPayload: 100}, "icmp.max_payload"},
		// One family-independent ceiling now: the dual-stack safe one (IPv6's).
		// There is no `family` to widen it for, so 1453 is rejected for everyone
		// and 1452 is the largest accepted value.
		{"max_payload one over the ceiling", ICMPProfile{MaxPayload: 1453}, "icmp.max_payload"},
		{"max_payload at the ceiling", ICMPProfile{MaxPayload: 1452}, ""},
		{"mtu_mode", ICMPProfile{MTUMode: "maybe"}, "icmp.mtu_mode"},
		{"mtu_min below floor", ICMPProfile{MTUMin: 400}, "icmp.mtu_min"},
		{"mtu_min above max_payload", ICMPProfile{MaxPayload: 700, MTUMin: 800}, "icmp.mtu_min"},
		{"mtu_step zero is defaulted not rejected", ICMPProfile{MTUStep: 0}, ""},
		{"mtu_step too large", ICMPProfile{MaxPayload: 700, MTUStep: 900}, "icmp.mtu_step"},
		{"pace negative", ICMPProfile{PaceMS: -1}, "icmp.pace_ms"},
		{"id_range not a pair", ICMPProfile{IDRange: "5"}, "icmp.id_range"},
		{"id_range non numeric", ICMPProfile{IDRange: "a-b"}, "icmp.id_range"},
		{"id_range inverted", ICMPProfile{IDRange: "20-10"}, "icmp.id_range"},
		{"id_range zero low", ICMPProfile{IDRange: "0-10"}, "icmp.id_range"},
		{"id_range over max", ICMPProfile{IDRange: "1-65536"}, "icmp.id_range"},
		{"polls_in_flight", ICMPProfile{PollsInFlight: -1}, "icmp.polls_in_flight"},
		{"idle_poll_ms", ICMPProfile{IdlePollMS: -1}, "icmp.idle_poll_ms"},
		{"keepalive_ms", ICMPProfile{KeepAliveMS: -1}, "icmp.keepalive_ms"},
		{"block_timeout unparsable", ICMPProfile{BlockTimeout: "soon"}, "icmp.block_timeout"},
		{"block_timeout non positive", ICMPProfile{BlockTimeout: "0s"}, "icmp.block_timeout"},
		{"block_timeout negative", ICMPProfile{BlockTimeout: "-1s"}, "icmp.block_timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.prof.resolve()
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("expected acceptance, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected a rejection naming %q", tc.wantSub)
			}
			if !errors.Is(err, ErrConfigRequired) {
				t.Fatalf("error must chain ErrConfigRequired: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q must name %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestBudgetBoundsIsFamilyIndependent(t *testing.T) {
	// With no `family` knob, the single ceiling is the dual-stack safe one: IPv6's
	// 1452, since a server binds both families and a v4-only budget would make
	// the IPv6 half oversized.
	if lo, hi := budgetBounds(); lo != icmpMinPayload || hi != icmpV6MaxPayload {
		t.Fatalf("budget bounds = %d..%d, want %d..%d", lo, hi, icmpMinPayload, icmpV6MaxPayload)
	}
}

// ---------------------------------------------------------------------------
// Echo Identifier pool
// ---------------------------------------------------------------------------

func TestPooledIDsRangeIsRespectedAndCycles(t *testing.T) {
	ids, err := newPooledIDs("1000-1002")
	if err != nil {
		t.Fatalf("newPooledIDs: %v", err)
	}
	seen := map[uint16]int{}
	for i := 0; i < 30; i++ {
		id := ids.next()
		if id < 1000 || id > 1002 {
			t.Fatalf("id %d outside the configured range", id)
		}
		seen[id]++
	}
	if len(seen) != 3 {
		t.Fatalf("pool of 3 yielded %d distinct ids", len(seen))
	}
	for id, n := range seen {
		if n != 10 {
			t.Fatalf("id %d used %d times, want an even 10 (round robin)", id, n)
		}
	}
}

func TestPooledIDsUnrestrictedNeverPicksReservedValues(t *testing.T) {
	ids, err := newPooledIDs("")
	if err != nil {
		t.Fatalf("newPooledIDs: %v", err)
	}
	distinct := map[uint16]struct{}{}
	for i := 0; i < 200; i++ {
		id := ids.next()
		if id == 0 || id == 65535 {
			t.Fatalf("id %d is reserved (0 = unset, 65535 = never chosen)", id)
		}
		distinct[id] = struct{}{}
	}
	if len(distinct) < 150 {
		t.Fatalf("unrestricted ids are not spread: %d distinct out of 200", len(distinct))
	}
}

func TestValidateIDRangeRejectsBareNumber(t *testing.T) {
	if _, err := validateIDRange("1000"); err == nil {
		t.Fatal("a bare number must be rejected: it is not a range")
	}
	if got, err := validateIDRange("  1000-1999  "); err != nil || got != "1000-1999" {
		t.Fatalf("validateIDRange normalisation = (%q,%v)", got, err)
	}
	if got, err := validateIDRange(""); err != nil || got != "" {
		t.Fatalf("empty id_range = (%q,%v)", got, err)
	}
}

// ---------------------------------------------------------------------------
// Pacing
// ---------------------------------------------------------------------------

func TestPacerFirstSlotIsImmediate(t *testing.T) {
	p := newPacer(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	if err := p.wait(ctx); err != nil {
		t.Fatalf("first wait: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Millisecond {
		t.Fatalf("an idle pacer must release the first caller immediately, took %v", elapsed)
	}
}

func TestPacerHonoursContextCancellation(t *testing.T) {
	// A one-hour interval makes the second caller's wait deterministic: it can
	// only end when the context says so.
	p := newPacer(time.Hour)
	if err := p.wait(context.Background()); err != nil {
		t.Fatalf("first wait: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := p.wait(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second wait = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("the pacer ignored the context and slept %v", elapsed)
	}
}

// TestPacerCapsAccumulatedDebt pins the debt cap. Sequential callers each wait
// one interval and the cap never engages; the cap exists for a BURST of callers
// that all arrive at once, which must not translate into a stall that outlives
// the burst.
func TestPacerCapsAccumulatedDebt(t *testing.T) {
	const interval = 10 * time.Millisecond
	p := newPacer(interval)
	const callers = 4 * icmpPaceBurstFactor

	start := time.Now()
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			if err := p.wait(context.Background()); err != nil {
				t.Errorf("wait: %v", err)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	// Uncapped, the last of 16 callers would leave at slot 15, i.e. ~150ms.
	// Capped at burstFactor intervals, nothing should wait much past 40ms.
	if limit := time.Duration(2*icmpPaceBurstFactor) * interval; elapsed > limit {
		t.Fatalf("a burst of %d callers took %v, want it capped near %v",
			callers, elapsed, time.Duration(icmpPaceBurstFactor)*interval)
	}
}

// TestPacerSpacesSequentialCallers is the other half of the contract: the
// pacer must actually slow a run of callers down, or a flood of Echo Requests
// would exhaust the host's global ICMP allowance.
func TestPacerSpacesSequentialCallers(t *testing.T) {
	const interval = 5 * time.Millisecond
	p := newPacer(interval)
	const callers = 6
	start := time.Now()
	for i := 0; i < callers; i++ {
		if err := p.wait(context.Background()); err != nil {
			t.Fatalf("wait %d: %v", i, err)
		}
	}
	elapsed := time.Since(start)
	// The first slot is free, so (callers-1) intervals is the floor.
	if min := time.Duration(callers-1) * interval; elapsed < min/2 {
		t.Fatalf("six sequential calls took only %v; the pacer is not spacing", elapsed)
	}
}

// ---------------------------------------------------------------------------
// Carrier health classification
// ---------------------------------------------------------------------------

// testClock is a manually advanced clock, injected via carrierMonitor.now so
// window rolls are deterministic instead of wall-clock dependent.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Unix(1_700_000_000, 0)}
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestMonitor(log Logger) (*carrierMonitor, *testClock) {
	clk := newTestClock()
	mon := newCarrierMonitor(testICMPPeer, 20*time.Millisecond, icmpDefaultBlockTO, log)
	mon.now = clk.now
	mon.bucketAt = clk.now()
	return mon, clk
}

func TestCarrierMonitorStartsInit(t *testing.T) {
	mon, _ := newTestMonitor(Nop{})
	if got := mon.State(); got != CarrierInit {
		t.Fatalf("initial state = %v, want init", got)
	}
	if got := mon.RTOFloor(); got != mon.baseFloor {
		t.Fatalf("init RTO floor = %v, want the base floor %v", got, mon.baseFloor)
	}
}

func TestCarrierMonitorAuthenticatedTrafficIsHealthy(t *testing.T) {
	mon, _ := newTestMonitor(Nop{})
	mon.noteAuthenticated()
	if got := mon.State(); got != CarrierUp {
		t.Fatalf("state after one authenticated record = %v, want up", got)
	}
}

func TestCarrierMonitorPollsWithoutRepliesBlock(t *testing.T) {
	mon, _ := newTestMonitor(Nop{})
	for i := 0; i < carrierMinPolls; i++ {
		mon.notePoll()
	}
	if got := mon.State(); got != CarrierBlocked {
		t.Fatalf("state after %d unanswered polls = %v, want blocked", carrierMinPolls, got)
	}
	if got := mon.RTOFloor(); got != icmpDefaultBlockTO {
		t.Fatalf("blocked RTO floor = %v, want the block timeout %v", got, icmpDefaultBlockTO)
	}
}

func TestCarrierMonitorFewRepliesThrottle(t *testing.T) {
	mon, _ := newTestMonitor(Nop{})
	// Interleave so the "no replies at all" rule never fires first: 5 polls
	// with 2 replies is 60% loss, which is throttling, not blockage.
	for i := 0; i < 2; i++ {
		mon.notePoll()
		mon.noteReply(50 * time.Millisecond)
	}
	for i := 0; i < 3; i++ {
		mon.notePoll()
	}
	if got := mon.State(); got != CarrierThrottled {
		t.Fatalf("state = %v, want throttled", got)
	}
	if want := 2 * mon.baseFloor; mon.RTOFloor() != want {
		t.Fatalf("throttled RTO floor = %v, want %v", mon.RTOFloor(), want)
	}
}

func TestCarrierMonitorAuthenticatedRecordClearsBlock(t *testing.T) {
	mon, _ := newTestMonitor(Nop{})
	for i := 0; i < carrierMinPolls; i++ {
		mon.notePoll()
	}
	if mon.State() != CarrierBlocked {
		t.Fatal("precondition: the monitor must be blocked")
	}
	mon.noteAuthenticated()
	if got := mon.State(); got != CarrierUp {
		t.Fatalf("state after an authenticated record = %v, want up", got)
	}
}

func TestCarrierMonitorSocketErrorForcesBlock(t *testing.T) {
	mon, _ := newTestMonitor(Nop{})
	mon.noteSocketError()
	if got := mon.State(); got != CarrierBlocked {
		t.Fatalf("state after a fatal socket error = %v, want blocked", got)
	}
	// A forced block is sticky until authenticated traffic returns.
	mon.notePoll()
	if got := mon.State(); got != CarrierBlocked {
		t.Fatalf("state = %v, want the forced block to persist", got)
	}
	mon.noteAuthenticated()
	if got := mon.State(); got != CarrierUp {
		t.Fatalf("state after authenticated traffic = %v, want up", got)
	}
}

func TestCarrierMonitorRTTBalloonThrottles(t *testing.T) {
	mon, _ := newTestMonitor(Nop{})
	// Establish a healthy baseline with a fast minimum RTT.
	mon.noteReply(10 * time.Millisecond)
	mon.noteAuthenticated()
	if mon.State() != CarrierUp {
		t.Fatal("precondition: a fast, authenticated path must be up")
	}
	// Now the RTT EWMA balloons past 3x the best: replies still arrive, so the
	// path is not dead, but it is clearly degraded.
	for i := 0; i < 20; i++ {
		mon.noteReply(200 * time.Millisecond)
	}
	if got := mon.State(); got != CarrierThrottled {
		t.Fatalf("state with a ballooned RTT = %v, want throttled", got)
	}
}

// TestCarrierMonitorLogSignatures pins the three acceptance signatures, which
// are how an operator tells a healthy path from a rate-limited one from a dead
// one without guessing.
func TestCarrierMonitorLogSignatures(t *testing.T) {
	log := &captureLogger{}

	mon, _ := newTestMonitor(log)
	mon.noteAuthenticated()
	if line := log.find("[ICMP] path healthy"); line == "" {
		t.Fatalf("missing the healthy signature; lines=%v", log.lines)
	}

	throttled, _ := newTestMonitor(log)
	for i := 0; i < 2; i++ {
		throttled.notePoll()
		throttled.noteReply(50 * time.Millisecond)
	}
	for i := 0; i < 3; i++ {
		throttled.notePoll()
	}
	if line := log.find("[ICMP] carrier throttled"); line == "" {
		t.Fatalf("missing the throttled signature; lines=%v", log.lines)
	} else if !strings.Contains(line, "rate limit") {
		t.Fatalf("throttled line must name a rate limit as the likely cause: %q", line)
	}

	blocked, _ := newTestMonitor(log)
	for i := 0; i < carrierMinPolls; i++ {
		blocked.notePoll()
	}
	line := log.find("[ICMP] carrier blocked")
	if line == "" {
		t.Fatalf("missing the blocked signature; lines=%v", log.lines)
	}
	if !strings.Contains(line, "hint=allow ICMP echo request+reply in BOTH directions") {
		t.Fatalf("blocked line must carry the actionable hint: %q", line)
	}
	if !strings.Contains(line, "replies=0") {
		t.Fatalf("blocked line must state replies=0: %q", line)
	}
}

func TestCarrierMonitorWindowRolls(t *testing.T) {
	mon, clk := newTestMonitor(Nop{})
	// Two polls in the first bucket is below the evidence threshold.
	mon.notePoll()
	mon.notePoll()
	if mon.State() != CarrierInit {
		t.Fatalf("state = %v; two polls are not enough evidence", mon.State())
	}
	// Roll the window: the counts slide into "previous" and the fresh bucket
	// starts empty, so the sliding sum still matters.
	clk.advance(carrierBucketLen)
	mon.notePoll()
	mon.notePoll()
	mon.notePoll()
	if got := mon.State(); got != CarrierBlocked {
		t.Fatalf("state = %v, want blocked (5 polls across the sliding window)", got)
	}
}

// ---------------------------------------------------------------------------
// Automatic MTU controller
// ---------------------------------------------------------------------------

func TestMTUControllerFixedModeNeverMoves(t *testing.T) {
	c := newMTUController(mtuFixed, 1472, 548, 100)
	if got := c.budget(); got != 1472 {
		t.Fatalf("fixed budget = %d, want the ceiling 1472", got)
	}
	for i := 0; i < 100; i++ {
		c.recordAcked(1472)
	}
	c.recordLost(1472)
	c.adoptPathBudget(900)
	c.shrinkForOversize(1472)
	if got := c.budget(); got != 1472 {
		t.Fatalf("fixed budget moved to %d", got)
	}
}

func TestMTUControllerStartsAtTheConservativeDefault(t *testing.T) {
	// 1200 is below the IPv6 guaranteed floor, so the default never fragments.
	c := newMTUController(mtuInBand, 1472, 548, 100)
	if got := c.budget(); got != icmpDefaultMaxPayload {
		t.Fatalf("adaptive start = %d, want %d", got, icmpDefaultMaxPayload)
	}
}

func TestMTUControllerGrowsAfterConsecutiveFullBudgetAcks(t *testing.T) {
	c := newMTUController(mtuInBand, 1472, 548, 100)
	for i := 0; i < mtuAcksToGrow; i++ {
		// A record smaller than the current budget is not evidence about the
		// ceiling and must reset the run.
		c.recordAcked(c.budget() - 1)
	}
	if got := c.budget(); got != icmpDefaultMaxPayload {
		t.Fatalf("a sub-budget ack grew the budget to %d", got)
	}
	for i := 0; i < mtuAcksToGrow; i++ {
		c.recordAcked(c.budget())
	}
	if got := c.budget(); got != icmpDefaultMaxPayload+100 {
		t.Fatalf("budget after %d full-budget acks = %d, want 1300", mtuAcksToGrow, got)
	}
}

func TestMTUControllerHalvesTheGapNearTheCeiling(t *testing.T) {
	c := newMTUController(mtuInBand, 1250, 548, 100)
	if got := c.budget(); got != 1200 {
		t.Fatalf("start = %d, want 1200", got)
	}
	for i := 0; i < mtuAcksToGrow; i++ {
		c.recordAcked(1200)
	}
	// 50 bytes remain and the step is 100, so the step halves: the search
	// converges on the ceiling geometrically instead of overshooting it.
	if got := c.budget(); got != 1225 {
		t.Fatalf("budget = %d, want 1225 (half the remaining gap)", got)
	}
	// Repeated rounds must actually reach the ceiling, never stop short.
	for round := 0; round < 20 && c.budget() < 1250; round++ {
		for i := 0; i < mtuAcksToGrow; i++ {
			c.recordAcked(c.budget())
			if c.budget() == 1250 {
				break
			}
		}
	}
	if got := c.budget(); got != 1250 {
		t.Fatalf("budget = %d, want the search to converge on the ceiling 1250", got)
	}
}

func TestMTUControllerAlreadyAtCeilingNeverGrows(t *testing.T) {
	c := newMTUController(mtuInBand, 1200, 548, 100)
	for i := 0; i < 5*mtuAcksToGrow; i++ {
		c.recordAcked(1200)
	}
	if got := c.budget(); got != 1200 {
		t.Fatalf("budget = %d, want the ceiling 1200", got)
	}
}

func TestMTUControllerShrinksAfterRepeatedLoss(t *testing.T) {
	c := newMTUController(mtuInBand, 1472, 548, 100)
	for i := 0; i < mtuLossesToShrink-1; i++ {
		c.recordLost(c.budget())
	}
	if got := c.budget(); got != 1200 {
		t.Fatalf("a single loss must not shrink the budget; got %d", got)
	}
	c.recordLost(c.budget())
	if got := c.budget(); got != 1100 {
		t.Fatalf("budget after %d losses = %d, want 1100", mtuLossesToShrink, got)
	}
}

func TestMTUControllerNeverShrinksBelowTheFloor(t *testing.T) {
	c := newMTUController(mtuInBand, 600, 550, 100)
	if got := c.budget(); got != 600 {
		t.Fatalf("start = %d", got)
	}
	for i := 0; i < 20*mtuLossesToShrink; i++ {
		c.recordLost(600)
	}
	if got := c.budget(); got != 550 {
		t.Fatalf("budget = %d, want the floor 550", got)
	}
}

func TestMTUControllerAdoptsPathBudgetDownOnly(t *testing.T) {
	c := newMTUController(mtuInBand, 1472, 548, 100)
	c.adoptPathBudget(1000)
	if got := c.budget(); got != 1000 {
		t.Fatalf("budget after a frag-needed report = %d, want 1000", got)
	}
	// Such a report is evidence that something was too big, never that a
	// larger size is possible.
	c.adoptPathBudget(1400)
	if got := c.budget(); got != 1000 {
		t.Fatalf("a frag-needed report must only move the budget down; got %d", got)
	}
	c.adoptPathBudget(100)
	if got := c.budget(); got != 548 {
		t.Fatalf("budget = %d, want it clamped to the floor 548", got)
	}
}

func TestMTUControllerAdoptProbedOnlyInProbeMode(t *testing.T) {
	inBand := newMTUController(mtuInBand, 1472, 548, 100)
	inBand.adoptProbed(1400)
	if got := inBand.budget(); got != icmpDefaultMaxPayload {
		t.Fatalf("a probe result must be ignored outside probe mode; got %d", got)
	}

	probe := newMTUController(mtuProbe, 1472, 548, 100)
	probe.adoptProbed(1400)
	if got := probe.budget(); got != 1400 {
		t.Fatalf("probe budget = %d, want 1400", got)
	}
	probe.adoptProbed(99999)
	if got := probe.budget(); got != 1472 {
		t.Fatalf("probe budget = %d, want the ceiling 1472", got)
	}
	probe.adoptProbed(1)
	if got := probe.budget(); got != 548 {
		t.Fatalf("probe budget = %d, want the floor 548", got)
	}
}

func TestMTUControllerShrinkForOversizeIsImmediate(t *testing.T) {
	c := newMTUController(mtuInBand, 1472, 548, 100)
	// The kernel refused exactly this size, which is as precise as a
	// frag-needed message: step down at once, not after three losses.
	c.shrinkForOversize(1200)
	if got := c.budget(); got != 1100 {
		t.Fatalf("budget = %d, want 1100", got)
	}
}

func TestMTUControllerSuspendsWhileCarrierIsUnhealthy(t *testing.T) {
	c := newMTUController(mtuInBand, 1472, 548, 100)
	c.setSuspended(true)
	for i := 0; i < 3*mtuAcksToGrow; i++ {
		c.recordAcked(c.budget())
	}
	for i := 0; i < 3*mtuLossesToShrink; i++ {
		c.recordLost(c.budget())
	}
	c.shrinkForOversize(c.budget())
	if got := c.budget(); got != icmpDefaultMaxPayload {
		t.Fatalf("a suspended controller moved to %d", got)
	}
	c.setSuspended(false)
	for i := 0; i < mtuAcksToGrow; i++ {
		c.recordAcked(c.budget())
	}
	if got := c.budget(); got != icmpDefaultMaxPayload+100 {
		t.Fatalf("budget after resuming = %d, want 1300", got)
	}
}

// TestMTUControllerReceiveCeilingIsTheFixedConfiguredMaximum is the asymmetry
// that keeps a tunnel alive in both directions: the send budget adapts, the
// receive ceiling never does.
func TestMTUControllerReceiveCeilingIsTheFixedConfiguredMaximum(t *testing.T) {
	c := newMTUController(mtuInBand, 1472, 548, 100)
	if got := c.receiveCeiling(); got != 1472 {
		t.Fatalf("receive ceiling = %d, want 1472", got)
	}
	c.shrinkForOversize(1200)
	c.adoptPathBudget(700)
	if got := c.budget(); got != 700 {
		t.Fatalf("send budget = %d, want 700", got)
	}
	if got := c.receiveCeiling(); got != 1472 {
		t.Fatalf("receive ceiling moved to %d with the send budget; it must stay 1472", got)
	}
}

// ---------------------------------------------------------------------------
// The built-in discard:// sink
// ---------------------------------------------------------------------------

func frameLengthRequest(t *testing.T, want int) []byte {
	t.Helper()
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(want))
	framed, err := EncodeMessage(n[:])
	if err != nil {
		t.Fatalf("EncodeMessage: %v", err)
	}
	return framed
}

func TestDiscardSinkDropsUplinkProbes(t *testing.T) {
	s := newDiscardSink()
	defer s.Close()
	framed, err := EncodeMessage([]byte("this is the uplink probe payload"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.Write(framed)
	if err != nil || n != len(framed) {
		t.Fatalf("Write = (%d,%v), want (%d,nil)", n, err, len(framed))
	}
	st := s.stats()
	if st.Dropped != 1 || st.Fills != 0 || st.Queued != 0 {
		t.Fatalf("stats = %+v, want one drop and nothing queued", st)
	}
}

func TestDiscardSinkAnswersLengthRequestsWithFiller(t *testing.T) {
	s := newDiscardSink()
	defer s.Close()
	const want = 900
	if _, err := s.Write(frameLengthRequest(t, want)); err != nil {
		t.Fatal(err)
	}
	if st := s.stats(); st.Fills != 1 || st.Queued != want {
		t.Fatalf("stats = %+v, want one fill of %d", st, want)
	}
	buf := make([]byte, want+16)
	n, err := s.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != want {
		t.Fatalf("Read returned %d bytes, want %d", n, want)
	}
	for i, b := range buf[:n] {
		if b != 0 {
			t.Fatalf("filler byte %d = %#x, want zeroed filler", i, b)
		}
	}
	if st := s.stats(); st.Queued != 0 {
		t.Fatalf("queue not drained: %+v", st)
	}
}

func TestDiscardSinkReassemblesASplitLengthRequest(t *testing.T) {
	s := newDiscardSink()
	defer s.Close()
	framed := frameLengthRequest(t, 300)
	if _, err := s.Write(framed[:3]); err != nil {
		t.Fatal(err)
	}
	if st := s.stats(); st.Queued != 0 {
		t.Fatalf("a partial frame must not be acted on: %+v", st)
	}
	if _, err := s.Write(framed[3:]); err != nil {
		t.Fatal(err)
	}
	if st := s.stats(); st.Queued != 300 || st.Fills != 1 {
		t.Fatalf("stats = %+v, want a single 300-byte fill", st)
	}
}

func TestDiscardSinkRejectsZeroAndCapsOversizeFills(t *testing.T) {
	s := newDiscardSink()
	defer s.Close()
	if _, err := s.Write(frameLengthRequest(t, 0)); err != nil {
		t.Fatal(err)
	}
	if st := s.stats(); st.Dropped != 1 {
		t.Fatalf("a zero-length request must be dropped: %+v", st)
	}
	// An over-cap request is clamped, never honoured verbatim: a bogus client
	// must not be able to make the server allocate on demand.
	if _, err := s.Write(frameLengthRequest(t, discardMaxFill*4)); err != nil {
		t.Fatal(err)
	}
	if st := s.stats(); st.Queued != discardMaxFill {
		t.Fatalf("oversize request queued %d, want it clamped to %d", st.Queued, discardMaxFill)
	}
}

func TestDiscardSinkRefusesToQueueBeyondItsBound(t *testing.T) {
	s := newDiscardSink()
	defer s.Close()
	frame := frameLengthRequest(t, discardMaxFill)
	for i := 0; i < discardMaxQueued/discardMaxFill; i++ {
		if _, err := s.Write(frame); err != nil {
			t.Fatal(err)
		}
	}
	if st := s.stats(); st.Queued != discardMaxQueued {
		t.Fatalf("queued %d, want the bound %d", st.Queued, discardMaxQueued)
	}
	if _, err := s.Write(frame); err != nil {
		t.Fatal(err)
	}
	if st := s.stats(); st.Queued != discardMaxQueued || st.Dropped == 0 {
		t.Fatalf("the sink must drop rather than grow: %+v", st)
	}
}

func TestDiscardSinkReadDeadline(t *testing.T) {
	s := newDiscardSink()
	defer s.Close()
	if err := s.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read = %v, want os.ErrDeadlineExceeded", err)
	}
}

func TestDiscardSinkCloseUnblocksReadWithEOF(t *testing.T) {
	s := newDiscardSink()
	done := make(chan error, 1)
	go func() {
		_, err := s.Read(make([]byte, 8))
		done <- err
	}()
	// Give the reader a moment to park on the wake channel, then close.
	time.Sleep(20 * time.Millisecond)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		// The sink's documented contract is io.EOF for a closed sink, because
		// the session's upstream pump treats any read error as "target is done".
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Read after Close = %v, want io.EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Read")
	}
}

func TestDiscardSinkLabelsAndNetworkName(t *testing.T) {
	s := newDiscardSink()
	defer s.Close()
	if s.LocalAddr().Network() != "discard" || s.RemoteAddr().Network() != "discard" {
		t.Fatalf("addresses = %v/%v, want the discard label", s.LocalAddr(), s.RemoteAddr())
	}
	if !isDiscardNetwork("discard") {
		t.Fatal("isDiscardNetwork must recognise the sink")
	}
	if isDiscardNetwork("tcp") || isDiscardNetwork("") {
		t.Fatal("isDiscardNetwork must not claim a real network")
	}
}

func TestParseTargetNetworkAndAddrRecognisesDiscard(t *testing.T) {
	cases := []struct {
		in            string
		wantNet, want string
	}{
		{"discard://", "discard", ""},
		{"discard://anything", "discard", "anything"},
		{"DISCARD://x", "discard", "x"},
		{"tcp://host:22", "tcp", "host:22"},
		{"udp://host:53", "udp", "host:53"},
	}
	for _, tc := range cases {
		net_, addr := ParseTargetNetworkAndAddr(tc.in)
		if net_ != tc.wantNet || addr != tc.want {
			t.Fatalf("ParseTargetNetworkAndAddr(%q) = (%q,%q), want (%q,%q)",
				tc.in, net_, addr, tc.wantNet, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// icmpTransport behaviour (no sockets)
// ---------------------------------------------------------------------------

func TestICMPTransportPublishesLiveBudgetAndFixedReceiveCeiling(t *testing.T) {
	tr, _ := newTestICMPTransport(t, ICMPProfile{
		MaxPayload: 1452, MTUMode: "auto", PaceMS: 1,
	}, Nop{})

	if got := tr.MaxRecordSize(); got != icmpDefaultMaxPayload {
		t.Fatalf("initial send budget = %d, want %d", got, icmpDefaultMaxPayload)
	}
	if got := tr.MaxReceiveSize(); got != 1452 {
		t.Fatalf("receive ceiling = %d, want the configured 1452", got)
	}
	for i := 0; i < mtuAcksToGrow; i++ {
		tr.RecordAcked(tr.MaxRecordSize())
	}
	if got := tr.MaxRecordSize(); got != icmpDefaultMaxPayload+100 {
		t.Fatalf("send budget after acks = %d, want 1300", got)
	}
	if got := tr.MaxReceiveSize(); got != 1452 {
		t.Fatalf("receive ceiling followed the send budget to %d; it must stay 1452", got)
	}
}

func TestICMPTransportAdoptsAnInbandPathBudget(t *testing.T) {
	tr, plat := newTestICMPTransport(t, ICMPProfile{
		MaxPayload: 1452, MTUMode: "auto", PaceMS: 1,
	}, Nop{})

	// A frag-needed report carries no record; the reader must adopt it and keep
	// waiting rather than hand back an empty payload.
	plat.incoming <- inboundEcho{PathBudget: 1000}
	plat.incoming <- inboundEcho{Payload: []byte("a record"), Path: PathID{Seq: 7}}

	buf := make([]byte, 1472)
	n, _, err := tr.ReadRecord(buf)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if string(buf[:n]) != "a record" {
		t.Fatalf("payload = %q, want the record after the frag-needed signal", buf[:n])
	}
	if got := tr.MaxRecordSize(); got != 1000 {
		t.Fatalf("send budget = %d, want the adopted path budget 1000", got)
	}
}

func TestICMPTransportSkipsBareEchoesButCountsThem(t *testing.T) {
	tr, plat := newTestICMPTransport(t, ICMPProfile{
		MaxPayload: 1200, MTUMode: "auto", PaceMS: 1,
	}, Nop{})

	// An inbound Echo Request with no record is the peer's keepalive: nothing to
	// deliver, but its arrival is proof the path works.
	plat.incoming <- inboundEcho{IsRequest: true, Path: PathID{Seq: 1}}
	plat.incoming <- inboundEcho{Payload: []byte("data"), Path: PathID{Seq: 2}}

	buf := make([]byte, 1200)
	n, _, err := tr.ReadRecord(buf)
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if string(buf[:n]) != "data" {
		t.Fatalf("payload = %q, want the real record", buf[:n])
	}
	if got := tr.CarrierState(); got != CarrierUp {
		t.Fatalf("carrier state = %v, want up after an authenticated inbound record", got)
	}
}

func TestICMPTransportOversizeSendShrinksTheBudget(t *testing.T) {
	tr, plat := newTestICMPTransport(t, ICMPProfile{
		MaxPayload: 1452, MTUMode: "auto", PaceMS: 1,
	}, Nop{})

	plat.setSendErr(fmt.Errorf("%w: the kernel refused it", ErrRecordTooLarge))
	err := tr.WriteRecord(make([]byte, 1200), testICMPPeer)
	if !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("WriteRecord = %v, want ErrRecordTooLarge", err)
	}
	if got := tr.MaxRecordSize(); got != 1100 {
		t.Fatalf("send budget = %d, want an immediate step down to 1100", got)
	}
}

func TestICMPTransportPokeAndPollStatsAttributeReplies(t *testing.T) {
	tr, plat := newTestICMPTransport(t, ICMPProfile{
		MaxPayload: 1200, MTUMode: "auto", PaceMS: 1,
	}, Nop{})

	seq, err := tr.Poke([]byte("ping"), testICMPPeer)
	if err != nil {
		t.Fatalf("Poke: %v", err)
	}
	if seq == 0 {
		t.Fatal("Poke must allocate a non-zero carrier sequence number")
	}
	if polls, replies := tr.PollStats(); polls != 1 || replies != 0 {
		t.Fatalf("PollStats = (%d,%d), want (1,0)", polls, replies)
	}
	// A reply whose sequence we never sent must not be counted: miscounting it
	// would corrupt the loss estimate.
	plat.incoming <- inboundEcho{Payload: []byte("stray"), Path: PathID{Seq: seq + 1000}}
	plat.incoming <- inboundEcho{Payload: []byte("pong"), Path: PathID{Seq: seq}}
	buf := make([]byte, 1200)
	if _, _, err := tr.ReadRecord(buf); err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if _, _, err := tr.ReadRecord(buf); err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if polls, replies := tr.PollStats(); polls != 1 || replies != 1 {
		t.Fatalf("PollStats = (%d,%d), want (1,1)", polls, replies)
	}
}

// TestICMPTransportForwardsBothMTUFeedbackDirections pins the delegation from
// the session-facing interface onto the shared controller.
func TestICMPTransportForwardsBothMTUFeedbackDirections(t *testing.T) {
	tr, _ := newTestICMPTransport(t, ICMPProfile{
		MaxPayload: 1452, MTUMode: "auto", PaceMS: 1,
	}, Nop{})

	// Grow on acknowledged full-budget records...
	for i := 0; i < mtuAcksToGrow; i++ {
		tr.RecordAcked(tr.MaxRecordSize())
	}
	if got := tr.MaxRecordSize(); got != icmpDefaultMaxPayload+100 {
		t.Fatalf("send budget after acks = %d, want 1300", got)
	}
	// ...and step back down on repeated loss.
	for i := 0; i < mtuLossesToShrink; i++ {
		tr.RecordLost(tr.MaxRecordSize())
	}
	if got := tr.MaxRecordSize(); got != icmpDefaultMaxPayload {
		t.Fatalf("send budget after losses = %d, want a step back to %d", got, icmpDefaultMaxPayload)
	}
}

func TestICMPTransportRetiresTheReverseProbeAfterRepeatedFailure(t *testing.T) {
	log := &captureLogger{}
	tr, plat := newTestICMPTransport(t, ICMPProfile{
		MaxPayload: 1200, MTUMode: "auto", PaceMS: 1,
	}, log)
	plat.setSendErr(errors.New("send refused"))

	for i := 0; i < 3; i++ {
		if err := tr.Probe([]byte("p"), testICMPPeer); err == nil {
			t.Fatalf("probe %d must report the send failure", i)
		}
	}
	if line := log.find("reverse probe disabled"); line == "" {
		t.Fatalf("retiring the probe must be logged; lines=%v", log.lines)
	}
	err := tr.Probe([]byte("p"), testICMPPeer)
	if !errors.Is(err, ErrTransportUnsupported) {
		t.Fatalf("Probe after retirement = %v, want ErrTransportUnsupported", err)
	}
}

func TestICMPTransportProbeCanBeDisabledByProfile(t *testing.T) {
	off := false
	tr, _ := newTestICMPTransport(t, ICMPProfile{
		MaxPayload: 1200, MTUMode: "auto", PaceMS: 1, Probe: &off,
	}, Nop{})
	if err := tr.Probe([]byte("p"), testICMPPeer); !errors.Is(err, ErrTransportUnsupported) {
		t.Fatalf("Probe with probe=false = %v, want ErrTransportUnsupported", err)
	}
}

func TestICMPTransportCarrierConditionTracksTheMonitor(t *testing.T) {
	tr, _ := newTestICMPTransport(t, ICMPProfile{
		MaxPayload: 1200, MTUMode: "auto", PaceMS: 1,
	}, Nop{})

	base := tr.RTOFloor()
	if base <= 0 {
		t.Fatalf("base RTO floor = %v, want a positive value", base)
	}
	tr.core.noteSocketError()
	if got := tr.CarrierState(); got != CarrierBlocked {
		t.Fatalf("carrier state = %v, want blocked", got)
	}
	if got := tr.RTOFloor(); got != icmpDefaultBlockTO {
		t.Fatalf("blocked RTO floor = %v, want %v", got, icmpDefaultBlockTO)
	}
	// An authenticated record is the one event that clears the block, and the
	// session layer is the only thing that can report it.
	tr.RecordAuthenticated()
	if got := tr.CarrierState(); got != CarrierUp {
		t.Fatalf("carrier state after authentication = %v, want up", got)
	}
	if got := tr.RTOFloor(); got != base {
		t.Fatalf("RTO floor after recovery = %v, want %v", got, base)
	}
}

func TestICMPTransportReplyAndEchoMirrorTheObservedPath(t *testing.T) {
	tr, plat := newTestICMPTransport(t, ICMPProfile{
		MaxPayload: 1200, MTUMode: "auto", PaceMS: 1,
	}, Nop{})

	path := PathID{Peer: testICMPPeer, Ident: 0x4242, Seq: 0x0101}
	if err := tr.ReplyRecord([]byte("pong"), path); err != nil {
		t.Fatalf("ReplyRecord: %v", err)
	}
	plat.mu.Lock()
	defer plat.mu.Unlock()
	if len(plat.replies) != 1 {
		t.Fatalf("recorded replies = %d, want 1", len(plat.replies))
	}
	if plat.replies[0] != path {
		t.Fatalf("reply path = %+v, want the observed path mirrored verbatim %+v", plat.replies[0], path)
	}
}

func TestICMPTransportSendsWithAFreshIdentifierAndSequence(t *testing.T) {
	tr, plat := newTestICMPTransport(t, ICMPProfile{
		MaxPayload: 1200, MTUMode: "auto", PaceMS: 1, IDRange: "700-709",
	}, Nop{})
	for i := 0; i < 3; i++ {
		if err := tr.WriteRecord([]byte("x"), testICMPPeer); err != nil {
			t.Fatal(err)
		}
	}
	plat.mu.Lock()
	defer plat.mu.Unlock()
	if len(plat.requests) != 3 {
		t.Fatalf("requests = %d, want 3", len(plat.requests))
	}
	seen := map[uint16]bool{}
	var lastSeq uint16
	for i, req := range plat.requests {
		if req.ident < 700 || req.ident > 709 {
			t.Fatalf("request %d ident = %d, outside the configured pool", i, req.ident)
		}
		if req.seq == 0 {
			t.Fatalf("request %d has sequence 0, which is reserved", i)
		}
		if i > 0 && req.seq == lastSeq {
			t.Fatalf("request %d reused sequence %d", i, req.seq)
		}
		lastSeq = req.seq
		seen[req.ident] = true
	}
	if len(seen) != 3 {
		t.Fatalf("ids did not spread across the pool: %v", seen)
	}
}

func TestICMPTransportCloseIsIdempotentAndUnblocksReads(t *testing.T) {
	tr, plat := newTestICMPTransport(t, ICMPProfile{
		MaxPayload: 1200, MTUMode: "auto", PaceMS: 1,
	}, Nop{})

	done := make(chan error, 1)
	go func() {
		_, _, err := tr.ReadRecord(make([]byte, 1200))
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a pending ReadRecord must fail once the carrier closes")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock ReadRecord")
	}
	plat.mu.Lock()
	closed := plat.closed
	plat.mu.Unlock()
	if !closed {
		t.Fatal("Close must reach the platform")
	}
	if tr.LocalID() != "fake-icmp" || tr.RemoteID() != "fake-peer" {
		t.Fatalf("labels = %q/%q", tr.LocalID(), tr.RemoteID())
	}
}

// ---------------------------------------------------------------------------
// Construction and the explicit platform refusal
// ---------------------------------------------------------------------------

func TestNewICMPClientTransportValidatesBeforeTouchingSockets(t *testing.T) {
	cases := []struct {
		name    string
		prof    ICMPProfile
		peer    netip.Addr
		wantSub string
	}{
		{"bad profile", ICMPProfile{MaxPayload: 9999}, netip.MustParseAddr("192.0.2.1"), "icmp.max_payload"},
		{"bad id range", ICMPProfile{IDRange: "nope"}, netip.MustParseAddr("192.0.2.1"), "icmp.id_range"},
		{"missing peer", ICMPProfile{}, netip.Addr{}, "needs a peer address"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newICMPClientTransport(tc.prof, tc.peer, Nop{}, nil)
			if err == nil {
				t.Fatal("expected a configuration-time failure")
			}
			if !errors.Is(err, ErrConfigRequired) {
				t.Fatalf("error must chain ErrConfigRequired: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q must mention %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestNewICMPServerTransportValidatesProfile(t *testing.T) {
	if _, err := newICMPServerTransport(ICMPProfile{MTUMode: "sometimes"}, Nop{}); !errors.Is(err, ErrConfigRequired) {
		t.Fatalf("a bad profile must be rejected before any socket work: %v", err)
	}
}

// TestICMPServerTransportIsExplicitOnUnsupportedPlatforms pins DESIGN_ICMP.md
// §4.1: a platform with no ICMP carrier must refuse with an actionable message,
// never start a tunnel that silently carries nothing.
func TestICMPServerTransportIsExplicitOnUnsupportedPlatforms(t *testing.T) {
	tr, err := newICMPServerTransport(ICMPProfile{PaceMS: 1}, Nop{})
	switch runtime.GOOS {
	case "linux", "android":
		// Linux needs CAP_NET_RAW; the test runner is usually unprivileged, and
		// a rooted runner would succeed. Both outcomes are correct here — the
		// refusal itself is covered on other platforms.
		if err != nil && !errors.Is(err, ErrNoCapNetRaw) && !errors.Is(err, ErrTransportUnsupported) {
			t.Fatalf("unexpected Linux failure: %v", err)
		}
		if tr != nil {
			_ = tr.Close()
		}
	default:
		if !errors.Is(err, ErrTransportUnsupported) {
			t.Fatalf("error on %s = %v, want ErrTransportUnsupported", runtime.GOOS, err)
		}
		if !strings.Contains(err.Error(), "Linux") {
			t.Fatalf("the refusal must say what to do instead: %q", err.Error())
		}
	}
}

// ---------------------------------------------------------------------------
// Capability discovery over the real carrier
// ---------------------------------------------------------------------------

func TestICMPTransportCapabilitySurface(t *testing.T) {
	tr, _ := newTestICMPTransport(t, ICMPProfile{
		MaxPayload: 1200, MTUMode: "auto", PaceMS: 1,
	}, Nop{})

	var asTransport Transport = tr
	if maxRecordSizeOf(asTransport) != icmpDefaultMaxPayload {
		t.Fatalf("MaxRecordSizer = %d", maxRecordSizeOf(asTransport))
	}
	if maxReceiveSizeOf(asTransport) != 1200 {
		t.Fatalf("MaxReceiveSizer = %d", maxReceiveSizeOf(asTransport))
	}
	if pollerOf(asTransport) == nil {
		t.Fatal("the ICMP carrier is request-triggered and must expose Poller")
	}
	if proberOf(asTransport) == nil {
		t.Fatal("the ICMP carrier must expose Prober")
	}
	if carrierConditionOf(asTransport) == nil {
		t.Fatal("the ICMP carrier must expose CarrierCondition")
	}
	if mtuFeedbackOf(asTransport) == nil {
		t.Fatal("the ICMP carrier must expose MTUFeedback")
	}
	if authenticatedFeedbackOf(asTransport) == nil {
		t.Fatal("the ICMP carrier must expose AuthenticatedFeedback")
	}
	if got := payloadBudgetOf(asTransport, 0); got != MaxPayloadFor(icmpDefaultMaxPayload) {
		t.Fatalf("payloadBudgetOf = %d, want %d", got, MaxPayloadFor(icmpDefaultMaxPayload))
	}
}
