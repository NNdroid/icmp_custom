package tunnel

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Method A': the active path-MTU probe
//
// The search is deliberately pure — it only ever talks to an mtuProbeLink — so
// the whole algorithm is testable with no socket, no root and no wall clock.
// ---------------------------------------------------------------------------

// fakeProbeLink answers probes from a declared payload ceiling per direction.
// A ceiling of -1 means "every size fails".
type fakeProbeLink struct {
	mu          sync.Mutex
	upCeiling   int
	downCeiling int
	failErr     error

	upProbes   int
	downProbes int
	maxUp      int
	maxDown    int
	closed     bool
}

func (l *fakeProbeLink) ProbeUplink(_ context.Context, payloadBytes int) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.upProbes++
	if payloadBytes > l.maxUp {
		l.maxUp = payloadBytes
	}
	if l.failErr != nil {
		return false, l.failErr
	}
	return payloadBytes <= l.upCeiling, nil
}

func (l *fakeProbeLink) ProbeDownlink(_ context.Context, payloadBytes int) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.downProbes++
	if payloadBytes > l.maxDown {
		l.maxDown = payloadBytes
	}
	if l.failErr != nil {
		return false, l.failErr
	}
	return payloadBytes <= l.downCeiling, nil
}

func (l *fakeProbeLink) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return nil
}

func (l *fakeProbeLink) probes() (up, down int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.upProbes, l.downProbes
}

// boundedProbe returns a probe func that succeeds for size <= boundary.
func boundedProbe(boundary int) func(int) (bool, error) {
	return func(size int) (bool, error) { return size <= boundary, nil }
}

func TestSearchMaxPayloadFindsTheExactBoundary(t *testing.T) {
	best, probes, ceilingHit := searchMaxPayload(context.Background(),
		500, 1200, 1500, 20, boundedProbe(1300))

	if best != 1300 {
		t.Fatalf("best = %d, want the exact boundary 1300", best)
	}
	if ceilingHit {
		t.Fatal("ceiling_hit must be false: 1300 is below the 1500 ceiling")
	}
	if probes > 20 {
		t.Fatalf("used %d probes, budget was 20", probes)
	}
}

func TestSearchMaxPayloadBelowTheAssumedStart(t *testing.T) {
	// The path is narrower than the conservative start, so the search must
	// refine DOWNWARD between the known-good floor and the failed start.
	best, _, ceilingHit := searchMaxPayload(context.Background(),
		500, 1200, 1500, 20, boundedProbe(700))
	if best != 700 {
		t.Fatalf("best = %d, want 700", best)
	}
	if ceilingHit {
		t.Fatal("ceiling_hit must be false")
	}
}

func TestSearchMaxPayloadReportsACeilingHit(t *testing.T) {
	best, _, ceilingHit := searchMaxPayload(context.Background(),
		500, 1200, 1500, 20, boundedProbe(1<<20))
	if best != 1500 {
		t.Fatalf("best = %d, want the ceiling 1500", best)
	}
	if !ceilingHit {
		t.Fatal("ceiling_hit must be true when the whole range works")
	}
}

// TestSearchMaxPayloadGivesUpWhenTheFloorFails pins the monotonicity contract:
// if the guaranteed floor does not survive, no larger size can either, and the
// caller must keep its existing in-band budget rather than adopt a bogus one.
func TestSearchMaxPayloadGivesUpWhenTheFloorFails(t *testing.T) {
	best, probes, ceilingHit := searchMaxPayload(context.Background(),
		500, 1200, 1500, 20, boundedProbe(100))
	if best != 0 {
		t.Fatalf("best = %d, want 0 when even the floor fails", best)
	}
	if probes != 1 {
		t.Fatalf("probes = %d, want exactly 1 (the floor attempt)", probes)
	}
	if ceilingHit {
		t.Fatal("ceiling_hit must be false")
	}
}

func TestSearchMaxPayloadHonoursItsProbeBudget(t *testing.T) {
	const budget = 4
	best, probes, _ := searchMaxPayload(context.Background(),
		500, 1200, 1500, budget, boundedProbe(1490))
	if probes > budget {
		t.Fatalf("used %d probes, budget was %d", probes, budget)
	}
	if best > 1490 {
		t.Fatalf("best = %d, which the link cannot actually carry", best)
	}
	if best < 500 {
		t.Fatalf("best = %d, must never fall below the floor", best)
	}
}

// TestSearchMaxPayloadTreatsAProbeErrorAsTooBig: the probe is best-effort, so an
// error is indistinguishable from "too big" for search purposes. Either way the
// size is unusable, and the caller has method B to fall back on.
func TestSearchMaxPayloadTreatsAProbeErrorAsTooBig(t *testing.T) {
	attempts := 0
	probe := func(size int) (bool, error) {
		attempts++
		if size == 500 {
			return true, nil
		}
		return false, errors.New("probe transport failed")
	}
	best, _, ceilingHit := searchMaxPayload(context.Background(), 500, 1200, 1500, 20, probe)
	if best != 500 {
		t.Fatalf("best = %d, want the last known-good floor 500", best)
	}
	if ceilingHit {
		t.Fatal("ceiling_hit must be false")
	}
}

func TestSearchMaxPayloadDegenerateRange(t *testing.T) {
	// floor == ceiling: one probe and the answer is already known.
	best, probes, ceilingHit := searchMaxPayload(context.Background(),
		900, 900, 900, 20, boundedProbe(900))
	if best != 900 || probes != 1 || !ceilingHit {
		t.Fatalf("degenerate range = (%d,%d,%t), want (900,1,true)", best, probes, ceilingHit)
	}
}

// ---------------------------------------------------------------------------
// The full two-direction search
// ---------------------------------------------------------------------------

func TestNewMTUProbeSearchConvertsRecordBudgetsToPlaintext(t *testing.T) {
	s := newMTUProbeSearch(resolvedProfile{
		maxPayload: 1472, mtuMin: 548, mtuStep: 100,
	}, Nop{})

	if want := MaxPayloadFor(1472); s.ceiling != want {
		t.Fatalf("ceiling = %d, want %d plaintext bytes", s.ceiling, want)
	}
	if want := MaxPayloadFor(548); s.floor != want {
		t.Fatalf("floor = %d, want %d plaintext bytes", s.floor, want)
	}
	if s.step != 100 {
		t.Fatalf("step = %d, want 100", s.step)
	}
	if s.budget != mtuProbeBudget {
		t.Fatalf("budget = %d, want %d", s.budget, mtuProbeBudget)
	}
}

func TestMTUProbeSearchSearchesBothDirectionsWithinItsBudget(t *testing.T) {
	log := &captureLogger{}
	s := newMTUProbeSearch(resolvedProfile{
		maxPayload: 1472, mtuMin: 548, mtuStep: 100,
	}, log)

	link := &fakeProbeLink{upCeiling: 1000, downCeiling: 1300}
	res := s.Run(context.Background(), link)

	if res.UplinkPayload <= 0 || res.UplinkPayload > 1000 {
		t.Fatalf("uplink payload = %d, want 0 < n <= 1000", res.UplinkPayload)
	}
	if res.DownlinkPayload <= 0 || res.DownlinkPayload > 1300 {
		t.Fatalf("downlink payload = %d, want 0 < n <= 1300", res.DownlinkPayload)
	}
	if res.Probes > mtuProbeBudget {
		t.Fatalf("spent %d probes, budget was %d", res.Probes, mtuProbeBudget)
	}
	if res.CeilingHit {
		t.Fatal("neither direction reached its ceiling")
	}
	if line := log.find("mtu probe done"); line == "" {
		t.Fatalf("the probe outcome must be logged; lines=%v", log.lines)
	} else if !strings.Contains(line, "uplink=") || !strings.Contains(line, "downlink=") {
		t.Fatalf("the probe log must report both directions: %q", line)
	}
}

// TestMTUProbeSearchSplitsItsBudgetEvenly is what keeps the uplink from eating
// the whole allowance: the direction this end controls is searched first, and
// the downlink must still get its half.
func TestMTUProbeSearchSplitsItsBudgetEvenly(t *testing.T) {
	s := newMTUProbeSearch(resolvedProfile{
		maxPayload: 1472, mtuMin: 548, mtuStep: 100,
	}, Nop{})
	link := &fakeProbeLink{upCeiling: 1 << 20, downCeiling: 1 << 20}
	s.Run(context.Background(), link)

	up, down := link.probes()
	if up < 1 || down < 1 {
		t.Fatalf("uplink/downlink probes = %d/%d; both directions must be searched", up, down)
	}
	if up+down > mtuProbeBudget {
		t.Fatalf("total probes = %d, budget was %d", up+down, mtuProbeBudget)
	}
	if up > mtuProbeBudget/2+1 {
		t.Fatalf("uplink used %d probes, more than its half", up)
	}
}

// TestMTUProbeSearchNeverFailsTheTunnel: an unusable probe path must yield no
// result, not an error the caller has to handle. Method B then carries on.
func TestMTUProbeSearchNeverFailsTheTunnel(t *testing.T) {
	log := &captureLogger{}
	s := newMTUProbeSearch(resolvedProfile{
		maxPayload: 1472, mtuMin: 548, mtuStep: 100,
	}, log)
	link := &fakeProbeLink{upCeiling: -1, downCeiling: -1}
	res := s.Run(context.Background(), link)

	if res.UplinkPayload != 0 || res.DownlinkPayload != 0 {
		t.Fatalf("result = %+v, want both directions to report 0", res)
	}
	if res.CeilingHit {
		t.Fatal("ceiling_hit must be false")
	}
}

func TestMTUProbeSearchSurvivesATransportError(t *testing.T) {
	s := newMTUProbeSearch(resolvedProfile{
		maxPayload: 1472, mtuMin: 548, mtuStep: 100,
	}, Nop{})
	link := &fakeProbeLink{failErr: errors.New("the probe socket died")}
	res := s.Run(context.Background(), link)
	if res.UplinkPayload != 0 || res.DownlinkPayload != 0 {
		t.Fatalf("a failing probe transport must yield no result, got %+v", res)
	}
}

// TestMTUProbeSearchNeverExceedsTheConfiguredCeiling guards the invariant that
// matters most: a probe is a REAL data record, so an adopted budget above the
// configured maximum would emit a record the peer's receive buffer cannot hold.
func TestMTUProbeSearchNeverExceedsTheConfiguredCeiling(t *testing.T) {
	resolved := resolvedProfile{maxPayload: 1200, mtuMin: 548, mtuStep: 100}
	s := newMTUProbeSearch(resolved, Nop{})
	link := &fakeProbeLink{upCeiling: 1 << 20, downCeiling: 1 << 20}
	res := s.Run(context.Background(), link)

	ceiling := MaxPayloadFor(resolved.maxPayload)
	if res.UplinkPayload > ceiling || res.DownlinkPayload > ceiling {
		t.Fatalf("result = %+v, want every payload <= the plaintext ceiling %d", res, ceiling)
	}
	if !res.CeilingHit {
		t.Fatal("a link that carries everything must report a ceiling hit")
	}
}
