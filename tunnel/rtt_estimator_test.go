package tunnel

import (
	"testing"
	"time"
)

func TestRTTEstimator(t *testing.T) {
	// First sample: rtt=R => srtt=R, rttvar=R/2, rto=R+4*(R/2)=3R.
	e := newRTTEstimator(200*time.Millisecond, 200*time.Millisecond, 10*time.Second)
	if e.HasSamples() {
		t.Fatal("a fresh estimator must report no samples")
	}
	e.Sample(100 * time.Millisecond)
	if e.SRTT() != 100*time.Millisecond {
		t.Fatalf("srtt=%v, want 100ms", e.SRTT())
	}
	if !e.HasSamples() {
		t.Fatal("HasSamples must be true after one sample")
	}
	if e.RTO() != 300*time.Millisecond {
		t.Fatalf("rto=%v, want 300ms", e.RTO())
	}

	// Stable samples (above the 200ms floor) converge to srtt as rttvar
	// decays to 0: rto -> srtt (here 300ms), no longer the initial 3R=900ms.
	e2 := newRTTEstimator(200*time.Millisecond, 200*time.Millisecond, 10*time.Second)
	for i := 0; i < 50; i++ {
		e2.Sample(300 * time.Millisecond)
	}
	if e2.RTO() < 250*time.Millisecond || e2.RTO() > 350*time.Millisecond {
		t.Fatalf("stable rto=%v, want ~300ms", e2.RTO())
	}

	// Jitter widens the variance and raises rto (must stay positive).
	e3 := newRTTEstimator(200*time.Millisecond, 200*time.Millisecond, 10*time.Second)
	e3.Sample(50 * time.Millisecond)
	e3.Sample(150 * time.Millisecond)
	e3.Sample(50 * time.Millisecond)
	e3.Sample(150 * time.Millisecond)
	if e3.RTO() <= 0 {
		t.Fatalf("jitter rto=%v, want >0", e3.RTO())
	}

	// Lower clamp: tiny rtt cannot drive rto below minRTT (200ms on server).
	e4 := newRTTEstimator(200*time.Millisecond, 200*time.Millisecond, 10*time.Second)
	e4.Sample(1 * time.Millisecond)
	if e4.RTO() != 200*time.Millisecond {
		t.Fatalf("lower clamp rto=%v, want 200ms", e4.RTO())
	}

	// Upper clamp: huge rtt cannot drive rto above maxRTT.
	e5 := newRTTEstimator(200*time.Millisecond, 200*time.Millisecond, 10*time.Second)
	e5.Sample(20 * time.Second)
	if e5.RTO() != 10*time.Second {
		t.Fatalf("upper clamp rto=%v, want 10s", e5.RTO())
	}

	// Defensive: zero / negative samples are ignored (state unchanged).
	e6 := newRTTEstimator(200*time.Millisecond, 200*time.Millisecond, 10*time.Second)
	e6.Sample(100 * time.Millisecond)
	before := e6.RTO()
	e6.Sample(0)
	if e6.RTO() != before {
		t.Fatal("zero sample unexpectedly changed state")
	}
	e6.Sample(-5 * time.Millisecond)
	if e6.RTO() != before {
		t.Fatal("negative sample unexpectedly changed state")
	}
}

func TestRTTEstimatorInitialRTOIsExposed(t *testing.T) {
	e := newRTTEstimator(750*time.Millisecond, 200*time.Millisecond, 10*time.Second)
	if e.RTO() != 750*time.Millisecond {
		t.Fatalf("initial rto=%v, want the configured initial 750ms", e.RTO())
	}
}

// TestRTTEstimatorConcurrentUse is a race-detector exercise: Sample, RTO and
// SRTT must be safe to call from different goroutines.
func TestRTTEstimatorConcurrentUse(t *testing.T) {
	e := newRTTEstimator(200*time.Millisecond, 200*time.Millisecond, 10*time.Second)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			e.Sample(time.Duration(100+i%50) * time.Millisecond)
		}
		close(done)
	}()
	for i := 0; i < 1000; i++ {
		_ = e.RTO()
		_ = e.SRTT()
		_ = e.HasSamples()
	}
	<-done
	if e.RTO() <= 0 {
		t.Fatal("concurrent use corrupted the estimator")
	}
}
