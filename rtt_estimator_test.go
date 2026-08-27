package myssh

import (
	"testing"
	"time"
)

// TestRTTEstimator covers the RFC 6298 estimator math + clamping (no network).
func TestRTTEstimator(t *testing.T) {
	// First sample: rtt=R => srtt=R, rttvar=R/2, rto=R+4*(R/2)=3R.
	e := newRTTEstimator(500*time.Millisecond, 200*time.Millisecond, 10*time.Second)
	e.Sample(100 * time.Millisecond)
	if e.srtt != 100*time.Millisecond {
		t.Fatalf("srtt=%v, want 100ms", e.srtt)
	}
	if e.rttvar != 50*time.Millisecond {
		t.Fatalf("rttvar=%v, want 50ms", e.rttvar)
	}
	if e.RTO() != 300*time.Millisecond {
		t.Fatalf("rto=%v, want 300ms", e.RTO())
	}

	// Stable samples (above the 200ms floor) converge to srtt as rttvar
	// decays to 0: rto -> srtt (here 300ms), no longer the initial 3R=900ms.
	e2 := newRTTEstimator(500*time.Millisecond, 200*time.Millisecond, 10*time.Second)
	for i := 0; i < 50; i++ {
		e2.Sample(300 * time.Millisecond)
	}
	if e2.RTO() < 250*time.Millisecond || e2.RTO() > 350*time.Millisecond {
		t.Fatalf("stable rto=%v, want ~300ms", e2.RTO())
	}

	// Jitter widens the variance and raises rto (must stay positive).
	e3 := newRTTEstimator(500*time.Millisecond, 200*time.Millisecond, 10*time.Second)
	e3.Sample(50 * time.Millisecond)
	e3.Sample(150 * time.Millisecond)
	e3.Sample(50 * time.Millisecond)
	e3.Sample(150 * time.Millisecond)
	if e3.RTO() <= 0 {
		t.Fatalf("jitter rto=%v, want >0", e3.RTO())
	}

	// Lower clamp: tiny rtt cannot drive rto below minRTT.
	e4 := newRTTEstimator(500*time.Millisecond, 200*time.Millisecond, 10*time.Second)
	e4.Sample(1 * time.Millisecond)
	if e4.RTO() != 200*time.Millisecond {
		t.Fatalf("lower clamp rto=%v, want 200ms", e4.RTO())
	}

	// Upper clamp: huge rtt cannot drive rto above maxRTT.
	e5 := newRTTEstimator(500*time.Millisecond, 200*time.Millisecond, 10*time.Second)
	e5.Sample(20 * time.Second)
	if e5.RTO() != 10*time.Second {
		t.Fatalf("upper clamp rto=%v, want 10s", e5.RTO())
	}

	// Defensive: zero / negative samples are ignored (state unchanged).
	e6 := newRTTEstimator(500*time.Millisecond, 200*time.Millisecond, 10*time.Second)
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
