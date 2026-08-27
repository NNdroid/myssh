package myssh

import (
	"sync"
	"time"
)

// rttEstimator implements an RFC 6298 RTT/timeout estimator (Jacobson/Karels)
// with Karn's rule: only samples RTT for packets that were never retransmitted.
//
// It is a pure in-memory type, safe for concurrent use, and does NOT touch the
// wire protocol — the udp_custom server is fully unaware of it (binary compatible).
type rttEstimator struct {
	mu      sync.Mutex
	srtt    time.Duration // smoothed RTT
	rttvar  time.Duration // RTT variance
	rto     time.Duration // current retransmission timeout
	hasData bool          // whether at least one sample has been taken
	minRTT  time.Duration // lower clamp (e.g. 200ms)
	maxRTT  time.Duration // upper clamp (e.g. 10s)
}

// newRTTEstimator builds an estimator. `initial` is used before any sample is
// collected (acts as the first RTO). `minRTT`/`maxRTT` clamp the computed RTO.
func newRTTEstimator(initial, minRTT, maxRTT time.Duration) *rttEstimator {
	return &rttEstimator{
		srtt:    initial,
		rttvar:  initial / 2,
		rto:     initial,
		hasData: false,
		minRTT:  minRTT,
		maxRTT:  maxRTT,
	}
}

// Sample feeds one RTT measurement (usually now - firstSent of an ACKed packet).
// Per Karn's rule, callers must only pass samples for never-retransmitted packets.
func (e *rttEstimator) Sample(rtt time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Defensive: a non-positive RTT is a clock anomaly / misuse and must not
	// corrupt the estimator state.
	if rtt <= 0 {
		return
	}

	if !e.hasData {
		// First sample: RFC 6298 step 2.2.
		e.srtt = rtt
		e.rttvar = rtt / 2
		e.hasData = true
	} else {
		// Subsequent samples: RFC 6298 step 2.3 (alpha=1/8, beta=1/4).
		errVal := rtt - e.srtt
		e.srtt += time.Duration(0.125 * float64(errVal))
		e.rttvar += time.Duration(0.25 * float64(absDuration(errVal)-e.rttvar))
	}

	e.rto = e.srtt + 4*e.rttvar
	if e.rto < e.minRTT {
		e.rto = e.minRTT
	}
	if e.rto > e.maxRTT {
		e.rto = e.maxRTT
	}
}

// RTO returns the current retransmission timeout.
func (e *rttEstimator) RTO() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rto
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
