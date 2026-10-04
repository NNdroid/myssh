package myssh

import (
	"context"
	"sync"
	"time"
)

// localDirectIPv6Tracker records a diagnostic observation of public IPv6
// reachability on the Android/device network used by DIRECT traffic. It does
// not gate forwarding: private/ULA/enterprise IPv6 may still be reachable even
// when all public probe targets fail.
type localDirectIPv6Tracker struct {
	mu         sync.Mutex
	state      int
	generation uint64
	done       chan struct{}
	doneClosed bool
}

var localDirectIPv6 = localDirectIPv6Tracker{
	state: ipv6EgressUnknown,
	done:  make(chan struct{}),
}

// Injectable for tests. Production uses a protected socket so the diagnostic
// probe leaves through the device's underlying network instead of the VPN.
var localDirectIPv6ProbeDial = func(ctx context.Context, target string) error {
	conn, err := dialProtected(ctx, ProxyConfig{}, "tcp", target, ipv6EgressProbeTimeout)
	if err != nil {
		return err
	}
	return conn.Close()
}

type localDirectIPv6ProbeResult struct {
	target string
	err    error
}

func resetLocalDirectIPv6State() {
	localDirectIPv6.mu.Lock()
	defer localDirectIPv6.mu.Unlock()
	localDirectIPv6.generation++
	localDirectIPv6.state = ipv6EgressUnknown
	localDirectIPv6.done = make(chan struct{})
	localDirectIPv6.doneClosed = false
}

// startLocalDirectIPv6Probe refreshes diagnostics on initial connect and later
// reconnects. A generation prevents stale probe results from overwriting a
// newer observation after an underlying-network change.
func startLocalDirectIPv6Probe() {
	localDirectIPv6.mu.Lock()
	localDirectIPv6.generation++
	generation := localDirectIPv6.generation
	localDirectIPv6.state = ipv6EgressUnknown
	localDirectIPv6.done = make(chan struct{})
	localDirectIPv6.doneClosed = false
	localDirectIPv6.mu.Unlock()

	taskTrack()
	go func() {
		defer taskRelease()
		available := probeLocalDirectIPv6()

		localDirectIPv6.mu.Lock()
		defer localDirectIPv6.mu.Unlock()
		if localDirectIPv6.generation != generation {
			return
		}
		if available {
			localDirectIPv6.state = ipv6EgressAvailable
			zlog.Infof("%s [IPv6-Direct] ✅ diagnostic: local public IPv6 reachable", TAG)
		} else {
			localDirectIPv6.state = ipv6EgressUnavailable
			zlog.Warnf("%s [IPv6-Direct] ⚠️ diagnostic: local public IPv6 not confirmed; target-specific DIRECT IPv6 remains allowed", TAG)
		}
		if !localDirectIPv6.doneClosed {
			close(localDirectIPv6.done)
			localDirectIPv6.doneClosed = true
		}
	}()
}

// probeLocalDirectIPv6 races the same public IPv6:443 targets used by the
// remote diagnostic, but through dialProtected(). One success proves public
// IPv6 reachability; all failures only mean that public IPv6 was not confirmed.
func probeLocalDirectIPv6() bool {
	if len(ipv6EgressProbeTargets) == 0 {
		return false
	}

	ctx, cancel := context.WithTimeout(currentEngineCtx(), ipv6EgressProbeTimeout)
	defer cancel()

	probeDial := localDirectIPv6ProbeDial
	results := make(chan localDirectIPv6ProbeResult, len(ipv6EgressProbeTargets))
	for _, target := range ipv6EgressProbeTargets {
		target := target
		taskTrack()
		go func() {
			defer taskRelease()
			err := probeDial(ctx, target)
			select {
			case results <- localDirectIPv6ProbeResult{target: target, err: err}:
			case <-ctx.Done():
			}
		}()
	}

	remaining := len(ipv6EgressProbeTargets)
	for remaining > 0 {
		select {
		case result := <-results:
			remaining--
			if result.err == nil {
				cancel()
				return true
			}
			if Debug {
				zlog.Debugf("%s [IPv6-Direct] diagnostic probe failed target=%s err=%v", TAG, result.target, result.err)
			}
		case <-ctx.Done():
			return false
		}
	}
	return false
}

func localDirectIPv6State() int {
	localDirectIPv6.mu.Lock()
	defer localDirectIPv6.mu.Unlock()
	return localDirectIPv6.state
}

func localDirectIPv6Unavailable() bool {
	return localDirectIPv6State() == ipv6EgressUnavailable
}

func localDirectIPv6StateName() string {
	switch localDirectIPv6State() {
	case ipv6EgressAvailable:
		return "available"
	case ipv6EgressUnavailable:
		return "unavailable"
	default:
		return "unknown"
	}
}

func waitLocalDirectIPv6Ms(timeoutMs int) int {
	localDirectIPv6.mu.Lock()
	state := localDirectIPv6.state
	done := localDirectIPv6.done
	localDirectIPv6.mu.Unlock()

	if state != ipv6EgressUnknown {
		return state
	}
	if timeoutMs <= 0 {
		return ipv6EgressUnknown
	}

	timer := time.NewTimer(time.Duration(timeoutMs) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-done:
		return localDirectIPv6State()
	case <-timer.C:
		return ipv6EgressUnknown
	}
}

// WaitDirectIPv6 waits for the local public-IPv6 diagnostic probe.
// Return values: 1 = observed available, 0 = not confirmed, -1 = unknown/timeout.
func (p *SshTProxy) WaitDirectIPv6(timeoutMs int) int {
	return waitLocalDirectIPv6Ms(timeoutMs)
}

// GetDirectIPv6State returns the diagnostic observation: available,
// unavailable (not confirmed), or unknown. It is not a forwarding policy.
func (p *SshTProxy) GetDirectIPv6State() string {
	return localDirectIPv6StateName()
}
