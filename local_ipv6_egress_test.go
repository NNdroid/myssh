package myssh

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// Keep package tests hermetic: production uses dialProtected(), while unit
// tests default to an immediately successful local diagnostic probe.
func init() {
	localDirectIPv6ProbeDial = func(ctx context.Context, target string) error {
		return nil
	}
}

func setLocalDirectIPv6StateForTest(state int) {
	localDirectIPv6.mu.Lock()
	defer localDirectIPv6.mu.Unlock()
	localDirectIPv6.generation++
	localDirectIPv6.state = state
	localDirectIPv6.done = make(chan struct{})
	localDirectIPv6.doneClosed = state != ipv6EgressUnknown
	if localDirectIPv6.doneClosed {
		close(localDirectIPv6.done)
	}
}

func TestLocalDirectIPv6ProbeRunsTargetsConcurrently(t *testing.T) {
	oldProbe := localDirectIPv6ProbeDial
	started := make(chan string, len(ipv6EgressProbeTargets))
	releaseAliDNS := make(chan struct{})

	localDirectIPv6ProbeDial = func(ctx context.Context, target string) error {
		started <- target
		if target == "[2400:3200::1]:443" {
			select {
			case <-releaseAliDNS:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		<-ctx.Done()
		return ctx.Err()
	}
	defer func() { localDirectIPv6ProbeDial = oldProbe }()

	result := make(chan bool, 1)
	go func() { result <- probeLocalDirectIPv6() }()

	seen := make(map[string]bool, len(ipv6EgressProbeTargets))
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for len(seen) < len(ipv6EgressProbeTargets) {
		select {
		case target := <-started:
			seen[target] = true
		case <-deadline.C:
			t.Fatalf("local IPv6 probe targets were not started concurrently: started=%v", seen)
		}
	}

	close(releaseAliDNS)
	select {
	case available := <-result:
		require.True(t, available)
	case <-time.After(time.Second):
		t.Fatal("local IPv6 probe did not return promptly after a target succeeded")
	}
}

func TestLocalDirectIPv6ProbeUsesOneSharedDeadline(t *testing.T) {
	oldProbe := localDirectIPv6ProbeDial
	localDirectIPv6ProbeDial = func(ctx context.Context, target string) error {
		<-ctx.Done()
		return ctx.Err()
	}
	defer func() { localDirectIPv6ProbeDial = oldProbe }()

	started := time.Now()
	require.False(t, probeLocalDirectIPv6())
	require.Less(t, time.Since(started), 3*time.Second)
}

func TestLocalProbeFailureDoesNotGateDirectTraffic(t *testing.T) {
	defer resetLocalDirectIPv6State()
	defer restoreIPv6EgressAuto(t)

	setLocalDirectIPv6StateForTest(ipv6EgressUnavailable)
	require.False(t, shouldRejectProxyIPv6Literal("2001:db8::1", true), "DIRECT literal decisions must use the target dial, not a public probe")

	oldRouter := globalRouter.Load()
	r := newGeoRouter()
	r.fullDomains["direct.example"] = struct{}{}
	globalRouter.Store(r)
	defer globalRouter.Store(oldRouter)

	req := new(dns.Msg)
	req.SetQuestion("direct.example.", dns.TypeAAAA)
	require.False(t, shouldSuppressDNSFamily(req), "DIRECT AAAA must not be globally suppressed by a diagnostic probe")
}

func TestRemoteForcedPolicyDoesNotLeakIntoDirect(t *testing.T) {
	defer resetLocalDirectIPv6State()
	defer restoreIPv6EgressAuto(t)

	require.NoError(t, configureIPv6EgressFromJSON(`{"ipv6_egress_mode":"ipv4-only"}`))
	setLocalDirectIPv6StateForTest(ipv6EgressUnavailable)

	require.True(t, shouldRejectProxyIPv6Literal("2001:db8::1", false), "explicit proxy policy still applies to PROXY")
	require.False(t, shouldRejectProxyIPv6Literal("2001:db8::1", true), "DIRECT remains target-driven")
}

func TestStartRemoteProbeRefreshesLocalDiagnosticState(t *testing.T) {
	defer resetLocalDirectIPv6State()
	defer restoreIPv6EgressAuto(t)

	oldRemoteProbe := ipv6EgressProbeDial
	oldLocalProbe := localDirectIPv6ProbeDial
	ipv6EgressProbeDial = func(ctx context.Context, client *ssh.Client, target string) error { return nil }
	localDirectIPv6ProbeDial = func(ctx context.Context, target string) error { return nil }
	defer func() {
		ipv6EgressProbeDial = oldRemoteProbe
		localDirectIPv6ProbeDial = oldLocalProbe
	}()

	require.NoError(t, configureIPv6EgressFromJSON(`{"ipv6_egress_mode":"auto"}`))
	setLocalDirectIPv6StateForTest(ipv6EgressUnavailable)
	startIPv6EgressProbe(&ssh.Client{})

	require.Equal(t, ipv6EgressAvailable, waitIPv6EgressMs(250))
	require.Equal(t, ipv6EgressAvailable, waitLocalDirectIPv6Ms(250))
}
