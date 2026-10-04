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
// tests default to an immediately successful local probe unless a test installs
// a more specific fake.
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
	elapsed := time.Since(started)
	require.Less(t, elapsed, 3*time.Second)
}

func TestLocalAndRemoteIPv6LiteralPoliciesAreIndependent(t *testing.T) {
	defer resetLocalDirectIPv6State()
	defer restoreIPv6EgressAuto(t)

	// Remote can use IPv6 while the device DIRECT path cannot.
	require.NoError(t, configureIPv6EgressFromJSON(`{"ipv6_egress_mode":"dual-stack"}`))
	setLocalDirectIPv6StateForTest(ipv6EgressUnavailable)
	require.False(t, shouldRejectProxyIPv6Literal("2001:db8::1", false), "proxy IPv6 follows remote capability")
	require.True(t, shouldRejectProxyIPv6Literal("2001:db8::1", true), "DIRECT IPv6 follows local capability")

	// The inverse must also remain independent.
	require.NoError(t, configureIPv6EgressFromJSON(`{"ipv6_egress_mode":"ipv4-only"}`))
	setLocalDirectIPv6StateForTest(ipv6EgressAvailable)
	require.True(t, shouldRejectProxyIPv6Literal("2001:db8::1", false))
	require.False(t, shouldRejectProxyIPv6Literal("2001:db8::1", true))
}

func TestDirectAAAAUsesLocalIPv6Capability(t *testing.T) {
	oldRouter := globalRouter.Load()
	r := newGeoRouter()
	r.fullDomains["direct.example"] = struct{}{}
	globalRouter.Store(r)
	defer globalRouter.Store(oldRouter)
	defer resetLocalDirectIPv6State()

	req := new(dns.Msg)
	req.SetQuestion("direct.example.", dns.TypeAAAA)

	setLocalDirectIPv6StateForTest(ipv6EgressUnavailable)
	require.True(t, shouldSuppressProxyAAAA(req), "DIRECT AAAA must be NODATA when the local path has no IPv6")

	setLocalDirectIPv6StateForTest(ipv6EgressAvailable)
	require.False(t, shouldSuppressProxyAAAA(req), "DIRECT AAAA must pass when the local path has IPv6")

	setLocalDirectIPv6StateForTest(ipv6EgressUnknown)
	require.False(t, shouldSuppressProxyAAAA(req), "unknown local state must not be treated as confirmed IPv4-only")
}

func TestStartRemoteProbeRefreshesLocalDirectIPv6State(t *testing.T) {
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
