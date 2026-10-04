package myssh

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func restoreIPv6EgressAuto(t *testing.T) {
	t.Helper()
	require.NoError(t, configureIPv6EgressFromJSON(`{"ipv6_egress_mode":"auto"}`))
}

func TestNormalizeIPv6EgressMode(t *testing.T) {
	cases := map[string]string{
		"":           IPv6EgressModeAuto,
		"auto":       IPv6EgressModeAuto,
		"ipv4":       IPv6EgressModeIPv4Only,
		"ipv4_only":  IPv6EgressModeIPv4Only,
		"ipv4-only":  IPv6EgressModeIPv4Only,
		"ipv6-only":  IPv6EgressModeIPv6Only,
		"ipv6_only":  IPv6EgressModeIPv6Only,
		"dual":       IPv6EgressModeDualStack,
		"dual_stack": IPv6EgressModeDualStack,
		"dual-stack": IPv6EgressModeDualStack,
		"ipv6":       IPv6EgressModeDualStack, // legacy alias
		"v6":         IPv6EgressModeDualStack, // legacy alias
	}
	for input, want := range cases {
		got, err := normalizeIPv6EgressMode(input)
		require.NoError(t, err, input)
		require.Equal(t, want, got, input)
	}
	_, err := normalizeIPv6EgressMode("bogus")
	require.Error(t, err)
}

func TestIPv6EgressProbeTargetsIncludeAliDNS(t *testing.T) {
	require.Contains(t, ipv6EgressProbeTargets, "[2400:3200::1]:443")
}

func TestIPv6EgressProbeRunsTargetsConcurrently(t *testing.T) {
	oldProbe := ipv6EgressProbeDial
	started := make(chan string, len(ipv6EgressProbeTargets))
	releaseAliDNS := make(chan struct{})

	ipv6EgressProbeDial = func(ctx context.Context, client *ssh.Client, target string) error {
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
	defer func() { ipv6EgressProbeDial = oldProbe }()

	result := make(chan bool, 1)
	go func() { result <- probeIPv6Egress(&ssh.Client{}) }()

	seen := make(map[string]bool, len(ipv6EgressProbeTargets))
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for len(seen) < len(ipv6EgressProbeTargets) {
		select {
		case target := <-started:
			seen[target] = true
		case <-deadline.C:
			t.Fatalf("probe targets were not started concurrently: started=%v", seen)
		}
	}

	close(releaseAliDNS)
	select {
	case available := <-result:
		require.True(t, available)
	case <-time.After(time.Second):
		t.Fatal("probe did not return promptly after a concurrent target succeeded")
	}
}

func TestIPv6EgressProbeUsesOneSharedDeadline(t *testing.T) {
	oldProbe := ipv6EgressProbeDial
	ipv6EgressProbeDial = func(ctx context.Context, client *ssh.Client, target string) error {
		<-ctx.Done()
		return ctx.Err()
	}
	defer func() { ipv6EgressProbeDial = oldProbe }()

	started := time.Now()
	require.False(t, probeIPv6Egress(&ssh.Client{}))
	require.Less(t, time.Since(started), 3*time.Second)
}

func TestIPv6EgressForcedModesReturnImmediately(t *testing.T) {
	defer restoreIPv6EgressAuto(t)

	require.NoError(t, configureIPv6EgressFromJSON(`{"ipv6_egress_mode":"ipv4-only"}`))
	require.Equal(t, ipv6EgressUnavailable, waitIPv6EgressMs(1))
	require.Equal(t, "unavailable", ipv6EgressStateName())

	require.NoError(t, configureIPv6EgressFromJSON(`{"ipv6_egress_mode":"ipv6-only"}`))
	require.Equal(t, ipv6EgressAvailable, waitIPv6EgressMs(1))

	require.NoError(t, configureIPv6EgressFromJSON(`{"ipv6_egress_mode":"dual-stack"}`))
	require.Equal(t, ipv6EgressAvailable, waitIPv6EgressMs(1))
}

func TestExplicitIPv4OnlyStillRejectsUnrecoverableProxyIPv6Literal(t *testing.T) {
	defer restoreIPv6EgressAuto(t)
	require.NoError(t, configureIPv6EgressFromJSON(`{"ipv6_egress_mode":"ipv4-only"}`))

	require.True(t, shouldRejectProxyIPv6Literal("2001:db8::1", false))
	require.False(t, shouldRejectProxyIPv6Literal("2001:db8::1", true), "DIRECT is target-driven")
	require.False(t, shouldRejectProxyIPv6Literal("203.0.113.7", false))
}

func TestAutoProbeFailureIsDiagnosticOnly(t *testing.T) {
	defer restoreIPv6EgressAuto(t)
	require.NoError(t, configureIPv6EgressFromJSON(`{"ipv6_egress_mode":"auto"}`))

	remoteIPv6Egress.mu.Lock()
	remoteIPv6Egress.state = ipv6EgressUnavailable
	remoteIPv6Egress.mu.Unlock()

	require.False(t, shouldRejectProxyIPv6Literal("2001:db8::1", false), "auto probe failure must not ban target-specific IPv6")
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeAAAA)
	require.False(t, shouldSuppressProxyAAAA(req), "auto probe failure must not suppress AAAA")
}

func TestExplicitFamilyPolicySuppressesOnlyMatchingDNSFamily(t *testing.T) {
	defer restoreIPv6EgressAuto(t)
	oldRouter := globalRouter.Load()
	globalRouter.Store(nil)
	defer globalRouter.Store(oldRouter)

	reqA := new(dns.Msg)
	reqA.SetQuestion("example.com.", dns.TypeA)
	reqAAAA := new(dns.Msg)
	reqAAAA.SetQuestion("example.com.", dns.TypeAAAA)

	require.NoError(t, configureIPv6EgressFromJSON(`{"ipv6_egress_mode":"ipv4-only"}`))
	require.False(t, shouldSuppressDNSFamily(reqA))
	require.True(t, shouldSuppressDNSFamily(reqAAAA))

	require.NoError(t, configureIPv6EgressFromJSON(`{"ipv6_egress_mode":"ipv6-only"}`))
	require.True(t, shouldSuppressDNSFamily(reqA))
	require.False(t, shouldSuppressDNSFamily(reqAAAA))
}

func TestNoDataReplyIsNoErrorAndEmpty(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeAAAA)
	packed, err := makeAAAANoDataReply(req)
	require.NoError(t, err)

	reply := new(dns.Msg)
	require.NoError(t, reply.Unpack(packed))
	require.Equal(t, dns.RcodeSuccess, reply.Rcode)
	require.Empty(t, reply.Answer)
	require.Equal(t, req.Id, reply.Id)
}

func TestAutoProbePublishesAvailableDiagnosticState(t *testing.T) {
	defer restoreIPv6EgressAuto(t)
	require.NoError(t, configureIPv6EgressFromJSON(`{"ipv6_egress_mode":"auto"}`))

	oldProbe := ipv6EgressProbeDial
	ipv6EgressProbeDial = func(ctx context.Context, client *ssh.Client, target string) error { return nil }
	defer func() { ipv6EgressProbeDial = oldProbe }()

	startIPv6EgressProbe(&ssh.Client{})
	require.Equal(t, ipv6EgressAvailable, waitIPv6EgressMs(250))
	// startIPv6EgressProbe also starts the local diagnostic probe. Wait for it
	// before this test returns so a later test can safely replace its fake dialer.
	require.Equal(t, ipv6EgressAvailable, waitLocalDirectIPv6Ms(250))
}
