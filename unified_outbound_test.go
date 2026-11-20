package myssh

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func withTestDNSCache(t *testing.T, entries map[string]dnsCacheEntry) {
	t.Helper()
	old := localDnsServer.Load()
	localDnsServer.Store(&LocalDnsServer{cache: entries})
	resetReverseDNSMemo()
	t.Cleanup(func() {
		resetReverseDNSMemo()
		localDnsServer.Store(old)
	})
}

func dnsCacheKeyForTest(domain string, qtype uint16) string {
	return dns.Fqdn(domain) + "-" + strconv.Itoa(int(qtype))
}

// TestInvalidateReverseDNSMemoIPsIsTargeted 钉住「定向失效」而非「全量清空」。
//
// DNS 缓存写入与清理非常频繁；若这里退化成全清，memo 会几乎永远为空，
// recoverDomainFromDNSCache 就会退化成每次都对 DNS 缓存做一遍 O(N) 全表扫描
// （且全程持有 cacheMu 读锁）。正确性只要求作废**受影响**的那些 IP。
func TestInvalidateReverseDNSMemoIPsIsTargeted(t *testing.T) {
	resetReverseDNSMemo()
	defer resetReverseDNSMemo()

	affected := net.ParseIP("203.0.113.9")
	unrelated := net.ParseIP("198.51.100.7")
	exp := time.Now().Add(time.Minute)

	reverseDNSMemo.Lock()
	reverseDNSMemo.entries[affected.String()] = reverseDNSMemoEntry{domain: "affected.example", expires: exp, found: true}
	reverseDNSMemo.entries[unrelated.String()] = reverseDNSMemoEntry{domain: "unrelated.example", expires: exp, found: true}
	reverseDNSMemo.Unlock()

	invalidateReverseDNSMemoIPs([]net.IP{affected})

	reverseDNSMemo.Lock()
	_, affectedLeft := reverseDNSMemo.entries[affected.String()]
	unrelatedEntry, unrelatedLeft := reverseDNSMemo.entries[unrelated.String()]
	reverseDNSMemo.Unlock()

	if affectedLeft {
		t.Fatal("IPs carried by the new DNS reply must be invalidated")
	}
	if !unrelatedLeft || unrelatedEntry.domain != "unrelated.example" {
		t.Fatal("unrelated IPs must keep their memo entry")
	}
}

func TestRecoverDomainFromDNSCacheUnique(t *testing.T) {
	expires := time.Now().Add(time.Minute)
	withTestDNSCache(t, map[string]dnsCacheEntry{
		dnsCacheKeyForTest("one.example", dns.TypeA): {
			expiresAt: expires,
			ips:       []net.IP{net.ParseIP("203.0.113.10")},
		},
	})

	domain, ok := recoverDomainFromDNSCache("203.0.113.10")
	require.True(t, ok)
	require.Equal(t, "one.example", domain)
}

func TestRecoverDomainFromDNSCacheRejectsSharedIPAmbiguity(t *testing.T) {
	expires := time.Now().Add(time.Minute)
	shared := net.ParseIP("203.0.113.10")
	withTestDNSCache(t, map[string]dnsCacheEntry{
		dnsCacheKeyForTest("one.example", dns.TypeA): {
			expiresAt: expires,
			ips:       []net.IP{shared},
		},
		dnsCacheKeyForTest("two.example", dns.TypeA): {
			expiresAt: expires,
			ips:       []net.IP{shared},
		},
	})

	domain, ok := recoverDomainFromDNSCache("203.0.113.10")
	require.False(t, ok)
	require.Empty(t, domain)
}

func TestRecoverDomainFromDNSCacheIgnoresExpiredBinding(t *testing.T) {
	withTestDNSCache(t, map[string]dnsCacheEntry{
		dnsCacheKeyForTest("expired.example", dns.TypeAAAA): {
			expiresAt: time.Now().Add(-time.Second),
			ips:       []net.IP{net.ParseIP("2001:db8::10")},
		},
	})

	_, ok := recoverDomainFromDNSCache("2001:db8::10")
	require.False(t, ok)
}

func TestOrderTCPHostsPreservesOriginalThenCrossFamily(t *testing.T) {
	defer restoreIPv6EgressAuto(t)
	require.NoError(t, configureIPv6EgressFromJSON(`{"ipv6_egress_mode":"auto"}`))

	ips := []net.IP{
		net.ParseIP("2001:db8::1"),
		net.ParseIP("192.0.2.1"),
		net.ParseIP("2001:db8::2"),
		net.ParseIP("192.0.2.2"),
	}
	got := orderTCPHosts(ips, "2001:db8::1", false)
	require.Equal(t, []string{"2001:db8::1", "192.0.2.1", "2001:db8::2", "192.0.2.2"}, got)
}

func TestOrderTCPHostsDomainDefaultsToIPv6ThenIPv4(t *testing.T) {
	defer restoreIPv6EgressAuto(t)
	require.NoError(t, configureIPv6EgressFromJSON(`{"ipv6_egress_mode":"auto"}`))

	ips := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}
	got := orderTCPHosts(ips, "", false)
	require.Equal(t, []string{"2001:db8::1", "192.0.2.1"}, got)
}

func TestOrderTCPHostsHonorsForcedProxyFamilies(t *testing.T) {
	defer restoreIPv6EgressAuto(t)
	ips := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}

	require.NoError(t, configureIPv6EgressFromJSON(`{"ipv6_egress_mode":"ipv4-only"}`))
	require.Equal(t, []string{"192.0.2.1"}, orderTCPHosts(ips, "2001:db8::1", false))

	require.NoError(t, configureIPv6EgressFromJSON(`{"ipv6_egress_mode":"ipv6-only"}`))
	require.Equal(t, []string{"2001:db8::1"}, orderTCPHosts(ips, "192.0.2.1", false))

	// DIRECT auto mode is target-driven and never inherits the remote policy.
	require.Equal(t, []string{"192.0.2.1", "2001:db8::1"}, orderTCPHosts(ips, "192.0.2.1", true))
}

func TestFilterDirectCandidatesKeepsOnlyGeoIPMatches(t *testing.T) {
	oldRouter := globalRouter.Load()
	r := newGeoRouter()
	r.ipTrie.Insert(net.IPv4(192, 0, 2, 0).To4(), 24)
	globalRouter.Store(r)
	defer globalRouter.Store(oldRouter)

	ips := []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("203.0.113.10"), net.ParseIP("2001:db8::10")}
	got := filterDirectCandidates(ips, outboundRoute{isDirect: true})
	require.Len(t, got, 1)
	require.Equal(t, "192.0.2.10", got[0].String())
}

func TestFilterDirectCandidatesKeepsAllForDomainDirect(t *testing.T) {
	ips := []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("203.0.113.10"), net.ParseIP("2001:db8::10")}
	got := filterDirectCandidates(ips, outboundRoute{isDirect: true, domainDirect: true})
	require.Equal(t, ips, got)
}

func TestRaceTCPDialAcceleratesAfterHardFailure(t *testing.T) {
	secondStarted := make(chan struct{}, 1)
	dial := func(ctx context.Context, target string) (net.Conn, error) {
		switch target {
		case "first":
			return nil, fmt.Errorf("network unreachable")
		case "second":
			secondStarted <- struct{}{}
			left, right := net.Pipe()
			_ = right.Close()
			return left, nil
		default:
			return nil, fmt.Errorf("unexpected target %q", target)
		}
	}

	started := time.Now()
	conn, winner, err := raceTCPDial(context.Background(), []string{"first", "second"}, dial)
	require.NoError(t, err)
	require.Equal(t, "second", winner)
	require.NotNil(t, conn)
	_ = conn.Close()
	require.Less(t, time.Since(started), happyEyeballsDelay)
	select {
	case <-secondStarted:
	default:
		t.Fatal("second candidate was never started")
	}
}

func TestRaceTCPDialReturnsFirstSuccessfulCandidate(t *testing.T) {
	dial := func(ctx context.Context, target string) (net.Conn, error) {
		if target == "slow" {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
				return nil, fmt.Errorf("too slow")
			}
		}
		left, right := net.Pipe()
		_ = right.Close()
		return left, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, winner, err := raceTCPDial(ctx, []string{"slow", "fast"}, dial)
	require.NoError(t, err)
	require.Equal(t, "fast", winner)
	_ = conn.Close()
}

// trackingConn 记录 Close 是否被调用，用于断言落败候选的连接被回收。
type trackingConn struct {
	net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *trackingConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// TestRaceTCPDialClosesLoserConnAfterWinner 钉住竞速落败者的回收契约：赢家人选
// 出来后，另一路已在途的拨号才完成并带回成功连接——无论走 goroutine 自身的
// 取消检查还是主循环的 drainLosers 兜底，该连接都必须被关闭，结果必须被消费
// （否则 fd 泄漏 + goroutine 滞留）。
func TestRaceTCPDialClosesLoserConnAfterWinner(t *testing.T) {
	loserReady := make(chan struct{})
	winnerReady := make(chan struct{})
	loserDial := make(chan struct{})
	var loser *trackingConn

	dial := func(ctx context.Context, target string) (net.Conn, error) {
		if target == "loser" {
			// 第一个发射的候选：拨号已挂起，等测试放行后才完成
			<-loserDial
			left, right := net.Pipe()
			_ = right.Close()
			loser = &trackingConn{Conn: left, closed: make(chan struct{})}
			close(loserReady)
			// 刻意不检查 ctx：模拟「检查通过后 cancel 才发生」的窄窗口
			return loser, nil
		}
		<-winnerReady
		left, right := net.Pipe()
		_ = right.Close()
		return left, nil
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// loser 在前（立即发射），winner 靠 happy-eyeballs 定时器延迟发射
		conn, winner, err := raceTCPDial(context.Background(), []string{"loser", "winner"}, dial)
		require.NoError(t, err)
		require.Equal(t, "winner", winner)
		_ = conn.Close()
	}()

	// 赢家拨号就绪 → 竞速必然以 winner 收敛并返回
	close(winnerReady)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("raceTCPDial did not return after winner dial completed")
	}

	// 主循环已返回，此刻放行落败拨号：其结果只能由 goroutine 自身的取消检查
	// 或 drainLosers 兜底消费
	close(loserDial)
	select {
	case <-loserReady:
	case <-time.After(2 * time.Second):
		t.Fatal("loser dial never completed")
	}
	select {
	case <-loser.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("loser conn was never closed (fd leak)")
	}
}
