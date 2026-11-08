package myssh

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func ip4PAAAA(ipv4 net.IP, port int) net.IP {
	v4 := ipv4.To4()
	v6 := make(net.IP, 16)
	v6[0], v6[1] = 0x20, 0x01
	v6[10], v6[11] = byte(port>>8), byte(port)
	copy(v6[12:], v4)
	return v6
}

// ip4pTestLookup 让测试结果与错误共用同一个具体类型：atomic.Value 不允许
// 先后 Store 不同动态类型，混存 []net.IP / error 会直接 panic。
type ip4pTestLookup struct {
	ips []net.IP
	err error
}

func ip4pIPs(ips ...net.IP) ip4pTestLookup { return ip4pTestLookup{ips: ips} }
func ip4pErr(err error) ip4pTestLookup     { return ip4pTestLookup{err: err} }

func TestIP4PWatchHost(t *testing.T) {
	cases := []struct {
		name   string
		target string
		want   string
	}{
		{"host and placeholder port", "nat.example.com:0", "nat.example.com"},
		{"host without port", "nat.example.com", "nat.example.com"},
		{"url form", "https://nat.example.com:443/tunnel", "nat.example.com"},
		{"ip4p literal", "[2001::3039:102:304]:0", ""},
		{"plain ipv4", "1.2.3.4:12345", ""},
		{"plain ipv6", "[2400:cb00::1]:443", ""},
		{"empty", "  ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ip4pWatchHost(tc.target); got != tc.want {
				t.Fatalf("ip4pWatchHost(%q) = %q, want %q", tc.target, got, tc.want)
			}
		})
	}
}

func TestIP4PWatchTargetFollowsDialTunnel(t *testing.T) {
	cfg := ProxyConfig{
		TunnelType: "raw",
		ProxyAddr:  "proxy.example.com:443",
		SshAddr:    "ssh.example.com:22",
	}
	if got := ip4pWatchTarget(cfg); got != cfg.SshAddr {
		t.Fatalf("raw without TLS must watch ssh_addr, got %q", got)
	}
	cfg.TunnelTLSEnabled = true
	if got := ip4pWatchTarget(cfg); got != cfg.ProxyAddr {
		t.Fatalf("raw with TLS must watch proxy_addr, got %q", got)
	}
	cfg.TunnelType = "h3"
	if got := ip4pWatchTarget(cfg); got != cfg.ProxyAddr {
		t.Fatalf("SDK tunnel must watch proxy_addr, got %q", got)
	}
	// 空类型按 dialTunnel 的规则回落 raw。
	cfg.TunnelType = ""
	cfg.TunnelTLSEnabled = false
	if got := ip4pWatchTarget(cfg); got != cfg.SshAddr {
		t.Fatalf("empty tunnel_type must fall back to raw/ssh_addr, got %q", got)
	}
}

func TestIP4PEndpointsFromIPsIsDeterministic(t *testing.T) {
	ips := []net.IP{
		ip4PAAAA(net.IPv4(1, 2, 3, 4), 9000),
		net.ParseIP("2400:cb00::1"), // 普通 AAAA，必须忽略
		ip4PAAAA(net.IPv4(1, 2, 3, 4), 1000),
	}
	first := ip4pEndpointsFromIPs(ips)
	second := ip4pEndpointsFromIPs([]net.IP{ips[2], ips[1], ips[0]})
	if len(first) != 2 || first[0] != "1.2.3.4:1000" || first[1] != "1.2.3.4:9000" {
		t.Fatalf("unexpected endpoints: %v", first)
	}
	if second[0] != first[0] || second[1] != first[1] {
		t.Fatalf("selection depends on DNS answer order: %v vs %v", first, second)
	}
}

// newTestIP4PWatcher 组装一个可在毫秒级驱动的 watchdog；lookup 从 current
// 原子读取，测试可以随时模拟 NATMap 更新 AAAA 或 DNS 查询失败。
func newTestIP4PWatcher(current *atomic.Value, changes chan [2]string, refreshed chan []net.IP) *ip4pWatcher {
	return &ip4pWatcher{
		host:     "natmap.test.invalid",
		interval: 5 * time.Millisecond,
		lookup: func(ctx context.Context, host string) ([]net.IP, error) {
			v := current.Load().(ip4pTestLookup)
			if v.err != nil {
				return nil, v.err
			}
			return v.ips, nil
		},
		refresh: func(host string, ips []net.IP) {
			select {
			case refreshed <- ips:
			default:
			}
		},
		onChange: func(old, next string) {
			select {
			case changes <- [2]string{old, next}:
			default:
			}
		},
	}
}

func runWatcher(t *testing.T, w *ip4pWatcher) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("IP4P watchdog did not exit on ctx cancel")
		}
	})
	return cancel
}

func TestIP4PWatchdogTriggersReconnectOnEndpointChange(t *testing.T) {
	var current atomic.Value
	current.Store(ip4pIPs(ip4PAAAA(net.IPv4(1, 2, 3, 4), 1111)))
	changes := make(chan [2]string, 4)
	refreshed := make(chan []net.IP, 8)
	w := newTestIP4PWatcher(&current, changes, refreshed)

	runWatcher(t, w)

	// 等基线建立（第一次 refresh）再改记录，避免竞态把新值当成基线。
	select {
	case <-refreshed:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog never established a baseline")
	}

	current.Store(ip4pIPs(ip4PAAAA(net.IPv4(1, 2, 3, 4), 2222)))
	select {
	case c := <-changes:
		if c[0] != "1.2.3.4:1111" || c[1] != "1.2.3.4:2222" {
			t.Fatalf("unexpected change %v -> %v", c[0], c[1])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("IP4P endpoint change did not trigger a rebuild")
	}

	// fresh 结果必须写回短 TTL 缓存，否则重连时仍会拨回旧端口。
	select {
	case ips := <-refreshed:
		got := ip4pEndpointsFromIPs(ips)
		if len(got) != 1 || got[0] != "1.2.3.4:2222" {
			t.Fatalf("cache refreshed with stale data: %v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not refresh the AAAA cache")
	}
}

func TestIP4PWatchdogIgnoresDNSErrorsAndUnchangedAnswers(t *testing.T) {
	var current atomic.Value
	current.Store(ip4pIPs(ip4PAAAA(net.IPv4(1, 2, 3, 4), 1111)))
	changes := make(chan [2]string, 4)
	refreshed := make(chan []net.IP, 64)
	w := newTestIP4PWatcher(&current, changes, refreshed)

	runWatcher(t, w)
	select {
	case <-refreshed:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog never established a baseline")
	}

	// 一次 DNS 抖动绝不能断开一条健康的隧道。
	current.Store(ip4pErr(errors.New("dns timeout")))
	time.Sleep(30 * time.Millisecond)

	// 记录暂时消失也不能算「端点变了」。
	current.Store(ip4pIPs(net.ParseIP("2400:cb00::1")))
	time.Sleep(30 * time.Millisecond)

	select {
	case c := <-changes:
		t.Fatalf("spurious reconnect on DNS error / missing IP4P record: %v", c)
	default:
	}

	current.Store(ip4pIPs(ip4PAAAA(net.IPv4(1, 2, 3, 4), 3333)))
	select {
	case c := <-changes:
		if c[0] != "1.2.3.4:1111" || c[1] != "1.2.3.4:3333" {
			t.Fatalf("unexpected change %v -> %v", c[0], c[1])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not recover after DNS errors")
	}
}

func TestIP4PWatchdogRetriesBootstrapDNSError(t *testing.T) {
	var calls atomic.Int64
	var current atomic.Value
	current.Store(ip4pIPs(ip4PAAAA(net.IPv4(1, 2, 3, 4), 1111)))
	changes := make(chan [2]string, 4)
	refreshed := make(chan []net.IP, 64)
	w := newTestIP4PWatcher(&current, changes, refreshed)
	original := w.lookup
	w.lookup = func(ctx context.Context, host string) ([]net.IP, error) {
		if calls.Add(1) <= 2 {
			return nil, errors.New("network not ready")
		}
		return original(ctx, host)
	}

	runWatcher(t, w)
	select {
	case <-refreshed:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog gave up after transient bootstrap DNS failures")
	}

	current.Store(ip4pIPs(ip4PAAAA(net.IPv4(1, 2, 3, 4), 4444)))
	select {
	case <-changes:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not become active after bootstrap retries")
	}
}

func TestIP4PWatchdogExitsForNonIP4PHost(t *testing.T) {
	var current atomic.Value
	current.Store(ip4pIPs(net.ParseIP("2400:cb00::1")))
	changes := make(chan [2]string, 1)
	refreshed := make(chan []net.IP, 1)
	w := newTestIP4PWatcher(&current, changes, refreshed)
	w.interval = time.Millisecond

	done := make(chan struct{})
	go func() {
		defer close(done)
		w.run(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog must exit immediately for a non-IP4P hostname")
	}
	select {
	case <-changes:
		t.Fatal("non-IP4P host triggered a reconnect")
	default:
	}
}

func TestStoreIP6CacheFeedsDialPath(t *testing.T) {
	const host = "ip4p-cache-test.invalid"
	storeIP6Cache(host, []net.IP{ip4PAAAA(net.IPv4(5, 6, 7, 8), 8080)})
	defer func() {
		ip4pAAAACacheMu.Lock()
		delete(ip4pAAAACache, host)
		ip4pAAAACacheMu.Unlock()
	}()

	// 传入必然失败的 resolver：能拿到结果就证明走的是 watchdog 刷新的缓存，
	// 而不是又发了一次可能被上游 DNS TTL 钉住的查询。
	failing := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("must not hit the network")
		},
	}
	ips, err := lookupIP6Cached(context.Background(), failing, host)
	if err != nil {
		t.Fatalf("lookupIP6Cached: %v", err)
	}
	got := ip4pEndpointsFromIPs(ips)
	if len(got) != 1 || got[0] != "5.6.7.8:8080" {
		t.Fatalf("cached endpoints = %v, want [5.6.7.8:8080]", got)
	}
}
