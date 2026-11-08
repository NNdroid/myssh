package myssh

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// IP4P 端点变化检测周期。与 ip4pAAAACacheTTL 对齐：NATMap 重新打洞后 AAAA
// 记录里的端口会变，30s 内主动发现并重建隧道，而不是干等 keepalive 超时。
//
// 注意检测能否奏效取决于 AAAA 记录的 TTL / Android netd 的 DNS 缓存：
// watchdog 每次都直接向系统解析器发一次查询（绕过 ip4pAAAACache），但绕不过
// 上游缓存。TTL 明显高于 30s 时，感知会相应推迟到缓存过期。
const (
	ip4pWatchInterval       = 30 * time.Second
	ip4pWatchLookupTimeout  = 3 * time.Second
	ip4pWatchBootstrapRetry = 3
)

// ip4pWatchHost 从拨号目标里提取需要监视的主机名。
//
// 只有「域名 + IP4P AAAA」形态才可能自己变化；IP4P 字面量和普通 IP 都是
// 静态配置，改动必然走 Stop/Start，不需要后台检测。
func ip4pWatchHost(target string) string {
	raw := strings.TrimSpace(target)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		raw = u.Host
	}
	host := raw
	if h, _, err := net.SplitHostPort(raw); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	return host
}

// ip4pWatchTarget 与 dialTunnel 选择底层拨号目标的规则保持一致：raw 且未开
// TLS 时走 ssh_addr，其余走 proxy_addr。监视错地址等于白查。
func ip4pWatchTarget(cfg ProxyConfig) string {
	// 与 dialTunnel 一致：空 tunnel_type 视作 raw。
	tunnelType := strings.ToLower(strings.TrimSpace(cfg.TunnelType))
	if (tunnelType == "" || tunnelType == "raw") && !cfg.TunnelTLSEnabled {
		return cfg.SshAddr
	}
	return cfg.ProxyAddr
}

// ip4pWatcher 周期比对域名当前的 IP4P 端点。lookup / refresh / onChange 都是
// 注入点，便于在测试里用假 DNS 驱动整个状态机而不触网、不碰真实引擎。
type ip4pWatcher struct {
	host     string
	interval time.Duration
	lookup   func(context.Context, string) ([]net.IP, error)
	refresh  func(string, []net.IP)
	onChange func(oldEndpoint, newEndpoint string)
}

// lookupEndpoint 做一次 fresh 查询并把结果写回短 TTL 缓存。
// 返回 ("", nil) 表示「确证不是 IP4P 节点」；返回 error 表示这次 DNS 查询失败，
// 调用方必须保持现状、绝不能据此断开连接。
func (w *ip4pWatcher) lookupEndpoint(ctx context.Context) (string, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, ip4pWatchLookupTimeout)
	defer cancel()

	ips, err := w.lookup(lookupCtx, w.host)
	if err != nil {
		return "", err
	}
	// 拨号路径（lookupIP6Cached）会读这份缓存。用 fresh 结果覆盖，重连时才
	// 不会又拨回已被 NATMap 淘汰的旧端口、白等一个 30s TTL + 3s 重试循环。
	w.refresh(w.host, ips)

	endpoints := ip4pEndpointsFromIPs(ips)
	if len(endpoints) == 0 {
		return "", nil
	}
	return endpoints[0], nil
}

// run 先建立基线，再周期比对。普通域名节点在首次确证后就退出，不留常驻
// goroutine；只有真正解出 IP4P 的节点才会一直驻留到引擎停止。
func (w *ip4pWatcher) run(ctx context.Context) {
	var baseline string
	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			return
		}
		endpoint, err := w.lookupEndpoint(ctx)
		if err == nil {
			baseline = endpoint
			break
		}
		// 启动时 DNS 可能尚未就绪，给几次机会；普通域名节点不会走到这里
		//（查询成功但无 IP4P 记录时 err == nil，直接跳出）。
		if attempt >= ip4pWatchBootstrapRetry || !waitRetry(ctx, w.interval) {
			return
		}
	}
	if baseline == "" {
		zlog.Debugf("%s [IP4P] No IP4P AAAA for %s; watchdog disabled", TAG, w.host)
		return
	}
	zlog.Infof("%s [IP4P] 🧩 Watching %s, current endpoint %s (every %s)", TAG, w.host, baseline, w.interval)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current, err := w.lookupEndpoint(ctx)
			if err != nil || current == "" || current == baseline {
				// 查询失败、记录暂时消失、端点未变：一次 DNS 抖动不能断流。
				continue
			}
			old := baseline
			baseline = current
			w.onChange(old, current)
		}
	}
}

// startIP4PWatchdog 在引擎启动时挂上 IP4P 端点监视。非域名目标直接返回，
// 不产生任何额外 DNS 流量或常驻 goroutine。
func startIP4PWatchdog(ctx context.Context, cfg ProxyConfig) {
	host := ip4pWatchHost(ip4pWatchTarget(cfg))
	if host == "" {
		return
	}

	w := &ip4pWatcher{
		host:     host,
		interval: ip4pWatchInterval,
		lookup: func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip6", host)
		},
		refresh: storeIP6Cache,
		onChange: func(oldEndpoint, newEndpoint string) {
			zlog.Warnf("%s [IP4P] 🧩 Endpoint changed %s -> %s, rebuilding the tunnel immediately", TAG, oldEndpoint, newEndpoint)
			// quicConnCache 的 key 含解析后的 IPv4:port，端点一变旧 key 就永远
			// 不会再被命中；不主动清，旧 *quic.Conn 会继续发 keepalive 并占着
			// UDP socket，每变一次端口就累积一条。
			closeQuicConnCache()
			// client.Wait() 立即返回，AutoSSH 走正常重连路径，届时会用刚刷新
			// 的 AAAA 缓存解出新端点。不要在这里直接拨号。
			dropCurrentSSHSession(fmt.Sprintf("🧩 IP4P endpoint changed to %s", newEndpoint))
		},
	}

	taskTrack()
	go func() {
		defer taskRelease()
		w.run(ctx)
	}()
}
