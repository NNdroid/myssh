package myssh

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func newProtectedDialer(cfg ProxyConfig, timeout time.Duration) *net.Dialer {
	dialer := &net.Dialer{Timeout: timeout}
	if cfg.BindInterface != "" {
		zlog.Debugf("%s [Dialer] bind interface: %s", TAG, cfg.BindInterface)
		bindDevice(dialer, cfg.BindInterface)
	}
	return wrapAndroidProtect(dialer)
}

func dialProtected(ctx context.Context, cfg ProxyConfig, network, address string, timeout time.Duration) (net.Conn, error) {
	dialer := newProtectedDialer(cfg, timeout)
	matchDialerNetwork(dialer, network)
	return dialer.DialContext(ctx, network, address)
}

// Desktop interface binding selects a local TCP address; UDP dials need the
// matching address type. Linux/Android fd-based binding has no LocalAddr.
func matchDialerNetwork(dialer *net.Dialer, network string) {
	if strings.HasPrefix(network, "udp") {
		if addr, ok := dialer.LocalAddr.(*net.TCPAddr); ok {
			dialer.LocalAddr = &net.UDPAddr{IP: addr.IP, Port: addr.Port, Zone: addr.Zone}
		}
	}
}

// applyOptimiseForTcpConnection 对 TCP 连接应用套接字层优化：
// 关闭 Nagle（SetNoDelay，降低 SSH/交互流量的首包延迟）、
// 默认保留系统缓冲、keepalive 15s。
func applyOptimiseForTcpConnection(conn net.Conn) {
	applyTCPConfig(conn, ProxyConfig{})
}

func applyTCPConfig(conn net.Conn, cfg ProxyConfig) {
	// 底层 net.Conn 不一定是 *net.TCPConn
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		// 关闭 Nagle 算法
		if err := tcpConn.SetNoDelay(true); err != nil {
			zlog.Warnf("%s [TCP Tune] Failed to set NoDelay: %v", TAG, err)
		}

		// 读缓冲
		if cfg.TcpBufferKB > 0 {
			if err := tcpConn.SetReadBuffer(cfg.TcpBufferKB * 1024); err != nil {
				zlog.Warnf("%s [TCP Tune] Failed to set ReadBuffer: %v", TAG, err)
			}

			// 写缓冲
			if err := tcpConn.SetWriteBuffer(cfg.TcpBufferKB * 1024); err != nil {
				zlog.Warnf("%s [TCP Tune] Failed to set WriteBuffer: %v", TAG, err)
			}
		}

		// 启用 TCP Keep-Alive
		if err := tcpConn.SetKeepAlive(true); err != nil {
			zlog.Warnf("%s [TCP Tune] Failed to enable KeepAlive: %v", TAG, err)
		} else {
			// keepalive 探测间隔 15 秒
			if err := tcpConn.SetKeepAlivePeriod(time.Duration(tcpKeepaliveIntervalSec) * time.Second); err != nil {
				zlog.Warnf("%s [TCP Tune] Failed to set KeepAlive period: %v", TAG, err)
			}
		}

		zlog.Debugf("%s [TCP Tune] NoDelay, KeepAlive; configured buffer=%dKB (0=OS default)", TAG, cfg.TcpBufferKB)
	} else {
		zlog.Debugf("%s [TCP Tune] ⚠️ Current connection is not TCP, skipping optimization", TAG)
	}
}

// dialSocket is the unified entry point for creating all underlying sockets.
// It handles timeouts and interface binding.
func dialSocket(ctx context.Context, cfg ProxyConfig, network, address string) (net.Conn, error) {
	zlog.Debugf("%s [Dialer] 🎬 Starting dial (network=%s, address=%s)", TAG, network, address)

	dialer := &net.Dialer{Timeout: 10 * time.Second}

	// Apply interface binding if specified in the config.
	if cfg.BindInterface != "" {
		zlog.Debugf("%s [Dialer] 🌐 Attempting to bind to specified network interface: %s", TAG, cfg.BindInterface)
		bindDevice(dialer, cfg.BindInterface)
	} else {
		zlog.Debugf("%s [Dialer] 🌐 No bind interface specified, using default routing", TAG)
	}

	//
	// IP4P resolution.
	//
	// Must happen BEFORE DialContext because standard net.Dialer cannot
	// extract/replace the port encoded inside an IP4P AAAA record.
	//
	resolvedAddress, ip4p, err := resolveIP4PDialAddress(
		ctx,
		dialer,
		network,
		address,
	)
	if err != nil {
		zlog.Errorf(
			"%s [Dialer] ❌ IP4P resolution failed for %s: %v",
			TAG,
			address,
			err,
		)
		return nil, err
	}

	if ip4p {
		zlog.Infof(
			"%s [Dialer] 🧩 IP4P resolved: %s -> %s",
			TAG,
			address,
			resolvedAddress,
		)

		address = resolvedAddress
	}

	// Apply Android VpnService Protect.
	safeDialer := wrapAndroidProtect(dialer)
	// Apply SO_MARK for tproxy bypass（Android 有效，其它平台为空实现）。
	// 与 protect 并联：protect 解决 VPN 模式的回环，mark 解决 tproxy 模式的回环。
	// 两者都要在 DialContext 之前挂上 —— Control 回调在 socket 创建后、connect 前触发。
	markDialer := wrapSocketMark(safeDialer)
	matchDialerNetwork(markDialer, network)

	zlog.Debugf("%s [Dialer] 📞 Executing DialContext...", TAG)
	conn, err := markDialer.DialContext(ctx, network, address)
	if err != nil {
		zlog.Errorf("%s [Socket] ❌ Underlying %s connection failed: %v", TAG, strings.ToUpper(network), err)
		return nil, err
	}
	zlog.Infof("%s [Socket] ✅ Underlying %s connection established successfully: %s", TAG, strings.ToUpper(network), address)

	return conn, nil
}

// dialTCP is a wrapper for creating a TCP socket.
func dialTCP(ctx context.Context, cfg ProxyConfig, target string) (net.Conn, error) {
	tcpConn, err := dialSocket(ctx, cfg, "tcp", target)
	if err != nil {
		return nil, err
	}
	applyTCPConfig(tcpConn, cfg)
	return tcpConn, nil
}

// dialUDP is a wrapper for creating a UDP socket.
func dialUDP(ctx context.Context, cfg ProxyConfig, target string) (net.Conn, error) {
	return dialSocket(ctx, cfg, "udp", target)
}

// ctxCloseConn 在引擎 ctx 取消时关闭底层连接，同时保证连接被正常关闭后
// 监视 goroutine 立即退出——否则每次拨号都会留下一个等到引擎停止才退出的
// goroutine，断线重连循环期间会持续累积。
type ctxCloseConn struct {
	net.Conn
	closeCh chan struct{}
	once    sync.Once
}

func (c *ctxCloseConn) Close() error {
	c.once.Do(func() { close(c.closeCh) })
	return c.Conn.Close()
}

// ReadFrom / WriteTo 必须显式代理，不能靠嵌入提升。
//
// 后果很具体：ctxCloseConn 内嵌的是 net.Conn 接口，promoted surface 里没有
// ReadFrom/WriteTo，所以它不满足 net.PacketConn。而 quic 与 kcptun 都注册为
// "udp" 网络——dialTunnel 先给出 *net.UDPConn，紧接着就被 watchEngineCtx 包一层，
// handler 里的 `baseConn.(*net.UDPConn)` / `baseConn.(net.PacketConn)` 断言必然失败。
// QUIC 与 KCP 因此完全无法工作；更糟的是报错文案含 "requires a "，正好命中
// engine.go 的 isPermanentConfigError，引擎会当成配置错误**永久放弃重连**。
func (c *ctxCloseConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if pc, ok := c.Conn.(net.PacketConn); ok {
		return pc.ReadFrom(p)
	}
	return 0, nil, fmt.Errorf("ctxCloseConn: ReadFrom on non-packet conn %T", c.Conn)
}

func (c *ctxCloseConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if pc, ok := c.Conn.(net.PacketConn); ok {
		return pc.WriteTo(b, addr)
	}
	return 0, fmt.Errorf("ctxCloseConn: WriteTo on non-packet conn %T", c.Conn)
}

// watchEngineCtx 包装 conn，使其随引擎 ctx 取消而关闭。
func watchEngineCtx(ctx context.Context, conn net.Conn) net.Conn {
	c := &ctxCloseConn{Conn: conn, closeCh: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Conn.Close()
		case <-c.closeCh:
		}
	}()
	return c
}

// dialTunnel 按 tunnel 类型查注册表，先建立底层连接再交给对应 handler 完成协议握手。
func dialTunnel(ctx context.Context, cfg ProxyConfig) (net.Conn, error) {
	tunnelType := strings.ToLower(cfg.TunnelType)
	if tunnelType == "" {
		tunnelType = "raw"
	}

	proto, exists := tunnelRegistry[tunnelType]
	if !exists {
		return nil, fmt.Errorf("unsupported tunnel type: %s", tunnelType)
	}

	target := cfg.ProxyAddr
	// raw模式且未开启tls则是纯SSH
	if tunnelType == "raw" && !cfg.TunnelTLSEnabled {
		target = cfg.SshAddr
	}

	zlog.Infof("%s [Tunnel] 1. Preparing to establish underlying connection, Target: %s, Mode: %s, Network requirement: %s", TAG, target, tunnelType, proto.Network)

	var baseConn net.Conn
	var err error

	//  info
	switch proto.Network {
	case "tcp":
		baseConn, err = dialTCP(ctx, cfg, target)
	case "udp":
		baseConn, err = dialUDP(ctx, cfg, target)
	case "custom":
		zlog.Infof("%s [Tunnel] ⚡ Underlying dialing taken over by protocol (on-demand lazy loading)", TAG)
		baseConn = nil
	default:
		baseConn = nil
	}

	// 底层连接建立失败时直接报错，不再交给 Handler
	if err != nil {
		return nil, err
	}

	// 把 baseConn 交给对应 tunnel handler 完成协议握手 (例如 HTTP/3, WebSocket, Base SSH 等场景)
	if baseConn != nil {
		baseConn = watchEngineCtx(ctx, baseConn)
	}
	targetConn, err := proto.Handler(ctx, cfg, baseConn)
	if err != nil && baseConn != nil {
		baseConn.Close()
	}
	if err == nil {
		//if Debug {
		//	targetConn = &DumpConn{Conn: targetConn, Prefix: "Client Local - Android"}
		//}
	}

	return targetConn, err
}

// DialNode is the unified function for establishing a tunnel and an SSH connection
func DialNode(ctx context.Context, cfg ProxyConfig, isPing bool) (*ssh.Client, net.Conn, error) {
	if err := validatePerformanceConfig(cfg); err != nil {
		return nil, nil, err
	}
	conn, err := dialTunnel(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("tunnel err: %v", err)
	}

	client, err := dialSSH(ctx, conn, cfg, isPing)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("ssh err: %v", err)
	}
	return client, conn, nil
}

// decodeIP4PIP reports whether ip is a NATMap IP4P literal and, if so, the
// encoded IPv4 address and port.
//
// IP4P packs an IPv4 address plus port into an IPv6 literal under the
// 2001::/80 prefix: 2001::<port>:<ipv4>, e.g. 2001::3039:102:304 =
// 1.2.3.4:12345. Only the first 10 bytes are fixed, so validation is a prefix
// check plus a zero check on bytes 2-9.
func decodeIP4PIP(ip net.IP) (net.IP, uint16, bool) {
	v6 := ip.To16()
	if v6 == nil || v6[0] != 0x20 || v6[1] != 0x01 {
		return nil, 0, false
	}
	for i := 2; i < 10; i++ {
		if v6[i] != 0 {
			return nil, 0, false
		}
	}
	port := binary.BigEndian.Uint16(v6[10:12])
	return net.IPv4(v6[12], v6[13], v6[14], v6[15]), port, true
}

// resolveIP4PDialAddress checks whether address is an IP4P literal or whether
// its hostname has an IP4P AAAA record.
//
// If IP4P is found:
//
//	example.com:0
//	    ↓ AAAA
//	2001::3039:102:304
//	    ↓
//	1.2.3.4:12345
//
// If no IP4P record exists, the original address is returned unchanged so
// net.Dialer can continue using the normal DNS resolution path.
func resolveIP4PDialAddress(
	ctx context.Context,
	dialer *net.Dialer,
	network string,
	address string,
) (string, bool, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// Let net.Dialer handle malformed/non-host:port addresses later.
		return address, false, nil
	}

	//
	// 1. address itself may already contain an IP4P literal:
	//
	//    [2001::3039:102:304]:0
	//
	if ip := net.ParseIP(host); ip != nil {
		ipv4, port, ok := decodeIP4PIP(ip)
		if !ok {
			return address, false, nil
		}

		if network == "tcp6" || network == "udp6" {
			return "", false, fmt.Errorf(
				"IP4P resolves to IPv4 and cannot be used with network %q",
				network,
			)
		}

		return net.JoinHostPort(
			ipv4.String(),
			strconv.Itoa(int(port)),
		), true, nil
	}

	//
	// 2. Hostname: explicitly query AAAA.
	//
	// Use the Dialer's resolver when configured, otherwise use Go's default
	// resolver. This keeps behavior consistent with net.Dialer as much as
	// possible.
	resolver := dialer.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	ips, err := resolver.LookupIP(ctx, "ip6", host)
	if err != nil {
		// IMPORTANT:
		// Failure to obtain AAAA does NOT mean dialing must fail.
		//
		// There may still be a normal A record, so return the original address
		// and let net.Dialer perform its normal resolution.
		return address, false, nil
	}

	for _, ip := range ips {
		ipv4, port, ok := decodeIP4PIP(ip)
		if !ok {
			continue
		}

		if network == "tcp6" || network == "udp6" {
			return "", false, fmt.Errorf(
				"IP4P resolves to IPv4 and cannot be used with network %q",
				network,
			)
		}

		return net.JoinHostPort(
			ipv4.String(),
			strconv.Itoa(int(port)),
		), true, nil
	}

	// No IP4P AAAA found.
	return address, false, nil
}
