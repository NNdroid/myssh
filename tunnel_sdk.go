package myssh

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

type sdkOwnedConn struct {
	net.Conn
	closeOnce sync.Once
	closeFn   func() error
}

func ownSDKConn(conn net.Conn, closeFn func() error) net.Conn {
	if closeFn == nil {
		return conn
	}
	return &sdkOwnedConn{Conn: conn, closeFn: closeFn}
}

func (c *sdkOwnedConn) Close() error {
	connErr := c.Conn.Close()
	var ownerErr error
	c.closeOnce.Do(func() { ownerErr = c.closeFn() })
	return errors.Join(connErr, ownerErr)
}

func sdkProxyEndpoint(cfg ProxyConfig, scheme, defaultPath string) (string, string, error) {
	raw := strings.TrimSpace(cfg.ProxyAddr)
	if raw == "" {
		return "", "", errors.New("proxy_addr is required")
	}
	if !strings.Contains(raw, "://") {
		raw = scheme + "://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("invalid proxy_addr %q", cfg.ProxyAddr)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
	if u.Scheme != scheme {
		return "", "", fmt.Errorf("tunnel %s requires a %s endpoint", cfg.TunnelType, scheme)
	}
	path := strings.TrimSpace(cfg.CustomPath)
	if path == "" && u.Path != "" && u.Path != "/" {
		path = u.EscapedPath()
	}
	if path == "" {
		path = defaultPath
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u.Path = ""
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/"), path, nil
}

func sdkTCPDialer(cfg ProxyConfig) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := newProtectedDialer(cfg, 10*time.Second).DialContext(ctx, network, address)
		if err == nil {
			applyOptimiseForTcpConnection(conn)
		}
		return conn, err
	}
}

func sdkQUICDialer(cfg ProxyConfig) func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
		remote, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return nil, err
		}
		pc, err := rangeListenConfig(cfg).ListenPacket(ctx, "udp", ":0")
		if err != nil {
			return nil, err
		}
		conn, err := quic.DialEarly(ctx, pc, remote, tlsConfig, quicConfig)
		if err != nil {
			_ = pc.Close()
			return nil, err
		}
		go func() {
			<-conn.Context().Done()
			_ = pc.Close()
		}()
		return conn, nil
	}
}

// sdkTLSConfig 构造 SDK 侧 TLS 配置：证书校验完全依赖指纹锁定
// （InsecureSkipVerify 恒为 true，由 VerifyPeerCertificate 里的指纹比对兜底）。
func sdkTLSConfig(cfg ProxyConfig) *tls.Config {
	return &tls.Config{
		ServerName:            strings.TrimSpace(cfg.ServerName),
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: MakePeerCertVerifier(cfg.VerifyCertificateFingerprint, cfg.ServerCertificateFingerprint),
	}
}

// warnWeakPSK 弱预共享密钥告警：UDP/ICMP 载体的 PSK 可被在线爆破
// （icmp_custom 的文档明确点名），16 字符以下的高熵不足在保存/拨号时
// 就应当被看见。只告警不拒绝——避免破坏已部署的短密钥。
func warnWeakPSK(source, psk string) {
	trimmed := strings.TrimSpace(psk)
	if trimmed != "" && len(trimmed) < 16 {
		zlog.Warnf("%s [Tunnel] ⚠️ %s PSK is only %d characters — short PSKs are brute-forceable online; use a high-entropy secret (16+ chars)", TAG, source, len(trimmed))
	}
}

func sdkCertificateFingerprint(cfg ProxyConfig) string {
	if !cfg.VerifyCertificateFingerprint {
		return ""
	}
	return strings.TrimSpace(cfg.ServerCertificateFingerprint)
}

func normalizeXHTTPALPN(value string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(value)), ",")
	first := ""
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if first == "" {
			first = part
		}
	}
	switch first {
	case "", "auto":
		return "auto"
	case "h3":
		if len(parts) > 1 {
			return "auto"
		}
		return "h3"
	case "h2":
		return "h2"
	case "h1", "http/1.1":
		return "h1"
	default:
		return "auto"
	}
}
