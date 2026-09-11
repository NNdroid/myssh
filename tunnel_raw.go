package myssh

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// rawALPN 解析 raw 隧道 TLS 模式的 ALPN 选项：空 = 不设置；
// h1/http/1.1 与 h2 是 TCP 上合法的伪装取值；h3 只存在于 UDP/QUIC，
// 在 TCP 的 TLS 里广告它语义为空，直接拒绝以免误配。
func rawALPN(value string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return nil, nil
	case "h1", "http/1.1":
		return []string{"http/1.1"}, nil
	case "h2":
		return []string{"h2"}, nil
	default:
		return nil, fmt.Errorf("alpn %q is not valid for the raw tunnel (want empty, h1 or h2; h3 requires the quic transport)", value)
	}
}

func init() {
	// raw：合并型注册——SSH 直接跑在 TCP 上（明文，或 uTLS 伪装）。
	// TLS 开关决定是否走 uTLS（SNI 伪装 + 证书指纹校验），可选 ALPN
	// 进一步伪装成浏览器流量；明文模式 ALPN 无意义。
	RegisterTunnel("raw", "tcp", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		if !cfg.TunnelTLSEnabled {
			return baseConn, nil
		}
		alpn, err := rawALPN(cfg.Alpn)
		if err != nil {
			baseConn.Close()
			return nil, err
		}
		if !cfg.VerifyCertificateFingerprint {
			zlog.Warnf("%s [Tunnel] ⚠️ Certificate verification is DISABLED (no fingerprint pinned) — the TLS server's identity is not checked; pin a fingerprint to detect MITM", TAG)
		}
		zlog.Infof("%s [Tunnel] 2. Preparing TLS (utls SNI Proxy) handshake, Spoofed SNI: %s, ALPN: %v", TAG, cfg.ServerName, alpn)

		utlsConfig := buildUTLSConfig(cfg, alpn)
		uConn, err := handshakeUTLS(ctx, baseConn, utlsConfig)
		if err != nil {
			zlog.Errorf("%s [Tunnel] ❌ TLS connection failed: %v", TAG, err)
			return nil, err
		}

		zlog.Infof("%s [Tunnel] ✅ TLS handshake successful", TAG)

		return watchEngineCtx(ctx, uConn), nil
	})
}
