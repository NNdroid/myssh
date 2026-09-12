package myssh

import (
	"context"
	"net"
)

func init() {
	// raw：合并型注册——SSH 直接跑在 TCP 上（明文，或 uTLS 伪装）。
	// TLS 开关（cfg.TunnelTLSEnabled）决定是否走 uTLS（SNI 伪装 + 证书
	// 指纹校验）。ALPN 固定为 Chrome 标准集 "h2,http/1.1"，刻意不作为配置
	// 暴露：真实 Chrome 恒发这两个协议，任何其它取值都会偏离 Chrome 的
	// ClientHello 画像（甚至可能因扩展增减而改变 JA3/JA4），削弱伪装效果。
	RegisterTunnel("raw", "tcp", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		if !cfg.TunnelTLSEnabled {
			return baseConn, nil
		}
		if !cfg.VerifyCertificateFingerprint {
			zlog.Warnf("%s [Tunnel] ⚠️ Certificate verification is DISABLED (no fingerprint pinned) — the TLS server's identity is not checked; pin a fingerprint to detect MITM", TAG)
		}
		zlog.Infof("%s [Tunnel] 2. Preparing TLS (uTLS SNI Proxy) handshake, Spoofed SNI: %s", TAG, cfg.ServerName)

		utlsConfig := buildUTLSConfig(cfg, []string{"h2", "http/1.1"})
		uConn, err := handshakeUTLS(ctx, baseConn, utlsConfig)
		if err != nil {
			zlog.Errorf("%s [Tunnel] ❌ TLS connection failed: %v", TAG, err)
			return nil, err
		}

		zlog.Infof("%s [Tunnel] ✅ TLS handshake successful", TAG)

		return watchEngineCtx(ctx, uConn), nil
	})
}
