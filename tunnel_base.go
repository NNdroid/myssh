package myssh

import (
	"context"
	"net"
)

func init() {
	// 基础直连
	RegisterTunnel("base", "tcp", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return baseConn, nil
	})

	// TLS (利用 uTLS 消除指纹)
	RegisterTunnel("tls", "tcp", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		zlog.Infof("%s [Tunnel] 2. Preparing TLS (utls SNI Proxy) handshake, Spoofed SNI: %s", TAG, cfg.ServerName)

		utlsConfig := buildUTLSConfig(cfg, nil)
		uConn, err := handshakeUTLS(ctx, baseConn, utlsConfig)
		if err != nil {
			zlog.Errorf("%s [Tunnel] ❌ TLS connection failed: %v", TAG, err)
			return nil, err
		}

		zlog.Infof("%s [Tunnel] ✅ TLS handshake successful", TAG)

		go func() {
			<-ctx.Done()
			if uConn != nil {
				uConn.Close()
			}
		}()

		return uConn, nil
	})
}
