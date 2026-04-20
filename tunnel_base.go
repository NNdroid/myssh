package myssh

import (
	"context"
	"net"

	utls "github.com/refraction-networking/utls"
)

func init() {
	// 基础直连
	RegisterTunnel("base", "tcp", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return baseConn, nil
	})

	// TLS (利用 uTLS 消除指纹)
	RegisterTunnel("tls", "tcp", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		zlog.Infof("%s [Tunnel] 2. 准备进行 TLS (utls SNI Proxy) 握手, 伪装 SNI: %s", TAG, cfg.ServerName)

		utlsConfig := &utls.Config{
			ServerName:         cfg.ServerName,
			InsecureSkipVerify: true,
		}

		tlsConn := utls.UClient(baseConn, utlsConfig, utls.HelloChrome_Auto)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ TLS 握手失败: %v", TAG, err)
			return nil, err
		}
		zlog.Infof("%s [Tunnel] ✅ TLS (utls) 握手成功", TAG)

		go func() {
			<-ctx.Done()
			if tlsConn != nil {
				tlsConn.Close()
			}
		}()

		return tlsConn, nil
	})
}
