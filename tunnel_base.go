package myssh

import (
	"net"

	utls "github.com/refraction-networking/utls"
)

func init() {
	// 1. 基础直连
	RegisterTunnel("base", "tcp", func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return baseConn, nil
	})

	// 2. TLS (利用 uTLS 消除指纹)
	RegisterTunnel("tls", "tcp", func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		zlog.Infof("%s [Tunnel] 2. 准备进行 TLS (utls SNI Proxy) 握手, 伪装 Host: %s", TAG, cfg.CustomHost)
		
		utlsConfig := &utls.Config{
			ServerName:         cfg.CustomHost,
			InsecureSkipVerify: true,
		}

		tlsConn := utls.UClient(baseConn, utlsConfig, utls.HelloChrome_Auto)
		if err := tlsConn.Handshake(); err != nil {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ TLS 握手失败: %v", TAG, err)
			return nil, err
		}
		zlog.Infof("%s [Tunnel] ✅ TLS (utls) 握手成功", TAG)
		return tlsConn, nil
	})
}