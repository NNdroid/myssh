package myssh

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// quicNetConn 将 quic.Stream (数据流) 和 quic.Connection (底层 UDP 会话)
// 包装为标准的 net.Conn，让上层 io.Copy 能够像操作 TCP 一样操作 QUIC
type quicNetConn struct {
	*quic.Stream
	conn *quic.Conn
}

func (q *quicNetConn) LocalAddr() net.Addr  { return (*q.conn).LocalAddr() }
func (q *quicNetConn) RemoteAddr() net.Addr { return (*q.conn).RemoteAddr() }
func (q *quicNetConn) Close() error {
	// 先关闭双向数据流
	q.Stream.Close()
	// 随后关闭整个 QUIC 连接以释放底层的 UDP 资源
	return (*q.conn).CloseWithError(0, "tunnel closed by client")
}

func init() {
	RegisterTunnel("quic", "udp", func(parentCtx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		// dialTunnel 发现是 "udp" 时，根本就不会去拨号 TCP，传进来的 baseConn 直接就是 nil！

		zlog.Infof("%s [Tunnel] 准备进行 QUIC (UDP) 握手, 目标: %s, 伪装 SNI: %s", TAG, cfg.ProxyAddr, cfg.ServerName)

		tlsConf := &tls.Config{
			ServerName:            cfg.ServerName,
			InsecureSkipVerify:    true,
			NextProtos:            []string{"h3"}, // ALPN 强行伪装为 HTTP/3 流量
			VerifyPeerCertificate: MakePeerCertVerifier(cfg.VerifyCertificateFingerprint, cfg.ServerCertificateFingerprint),
		}

		quicConfig := &quic.Config{
			HandshakeIdleTimeout: 10 * time.Second,
			MaxIdleTimeout:       30 * time.Second,
			KeepAlivePeriod:      15 * time.Second, // 开启 KeepAlive 防止 UDP 洞口被 NAT 路由器提前关闭
		}

		// Dial 10s 连接超时
		dialCtx, cancel := context.WithTimeout(parentCtx, 10*time.Second)
		defer cancel()

		conn, err := quic.DialAddrEarly(dialCtx, cfg.ProxyAddr, tlsConf, quicConfig)
		if err != nil {
			zlog.Errorf("%s [Tunnel] ❌ QUIC 连接失败: %v", TAG, err)
			return nil, err
		}

		zlog.Infof("%s [Tunnel] ✅ QUIC 握手成功，准备打开数据流(Stream)", TAG)

		stream, err := conn.OpenStreamSync(parentCtx)
		if err != nil {
			conn.CloseWithError(1, "stream open error")
			zlog.Errorf("%s [Tunnel] ❌ QUIC Stream 打开失败: %v", TAG, err)
			return nil, err
		}

		zlog.Infof("%s [Tunnel] ✅ QUIC Stream 打开成功，底层 UDP 通道已打通", TAG)

		return &quicNetConn{
			Stream: stream,
			conn:   conn,
		}, nil
	})
}
