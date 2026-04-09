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
	quic.Stream
	conn quic.Connection
}

func (q *quicNetConn) LocalAddr() net.Addr  { return q.conn.LocalAddr() }
func (q *quicNetConn) RemoteAddr() net.Addr { return q.conn.RemoteAddr() }
func (q *quicNetConn) Close() error {
	// 先关闭双向数据流
	q.Stream.Close()
	// 随后关闭整个 QUIC 连接以释放底层的 UDP 资源
	return q.conn.CloseWithError(0, "tunnel closed by client")
}

func init() {
	RegisterTunnel("quic", func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		// ⚠️ 核心处理：QUIC 跑在 UDP 上。
		// 父级函数 dialTunnel 传进来的 baseConn 是 TCP 的，直接关掉它，避免浪费连接。
		if baseConn != nil {
			baseConn.Close()
		}

		zlog.Infof("%s [Tunnel] 2. 准备进行 QUIC (UDP) 握手, 目标: %s, 伪装 Host: %s", TAG, cfg.ProxyAddr, cfg.CustomHost)

		// 注意：quic-go 目前无法直接与 utls 深度结合。
		// 但 QUIC 本身的报文特征与 TCP TLS 完全不同，使用标准库的 tls 伪装成 HTTP/3 即可。
		tlsConf := &tls.Config{
			ServerName:         cfg.CustomHost,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"}, // ALPN 强行伪装为 HTTP/3 流量
		}

		quicConfig := &quic.Config{
			HandshakeIdleTimeout: 10 * time.Second,
			MaxIdleTimeout:       30 * time.Second,
			KeepAlivePeriod:      15 * time.Second, // 开启 KeepAlive 防止 UDP 洞口被 NAT 路由器提前关闭
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// 1. 发起 QUIC 连接 (底层会自动建立 UDP 会话并完成 TLS 1.3 握手)
		conn, err := quic.DialAddr(ctx, cfg.ProxyAddr, tlsConf, quicConfig)
		if err != nil {
			zlog.Errorf("%s [Tunnel] ❌ QUIC 连接失败: %v", TAG, err)
			return nil, err
		}

		zlog.Infof("%s [Tunnel] ✅ QUIC 握手成功，准备打开数据流(Stream)", TAG)

		// 2. 在 QUIC 连接上打开一个同步的双向数据流
		stream, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			conn.CloseWithError(1, "stream open error")
			zlog.Errorf("%s [Tunnel] ❌ QUIC Stream 打开失败: %v", TAG, err)
			return nil, err
		}

		zlog.Infof("%s [Tunnel] ✅ QUIC Stream 打开成功，底层 UDP 通道已打通", TAG)

		// 3. 包装并返回，完美接入现有的 SSH 代理流程
		return &quicNetConn{
			Stream: stream,
			conn:   conn,
		}, nil
	})
}