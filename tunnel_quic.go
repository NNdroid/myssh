package myssh

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// quicCacheKey identifies a QUIC connection by its network endpoint and the TLS
// identity used to establish it. The same ProxyAddr can serve several profiles
// with different SNI or pinned fingerprints; reusing a connection across
// profiles would send the wrong SNI and silently bypass the other profile's
// certificate pinning (InsecureSkipVerify is always on, so the pin lives
// entirely in the per-connection VerifyPeerCertificate).
//
// verify 必须进 key：指纹**字符串**可以相同而校验开关不同（未校验的节点留着
// 上次的指纹串是正常状态）。若只按指纹分桶，未校验的节点先拨号建连，需要校验
// 的节点命中缓存直接复用——校验发生在握手时，复用的连接等于从未校验过，pin 被
// 静默绕过，MITM 无从察觉。
type quicCacheKey struct {
	addr        string
	sni         string
	fingerprint string
	verify      bool
}

func quicCacheKeyOf(cfg ProxyConfig) quicCacheKey {
	return quicCacheKey{
		addr:        cfg.ProxyAddr,
		sni:         effectiveServerName(cfg.ServerName),
		fingerprint: cfg.ServerCertificateFingerprint,
		verify:      cfg.VerifyCertificateFingerprint,
	}
}

// 按 ProxyAddr 缓存 QUIC 连接，实现多流复用 (Multiplexing)
var quicConnCache sync.Map

// closeQuicConnCache closes all cached QUIC connections.
// The engine must call this when stopping: otherwise the QUIC connections and their
// underlying UDP sockets stay alive and keep sending KeepAlive packets, and after
// stop->start the stale connections would be wrongly reused.
func closeQuicConnCache() {
	quicConnCache.Range(func(key, value interface{}) bool {
		if conn, ok := value.(*quic.Conn); ok {
			_ = conn.CloseWithError(0, "engine stopped")
		}
		quicConnCache.Delete(key)
		return true
	})
}

type quicNetConn struct {
	*quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (q *quicNetConn) LocalAddr() net.Addr  { return q.localAddr }
func (q *quicNetConn) RemoteAddr() net.Addr { return q.remoteAddr }

func (q *quicNetConn) Close() error {
	// 只关闭当前 QUIC Stream，不影响复用的 connection
	q.CancelRead(0)         // 中止本端读
	return q.Stream.Close() // 发送 FIN 正常关闭流
	// 切勿调用 q.conn.CloseWithError()，那会断开整个复用的连接！
}

func init() {
	RegisterTunnel("quic", "udp", func(parentCtx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {

		zlog.Infof("%s [Tunnel] 2. Preparing QUIC (UDP) handshake, Target: %s, Spoofed SNI: %s", TAG, cfg.ProxyAddr, cfg.ServerName)

		// 必须是 net.PacketConn，不能是具体的 *net.UDPConn：dialTunnel 已把 UDP 连接
		// 包进 ctxCloseConn（随引擎 ctx 取消而关闭），具体类型断言在这里必然失败。
		// 之前 QUIC 因此完全不可用，且报错含 "requires a " 会命中 isPermanentConfigError，
		// 引擎直接判定为配置错误、永久放弃重连。quic.Transport.Conn 本身就是 net.PacketConn，
		// 这里放宽没有正确性问题，只是损失 OOB 的 DF/ECN 优化。
		udpConn, ok := baseConn.(net.PacketConn)
		if !ok || udpConn == nil {
			return nil, fmt.Errorf("QUIC tunnel requires a net.PacketConn, got %T", baseConn)
		}

		// ==========================================
		// 命中缓存，直接复用已有 QUIC 连接
		// ==========================================
		if cachedVal, ok := quicConnCache.Load(quicCacheKeyOf(cfg)); ok {
			conn := cachedVal.(*quic.Conn)

			// 在既有 QUIC 连接上开新 Stream
			stream, err := conn.OpenStreamSync(parentCtx)
			if err == nil {
				// 复用成功！
				// 关闭多余的 UDP 通道，保留「共享」的 udpConn 之外
				// 重复创建的 UDP Port / FD（如有）即可！
				udpConn.Close()

				zlog.Infof("%s [Tunnel] ⚡ Reused cached QUIC connection, instantly opened new Stream", TAG)
				return &quicNetConn{
					Stream:     stream,
					localAddr:  conn.LocalAddr(),
					remoteAddr: conn.RemoteAddr(),
				}, nil
			}

			// 连接已死 (可能超时)。必须 CloseWithError 释放底层 UDP socket 与
			// quic-go 收发 goroutine，再 Delete；否则它们会存活到 engine 停止，
			// 且 stop->start 后还可能被错误复用。
			//
			// 只摘走**我们自己关掉的这个** conn：并发 dial 会同时 Load 到同一个
			// 死连接，一方摘走后重拨并把新连接 Store 回同 key，此时另一个 goroutine
			// 再 Delete(key) 会把那条活连接从缓存里删掉——它既不被任何引用持有、
			// 也不在 closeQuicConnCache 的清扫范围里，UDP socket 与收发 goroutine
			// 就此成为孤儿，跨重连周期累积。
			_ = conn.CloseWithError(0, "cached QUIC connection dead")
			quicConnCache.CompareAndDelete(quicCacheKeyOf(cfg), conn)
			zlog.Warnf("%s [Tunnel] ⚠️ Cached QUIC connection dead (%v), redialing...", TAG, err)
		}

		// ==========================================
		// 未命中，新建 QUIC 连接
		// ==========================================
		udpAddr, err := net.ResolveUDPAddr("udp", cfg.ProxyAddr)
		if err != nil {
			udpConn.Close()
			return nil, err
		}

		tlsConf := &tls.Config{
			ServerName:            effectiveServerName(cfg.ServerName),
			InsecureSkipVerify:    true,
			NextProtos:            []string{"h3"}, // ALPN 固定为 HTTP/3 协议
			VerifyPeerCertificate: MakePeerCertVerifier(cfg.VerifyCertificateFingerprint, cfg.ServerCertificateFingerprint),
		}

		quicConfig := &quic.Config{
			HandshakeIdleTimeout: 10 * time.Second,
			MaxIdleTimeout:       30 * time.Second,
			KeepAlivePeriod:      15 * time.Second, // 周期 KeepAlive 防止 UDP 运营商 NAT 老化
		}

		dialCtx, cancel := context.WithTimeout(parentCtx, 10*time.Second)
		defer cancel()

		conn, err := quic.DialEarly(dialCtx, udpConn, udpAddr, tlsConf, quicConfig)
		if err != nil {
			udpConn.Close() // 失败时 cleanup 掉 Socket
			zlog.Errorf("%s [Tunnel] ❌ QUIC connection failed: %v", TAG, err)
			return nil, err
		}

		// 握手成功后，把连接放入 QUIC 缓存，供后续复用
		quicConnCache.Store(quicCacheKeyOf(cfg), conn)
		zlog.Infof("%s [Tunnel] ✅ QUIC handshake successful, preparing to open Stream", TAG)

		stream, err := conn.OpenStreamSync(parentCtx)
		if err != nil {
			// 同样是按值摘走，而不是按 key 删（见缓存命中分支的注释）。
			quicConnCache.CompareAndDelete(quicCacheKeyOf(cfg), conn)
			conn.CloseWithError(1, "stream open error")
			zlog.Errorf("%s [Tunnel] ❌ QUIC Stream open failed: %v", TAG, err)
			return nil, err
		}

		zlog.Infof("%s [Tunnel] ✅ QUIC Stream opened successfully, underlying UDP channel established", TAG)

		return &quicNetConn{
			Stream:     stream,
			localAddr:  conn.LocalAddr(),
			remoteAddr: conn.RemoteAddr(),
		}, nil
	})
}
