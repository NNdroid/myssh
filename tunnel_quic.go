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

// 全域 QUIC 連線快取，實現真正的多工複用 (Multiplexing)
var quicConnCache sync.Map

type quicNetConn struct {
	*quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (q *quicNetConn) LocalAddr() net.Addr  { return q.localAddr }
func (q *quicNetConn) RemoteAddr() net.Addr { return q.remoteAddr }

func (q *quicNetConn) Close() error {
	// 完整關閉 QUIC Stream 的雙向通道，並釋放記憶體
	q.CancelRead(0)         // 強制停止讀取並釋放接收緩衝區
	return q.Stream.Close() // 發送 FIN 關閉寫入端
	// 絕對不可呼叫 q.conn.CloseWithError()，因為底層連線要留給其他 Stream 繼續共用！
}

func init() {
	RegisterTunnel("quic", "udp", func(parentCtx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {

		zlog.Infof("%s [Tunnel] 2. Preparing QUIC (UDP) handshake, Target: %s, Spoofed SNI: %s", TAG, cfg.ProxyAddr, cfg.ServerName)

		udpConn, ok := baseConn.(*net.UDPConn)
		if !ok || udpConn == nil {
			return nil, fmt.Errorf("QUIC tunnel requires a valid *net.UDPConn, got %T", baseConn)
		}

		// ==========================================
		// 快取攔截，嘗試複用已建立的 QUIC 連線
		// ==========================================
		if cachedVal, ok := quicConnCache.Load(cfg.ProxyAddr); ok {
			conn := cachedVal.(quic.Conn)

			// 嘗試在現有的 QUIC 連線上開啟新的輕量級 Stream
			stream, err := conn.OpenStreamSync(parentCtx)
			if err == nil {
				// 命中快取且開啟成功！
				// 因為我們複用了舊的 UDP 通道，所以框架剛才傳進來的這個「全新」udpConn 已經沒用了
				// 必須立刻關閉它，否則會造成嚴重的 UDP Port / FD (檔案描述符) 洩漏！
				udpConn.Close()

				zlog.Infof("%s [Tunnel] ⚡ Reused cached QUIC connection, instantly opened new Stream", TAG)
				return &quicNetConn{
					Stream:     stream,
					localAddr:  conn.LocalAddr(),
					remoteAddr: conn.RemoteAddr(),
				}, nil
			}

			// 如果開啟失敗 (例如伺服器端閒置超時斷開了)，將其從快取剔除，繼續往下重新撥號
			quicConnCache.Delete(cfg.ProxyAddr)
			zlog.Warnf("%s [Tunnel] ⚠️ Cached QUIC connection dead (%v), redialing...", TAG, err)
		}

		// ==========================================
		// 冷啟動，建立全新的 QUIC 連線
		// ==========================================
		udpAddr, err := net.ResolveUDPAddr("udp", cfg.ProxyAddr)
		if err != nil {
			udpConn.Close()
			return nil, err
		}

		tlsConf := &tls.Config{
			ServerName:            cfg.ServerName,
			InsecureSkipVerify:    true,
			NextProtos:            []string{"h3"}, // ALPN 強行偽裝為 HTTP/3 流量
			VerifyPeerCertificate: MakePeerCertVerifier(cfg.VerifyCertificateFingerprint, cfg.ServerCertificateFingerprint),
		}

		quicConfig := &quic.Config{
			HandshakeIdleTimeout: 10 * time.Second,
			MaxIdleTimeout:       30 * time.Second,
			KeepAlivePeriod:      15 * time.Second, // 開啟 KeepAlive 防止 UDP 洞口被 NAT 路由器提前關閉
		}

		dialCtx, cancel := context.WithTimeout(parentCtx, 10*time.Second)
		defer cancel()

		conn, err := quic.DialEarly(dialCtx, udpConn, udpAddr, tlsConf, quicConfig)
		if err != nil {
			udpConn.Close() // 握手失敗，清理底層的物理 Socket
			zlog.Errorf("%s [Tunnel] ❌ QUIC connection failed: %v", TAG, err)
			return nil, err
		}

		// 成功撥號後，將這個實體 QUIC 連線存入全域快取，供後續數千個代理請求共用
		quicConnCache.Store(cfg.ProxyAddr, conn)
		zlog.Infof("%s [Tunnel] ✅ QUIC handshake successful, preparing to open Stream", TAG)

		stream, err := conn.OpenStreamSync(parentCtx)
		if err != nil {
			quicConnCache.Delete(cfg.ProxyAddr)
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
