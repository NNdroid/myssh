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

// info  QUIC  info ， info  (Multiplexing)
var quicConnCache sync.Map

type quicNetConn struct {
	*quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (q *quicNetConn) LocalAddr() net.Addr  { return q.localAddr }
func (q *quicNetConn) RemoteAddr() net.Addr { return q.remoteAddr }

func (q *quicNetConn) Close() error {
	//  info  QUIC Stream  info channel， info
	q.CancelRead(0)         //  info
	return q.Stream.Close() //  info  FIN  info
	//  info  q.conn.CloseWithError()， info  Stream  info ！
}

func init() {
	RegisterTunnel("quic", "udp", func(parentCtx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {

		zlog.Infof("%s [Tunnel] 2. Preparing QUIC (UDP) handshake, Target: %s, Spoofed SNI: %s", TAG, cfg.ProxyAddr, cfg.ServerName)

		udpConn, ok := baseConn.(*net.UDPConn)
		if !ok || udpConn == nil {
			return nil, fmt.Errorf("QUIC tunnel requires a valid *net.UDPConn, got %T", baseConn)
		}

		// ==========================================
		//  info ， info  QUIC  info
		// ==========================================
		if cachedVal, ok := quicConnCache.Load(cfg.ProxyAddr); ok {
			conn := cachedVal.(*quic.Conn)

			//  info  QUIC  info  Stream
			stream, err := conn.OpenStreamSync(parentCtx)
			if err == nil {
				//  info successfully！
				//  info  UDP channel， info 「 info 」udpConn  info
				//  info ， info  UDP Port / FD ( info )  info ！
				udpConn.Close()

				zlog.Infof("%s [Tunnel] ⚡ Reused cached QUIC connection, instantly opened new Stream", TAG)
				return &quicNetConn{
					Stream:     stream,
					localAddr:  conn.LocalAddr(),
					remoteAddr: conn.RemoteAddr(),
				}, nil
			}

			//  info  ( info )， info ， info
			quicConnCache.Delete(cfg.ProxyAddr)
			zlog.Warnf("%s [Tunnel] ⚠️ Cached QUIC connection dead (%v), redialing...", TAG, err)
		}

		// ==========================================
		//  info ， info  QUIC  info
		// ==========================================
		udpAddr, err := net.ResolveUDPAddr("udp", cfg.ProxyAddr)
		if err != nil {
			udpConn.Close()
			return nil, err
		}

		tlsConf := &tls.Config{
			ServerName:            cfg.ServerName,
			InsecureSkipVerify:    true,
			NextProtos:            []string{"h3"}, // ALPN  info  HTTP/3  info
			VerifyPeerCertificate: MakePeerCertVerifier(cfg.VerifyCertificateFingerprint, cfg.ServerCertificateFingerprint),
		}

		quicConfig := &quic.Config{
			HandshakeIdleTimeout: 10 * time.Second,
			MaxIdleTimeout:       30 * time.Second,
			KeepAlivePeriod:      15 * time.Second, //  info  KeepAlive  info  UDP  info  NAT  info
		}

		dialCtx, cancel := context.WithTimeout(parentCtx, 10*time.Second)
		defer cancel()

		conn, err := quic.DialEarly(dialCtx, udpConn, udpAddr, tlsConf, quicConfig)
		if err != nil {
			udpConn.Close() //  info ，cleanup info  Socket
			zlog.Errorf("%s [Tunnel] ❌ QUIC connection failed: %v", TAG, err)
			return nil, err
		}

		// successfully info ， info  QUIC  info ， info
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
