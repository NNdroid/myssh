package myssh

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
)

// WebTransport  info
var (
	wtSessionCache sync.Map
	wtMutex        sync.Mutex
)

// getWTSession 获取或新建 WebTransport 会话 (带断线自愈检测)
func getWTSession(cfg ProxyConfig, reqUrl string) (*webtransport.Session, error) {
	if val, ok := wtSessionCache.Load(cfg.ProxyAddr); ok {
		sess := val.(*webtransport.Session)
		select {
		case <-sess.Context().Done():
			wtSessionCache.Delete(cfg.ProxyAddr)
		default:
			return sess, nil
		}
	}

	wtMutex.Lock()
	defer wtMutex.Unlock()

	// Double-check
	if val, ok := wtSessionCache.Load(cfg.ProxyAddr); ok {
		sess := val.(*webtransport.Session)
		select {
		case <-sess.Context().Done():
			wtSessionCache.Delete(cfg.ProxyAddr)
		default:
			return sess, nil
		}
	}

	zlog.Infof("%s [Tunnel-WT] ⚡ Cache miss, establishing brand new underlying WebTransport session...", TAG)

	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	baseConn, err := dialUDP(dialCtx, cfg, cfg.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("wt underlying udp dial failed: %w", err)
	}

	udpConn, ok := baseConn.(*net.UDPConn)
	if !ok {
		baseConn.Close()
		return nil, fmt.Errorf("expected *net.UDPConn, got %T", baseConn)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.ProxyAddr)
	if err != nil {
		udpConn.Close()
		return nil, err
	}

	tlsConf := &tls.Config{
		ServerName:            cfg.ServerName,
		InsecureSkipVerify:    true,
		NextProtos:            []string{"h3"},
		VerifyPeerCertificate: MakePeerCertVerifier(cfg.VerifyCertificateFingerprint, cfg.ServerCertificateFingerprint),
	}

	quicConf := &quic.Config{
		EnableDatagrams:                  true,
		EnableStreamResetPartialDelivery: true,
		HandshakeIdleTimeout:             10 * time.Second,
		MaxIdleTimeout:                   30 * time.Second,
		KeepAlivePeriod:                  8 * time.Second,
	}

	//  info  dialCtx  info ， info  10  info
	qconn, err := quic.DialEarly(dialCtx, udpConn, udpAddr, tlsConf, quicConf)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("quic dial failed: %w", err)
	}

	dialer := &webtransport.Dialer{
		TLSClientConfig: tlsConf,
		QUICConfig:      quicConf,
		DialAddr: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return qconn, nil
		},
	}

	headers := make(http.Header)
	if cfg.CustomHost != "" {
		headers.Set("Host", cfg.CustomHost)
	}
	headers.Set("User-Agent", "Mozilla/5.0 (Linux; Android 16; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko)")
	headers.Set("X-Target", cfg.SshAddr)
	headers.Set("X-Network", "tcp")
	if cfg.ProxyAuthRequired {
		headers.Set("Proxy-Authorization", "Bearer "+cfg.ProxyAuthToken)
	}

	//  info  dialCtx  info ， info  WebTransport  info
	_, session, err := dialer.Dial(dialCtx, reqUrl, headers)
	if err != nil {
		//  info  QUIC  info ， info  UDP
		qconn.CloseWithError(1, "wt dial failed")
		udpConn.Close()
		return nil, err
	}

	zlog.Infof("%s [Tunnel-WT] ✅ Underlying WebTransport session established successfully!", TAG)

	wtSessionCache.Store(cfg.ProxyAddr, session)
	return session, nil
}

type wtConn struct {
	*webtransport.Stream
	remoteAddr string
}

func (w *wtConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (w *wtConn) RemoteAddr() net.Addr {
	addr, _ := net.ResolveUDPAddr("udp", w.remoteAddr)
	return addr
}

func (w *wtConn) Close() error {
	w.CancelRead(0)
	w.CancelWrite(0)
	return w.Stream.Close()
}

func init() {
	RegisterTunnel("wt", "custom", func(parentCtx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {

		path := cfg.CustomPath
		if path == "" {
			path = "/tunnel"
		}
		reqUrl := fmt.Sprintf("https://%s%s", cfg.ProxyAddr, path)

		var session *webtransport.Session
		var stream *webtransport.Stream
		var err error

		//  info  ( info  2  info )
		//  info 「 info 」 info
		for attempt := 1; attempt <= 2; attempt++ {
			session, err = getWTSession(cfg, reqUrl)
			if err != nil {
				zlog.Errorf("%s [Tunnel] ❌ Failed to get WebTransport session: %v", TAG, err)
				return nil, err
			}

			stream, err = session.OpenStreamSync(parentCtx)
			if err == nil {
				break // successfully info  Stream， info
			}

			//  info ，cleanup info
			zlog.Warnf("%s [Tunnel] ⚠️ Detected WebTransport zombie session (Attempt %d/2), cleaning up and retrying...", TAG, attempt)
			wtSessionCache.Delete(cfg.ProxyAddr)
			session.CloseWithError(1, "stream open failed due to dead session")

			//  info ， info
			if attempt == 2 {
				return nil, fmt.Errorf("open stream failed after retry: %w", err)
			}
		}

		zlog.Debugf("%s [Tunnel] ⚡ Allocated new WT virtual stream channel", TAG)

		rConn := &wtConn{
			Stream:     stream,
			remoteAddr: cfg.ProxyAddr,
		}

		return WrapWithPadding(rConn), nil
	})
}
