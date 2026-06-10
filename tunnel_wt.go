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

// WebTransport 全局会话池
var (
	wtSessionCache sync.Map
	wtMutex        sync.Mutex
)

// getWTSession 获取或新建一个复用的 WebTransport 会话 (懒加载拨号)
func getWTSession(cfg ProxyConfig, reqUrl string) (*webtransport.Session, error) {
	if val, ok := wtSessionCache.Load(cfg.ProxyAddr); ok {
		return val.(*webtransport.Session), nil
	}

	wtMutex.Lock()
	defer wtMutex.Unlock()

	if val, ok := wtSessionCache.Load(cfg.ProxyAddr); ok {
		return val.(*webtransport.Session), nil
	}

	zlog.Infof("%s [Tunnel-WT] ⚡ 缓存未命中，正在建立底层 WebTransport 全新会话...", TAG)

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

	qconn, err := quic.DialEarly(context.Background(), udpConn, udpAddr, tlsConf, quicConf)
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

	_, session, err := dialer.Dial(context.Background(), reqUrl, headers)
	if err != nil {
		udpConn.Close()
		return nil, err
	}

	zlog.Infof("%s [Tunnel-WT] ✅ 底层 WebTransport 会话建立成功！", TAG)

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

// 💡 重写关闭逻辑，利用匿名字段的特性直接调用接口方法
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

		session, err := getWTSession(cfg, reqUrl)
		if err != nil {
			zlog.Errorf("%s [Tunnel] ❌ WebTransport 会话获取失败: %v", TAG, err)
			return nil, err
		}

		stream, err := session.OpenStreamSync(parentCtx)
		if err != nil {
			zlog.Warnf("%s [Tunnel] ⚠️ 发现 WebTransport 僵尸会话，正在清理并重试...", TAG)
			wtSessionCache.Delete(cfg.ProxyAddr)
			session.CloseWithError(1, "stream open failed due to dead session")
			return nil, fmt.Errorf("open stream failed: %w", err)
		}

		zlog.Debugf("%s [Tunnel] ⚡ 已分配新的 WT 虚拟流通道", TAG)

		rConn := &wtConn{
			Stream:     stream,
			remoteAddr: cfg.ProxyAddr,
		}

		return WrapWithPadding(rConn), nil
	})
}
