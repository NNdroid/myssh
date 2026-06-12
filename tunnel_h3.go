package myssh

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ----- HTTP/3 (QUIC) 隧道实现 -----

var (
	h3TransportCache sync.Map
	clientMu         sync.Mutex
)

// getH3Transport 获取或初始化复用的 HTTP/3 传输层 (懒加载拨号)
func getH3Transport(cfg ProxyConfig) (*http3.Transport, error) {
	proxyAddr := cfg.ProxyAddr

	if rt, ok := h3TransportCache.Load(proxyAddr); ok {
		return rt.(*http3.Transport), nil
	}

	clientMu.Lock()
	defer clientMu.Unlock()

	if rt, ok := h3TransportCache.Load(proxyAddr); ok {
		return rt.(*http3.Transport), nil
	}

	zlog.Infof("%s [Tunnel-H3] 🔄 Cache miss, starting to establish brand new physical UDP connection and QUIC handshake...", TAG)

	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	baseConn, err := dialUDP(dialCtx, cfg, proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("h3 underlying udp dial failed: %w", err)
	}

	udpConn, ok := baseConn.(*net.UDPConn)
	if !ok {
		baseConn.Close()
		return nil, fmt.Errorf("expected *net.UDPConn, got %T", baseConn)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", proxyAddr)
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
		MaxIdleTimeout:                   60 * time.Second,
		KeepAlivePeriod:                  8 * time.Second,
		InitialStreamReceiveWindow:       1024 * 1024 * 5,
		MaxStreamReceiveWindow:           1024 * 1024 * 15,
		InitialConnectionReceiveWindow:   1024 * 1024 * 10,
		MaxConnectionReceiveWindow:       1024 * 1024 * 20,
		MaxIncomingStreams:               1000,
		MaxIncomingUniStreams:            1000,
	}

	qconn, err := quic.DialEarly(context.Background(), udpConn, udpAddr, tlsConf, quicConf)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("quic dial failed: %w", err)
	}

	rt := &http3.Transport{
		TLSClientConfig: tlsConf,
		QUICConfig:      quicConf,
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return qconn, nil
		},
	}

	h3TransportCache.Store(proxyAddr, rt)
	zlog.Infof("%s [Tunnel-H3] ✅ Underlying QUIC physical tunnel established successfully and cached", TAG)

	return rt, nil
}

type h3Conn struct {
	remoteAddr string
	pw         *io.PipeWriter
	respBody   io.ReadCloser
	cancel     context.CancelFunc
}

func (s *h3Conn) Read(b []byte) (n int, err error)  { return s.respBody.Read(b) }
func (s *h3Conn) Write(b []byte) (n int, err error) { return s.pw.Write(b) }
func (s *h3Conn) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.pw != nil {
		s.pw.Close()
	}
	if s.respBody != nil {
		s.respBody.Close()
	}
	return nil
}

func (s *h3Conn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (s *h3Conn) RemoteAddr() net.Addr {
	addr, _ := net.ResolveUDPAddr("udp", s.remoteAddr)
	return addr
}
func (s *h3Conn) SetDeadline(t time.Time) error      { return nil }
func (s *h3Conn) SetReadDeadline(t time.Time) error  { return nil }
func (s *h3Conn) SetWriteDeadline(t time.Time) error { return nil }

func init() {
	os.Setenv("QUIC_GO_DISABLE_GSO", "true")
	os.Setenv("QUIC_GO_DISABLE_ECN", "true")

	RegisterTunnel("h3", "custom", func(parentCtx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		zlog.Infof("%s [Tunnel] 2. Preparing HTTP/3 tunnel handshake, spoofed Host: %s", TAG, cfg.CustomHost)

		path := cfg.CustomPath
		if path == "" {
			path = "/tunnel"
		}
		reqUrl := fmt.Sprintf("https://%s%s", cfg.ProxyAddr, path)

		rt, err := getH3Transport(cfg)
		if err != nil {
			return nil, err
		}

		client := &http.Client{Transport: rt}
		pr, pw := io.Pipe()
		ctx, cancel := context.WithCancel(parentCtx)

		req, err := http.NewRequestWithContext(ctx, "POST", reqUrl, pr)
		if err != nil {
			cancel()
			return nil, err
		}

		req.Header.Set("Host", cfg.CustomHost)
		if cfg.CustomHost != "" {
			req.Host = cfg.CustomHost
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 16; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko)")
		req.Header.Set("X-Target", cfg.SshAddr)
		req.Header.Set("X-Network", "tcp")
		if cfg.ProxyAuthRequired {
			req.Header.Set("Proxy-Authorization", "Bearer "+cfg.ProxyAuthToken)
		}
		req.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
		req.Header.Set("Pragma", "no-cache")
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("X-Content-Type-Options", "nosniff")
		req.Header.Set("X-Accel-Buffering", "no")

		respChan := make(chan *http.Response, 1)
		errChan := make(chan error, 1)

		go func() {
			resp, err := client.Do(req)
			if err != nil {
				errChan <- err
				return
			}
			respChan <- resp
		}()

		select {
		case err := <-errChan:
			cancel()
			zlog.Errorf("%s [Tunnel] ❌ HTTP/3 handshake request failed: %v", TAG, err)
			h3TransportCache.Delete(cfg.ProxyAddr)
			return nil, err
		case resp := <-respChan:
			if resp.StatusCode != http.StatusOK {
				cancel()
				zlog.Errorf("%s [Tunnel] ❌ HTTP/3 server rejected, status code: %d", TAG, resp.StatusCode)
				return nil, fmt.Errorf("HTTP status: %d", resp.StatusCode)
			}
			zlog.Infof("%s [Tunnel] ✅ HTTP/3 tunnel handshake successful, data stream ready", TAG)

			rConn := &h3Conn{
				remoteAddr: cfg.ProxyAddr,
				pw:         pw,
				respBody:   resp.Body,
				cancel:     cancel,
			}

			return WrapWithPadding(rConn), nil

		case <-time.After(15 * time.Second):
			cancel()
			zlog.Errorf("%s [Tunnel] ❌ HTTP/3 handshake timeout", TAG)
			h3TransportCache.Delete(cfg.ProxyAddr)
			return nil, fmt.Errorf("h3 handshake timeout")
		}
	})
}
