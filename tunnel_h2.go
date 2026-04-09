package myssh

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// streamConn 用于将 HTTP/2 的双向流包装成标准的 net.Conn
type streamConn struct {
	net.Conn
	pw       *io.PipeWriter
	respBody io.ReadCloser
	cancel   context.CancelFunc
}

func (s *streamConn) Read(b []byte) (n int, err error) { return s.respBody.Read(b) }
func (s *streamConn) Write(b []byte) (n int, err error) { return s.pw.Write(b) }
func (s *streamConn) Close() error {
	if s.cancel != nil { s.cancel() }
	if s.pw != nil { s.pw.Close() }
	if s.respBody != nil { s.respBody.Close() }
	return s.Conn.Close()
}

func init() {
	// 提取 H2 通用握手逻辑
	h2Handler := func(cfg ProxyConfig, baseConn net.Conn, isH2TLS bool) (net.Conn, error) {
		scheme := "http"
		if isH2TLS {
			scheme = "https"
		}

		zlog.Infof("%s [Tunnel] 2. 准备进行 %s 隧道握手, 伪装 Host: %s", TAG, scheme, cfg.CustomHost)

		path := cfg.CustomPath
		if path == "" {
			path = "/tunnel"
		}

		reqUrl := fmt.Sprintf("%s://%s%s", scheme, cfg.ProxyAddr, path)

		pr, pw := io.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		req, err := http.NewRequestWithContext(ctx, "POST", reqUrl, pr)
		if err != nil {
			baseConn.Close()
			cancel()
			return nil, err
		}

		req.Header.Set("Host", cfg.CustomHost)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
		req.Header.Set("X-Target", cfg.SshAddr) // 核心路由信息

		transport := &http2.Transport{}
		if isH2TLS {
			transport.DialTLSContext = func(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
				utlsConfig := &utls.Config{
					ServerName:         cfg.CustomHost,
					InsecureSkipVerify: true,
					NextProtos:         []string{"h2", "http/1.1"},
				}
				uConn := utls.UClient(baseConn, utlsConfig, utls.HelloChrome_Auto)
				if err := uConn.HandshakeContext(ctx); err != nil {
					return nil, err
				}
				return uConn, nil
			}
		} else {
			transport.AllowHTTP = true
			transport.DialTLSContext = func(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
				return baseConn, nil
			}
		}

		client := &http.Client{Transport: transport}
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
			baseConn.Close()
			cancel()
			zlog.Errorf("%s [Tunnel] ❌ %s 握手请求失败: %v", TAG, scheme, err)
			return nil, err
		case resp := <-respChan:
			if resp.StatusCode != http.StatusOK {
				baseConn.Close()
				cancel()
				zlog.Errorf("%s [Tunnel] ❌ %s 服务端拒绝, 状态码: %d", TAG, scheme, resp.StatusCode)
				return nil, fmt.Errorf("HTTP2 status: %d", resp.StatusCode)
			}
			zlog.Infof("%s [Tunnel] ✅ %s 隧道握手成功", TAG, scheme)

			return &streamConn{
				Conn:     baseConn,
				pw:       pw,
				respBody: resp.Body,
				cancel:   cancel,
			}, nil
		case <-time.After(15 * time.Second):
			baseConn.Close()
			cancel()
			zlog.Errorf("%s [Tunnel] ❌ %s 握手超时", TAG, scheme)
			return nil, fmt.Errorf("h2 handshake timeout")
		}
	}

	RegisterTunnel("h2c", func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return h2Handler(cfg, baseConn, false)
	})
	RegisterTunnel("h2", func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return h2Handler(cfg, baseConn, true)
	})
}