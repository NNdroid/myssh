package myssh

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

var masqueH2TransportCache sync.Map

func getH2Transport(cfg ProxyConfig) *http2.Transport {
	if v, ok := masqueH2TransportCache.Load(cfg.ProxyAddr); ok {
		return v.(*http2.Transport)
	}

	rt := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
			c, err := dialTCP(ctx, cfg, cfg.ProxyAddr)
			if err != nil {
				return nil, err
			}
			// 注入 10 秒絕對超時，防止握手死鎖
			c.SetDeadline(time.Now().Add(10 * time.Second))

			utlsConfig := &utls.Config{
				ServerName:            cfg.ServerName,
				InsecureSkipVerify:    true,
				NextProtos:            []string{"h2", "http/1.1"},
				VerifyPeerCertificate: MakePeerCertVerifier(cfg.VerifyCertificateFingerprint, cfg.ServerCertificateFingerprint),
			}
			uConn := utls.UClient(c, utlsConfig, utls.HelloChrome_Auto)
			if err := uConn.HandshakeContext(ctx); err != nil {
				c.Close()
				return nil, err
			}
			// 握手成功後重置超時
			c.SetDeadline(time.Time{})

			return uConn, nil
		},
	}
	masqueH2TransportCache.Store(cfg.ProxyAddr, rt)
	return rt
}

type masqueStreamConn struct {
	pw       *io.PipeWriter
	respBody io.ReadCloser
	cancel   context.CancelFunc
	remote   string
}

func (c *masqueStreamConn) Read(p []byte) (n int, err error)  { return c.respBody.Read(p) }
func (c *masqueStreamConn) Write(p []byte) (n int, err error) { return c.pw.Write(p) }
func (c *masqueStreamConn) Close() error {
	c.cancel()
	c.pw.Close()
	return c.respBody.Close()
}
func (c *masqueStreamConn) LocalAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (c *masqueStreamConn) RemoteAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", c.remote)
	if addr == nil {
		return &net.TCPAddr{IP: net.IPv4zero, Port: 443}
	}
	return addr
}
func (c *masqueStreamConn) SetDeadline(t time.Time) error      { return nil }
func (c *masqueStreamConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *masqueStreamConn) SetWriteDeadline(t time.Time) error { return nil }

func init() {
	RegisterTunnel("masque", "custom", func(parentCtx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {

		isH2 := strings.ToLower(cfg.Alpn) == "h2"
		protoStr := "HTTP/3"
		if isH2 {
			protoStr = "HTTP/2"
		}

		zlog.Infof("%s [Tunnel] Preparing MASQUE (CONNECT-TCP) tunnel handshake over %s, Target: %s", TAG, protoStr, cfg.SshAddr)

		// 解析目标地址，处理 IPv6 的方括号问题
		host, port, err := net.SplitHostPort(cfg.SshAddr)
		if err != nil {
			zlog.Warnf("%s [Tunnel] ⚠️ Failed to resolve SSH address, trying default port 22: %v", TAG, err)
			host = cfg.SshAddr
			port = "22"
		}

		path := cfg.CustomPath
		if path == "" {
			path = "/.well-known/masque/tcp"
		}

		// 去除末尾所有斜杠，确保拼接时路径整洁
		path = strings.TrimRight(path, "/")

		// 构造最终符合 RFC 9298 风格的路径
		fullPath := fmt.Sprintf("%s/%s/%s/", path, url.PathEscape(host), url.PathEscape(port))

		reqUrlStr := fmt.Sprintf("https://%s%s", cfg.ProxyAddr, fullPath)
		reqUrl, _ := url.Parse(reqUrlStr)

		var rt http.RoundTripper

		if isH2 {
			rt = getH2Transport(cfg)
		} else {
			h3rt, err := getH3Transport(cfg)
			if err != nil {
				zlog.Errorf("%s [Tunnel] ❌ Failed to get MASQUE transport layer: %v", TAG, err)
				return nil, err
			}
			rt = h3rt
		}

		pr, pw := io.Pipe()
		ctx, cancel := context.WithCancel(parentCtx)

		// 发起 CONNECT 请求
		req, err := http.NewRequestWithContext(ctx, http.MethodConnect, reqUrl.String(), pr)
		if err != nil {
			cancel()
			return nil, err
		}

		if isH2 {
			req.Proto = "HTTP/2.0"
			req.ProtoMajor = 2
			req.ProtoMinor = 0
		} else {
			// 强制设定 HTTP/3 协议，防止退化为 H1 代理语义
			req.Proto = "HTTP/3"
			req.ProtoMajor = 3
			req.ProtoMinor = 0
		}

		if cfg.CustomHost != "" {
			req.Host = cfg.CustomHost
		}

		// 触发伪头部 :protocol
		req.Header.Set("Protocol", "connect-tcp")
		req.Header.Set("Capsule-Protocol", "?1")

		// 其他伪装 Header
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("X-Target", cfg.SshAddr)
		req.Header.Set("X-Network", "tcp")
		if cfg.ProxyAuthRequired {
			req.Header.Set("Proxy-Authorization", "Bearer "+cfg.ProxyAuthToken)
		}
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("X-Accel-Buffering", "no")

		respChan := make(chan *http.Response, 1)
		errChan := make(chan error, 1)

		go func() {
			resp, rtErr := rt.RoundTrip(req)
			if rtErr != nil {
				errChan <- rtErr
				return
			}
			respChan <- resp
		}()

		select {
		case err := <-errChan:
			cancel()
			pw.CloseWithError(err)
			pr.CloseWithError(err)
			zlog.Errorf("%s [Tunnel] ❌ MASQUE handshake failed: %v", TAG, err)

			if !isH2 {
				h3TransportCache.Delete(cfg.ProxyAddr)
			}
			return nil, err

		case resp := <-respChan:
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				cancel()
				resp.Body.Close() // 安全釋放 HTTP Stream
				zlog.Errorf("%s [Tunnel] ❌ MASQUE server rejected, status code: %d", TAG, resp.StatusCode)
				return nil, fmt.Errorf("masque proxy returned status %d", resp.StatusCode)
			}

			zlog.Infof("%s [Tunnel] ✅ MASQUE tunnel handshake successful", TAG)

			if isH2 {
				rConn := &masqueStreamConn{
					remote:   cfg.ProxyAddr,
					pw:       pw,
					respBody: resp.Body,
					cancel:   cancel,
				}
				return WrapWithPadding(rConn), nil
			} else {
				rConn := &h3Conn{
					remoteAddr: cfg.ProxyAddr,
					pw:         pw,
					respBody:   resp.Body,
					cancel:     cancel,
				}
				return WrapWithPadding(rConn), nil
			}

		case <-time.After(15 * time.Second):
			cancel()
			timeoutErr := fmt.Errorf("masque handshake timeout")
			pw.CloseWithError(timeoutErr)
			pr.CloseWithError(timeoutErr)
			zlog.Errorf("%s [Tunnel] ❌ MASQUE handshake timeout", TAG)

			if !isH2 {
				h3TransportCache.Delete(cfg.ProxyAddr)
			}
			return nil, timeoutErr
		}
	})
}
