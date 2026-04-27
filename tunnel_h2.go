package myssh

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// ==========================================
// 1. HTTP/2 双向流转 net.Conn 适配器
// ==========================================
type streamConn struct {
	net.Conn
	pw       *io.PipeWriter
	respBody io.ReadCloser
	cancel   context.CancelFunc
}

func (s *streamConn) Read(b []byte) (n int, err error)  { return s.respBody.Read(b) }
func (s *streamConn) Write(b []byte) (n int, err error) { return s.pw.Write(b) }
func (s *streamConn) Close() error {
	if s.cancel != nil {
		s.cancel()
	}

	var errs []error
	if s.pw != nil {
		// 🌟 先关闭写入管道，让服务端收到 EOF
		if err := s.pw.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.respBody != nil {
		if err := s.respBody.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.Conn != nil {
		if err := s.Conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// ==========================================
// 2. gRPC 数据帧封装器
// ==========================================
type grpcWriter struct {
	w io.Writer
}

func (g *grpcWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	// 🌟在栈上分配 5 字节固定头部，避免堆分配
	var header [5]byte
	binary.BigEndian.PutUint32(header[1:5], uint32(len(p)))

	// 分两次写入，底层 http2.Transport 会自动处理缓冲
	if _, err := g.w.Write(header[:]); err != nil {
		return 0, err
	}
	return g.w.Write(p)
}

type grpcReader struct {
	r    io.Reader
	left uint32
}

func (g *grpcReader) Read(p []byte) (n int, err error) {
	for g.left == 0 {
		var header [5]byte
		if _, err := io.ReadFull(g.r, header[:]); err != nil {
			return 0, err
		}
		g.left = binary.BigEndian.Uint32(header[1:5])
	}

	toRead := uint32(len(p))
	if toRead > g.left {
		toRead = g.left
	}

	n, err = g.r.Read(p[:toRead])
	g.left -= uint32(n)
	return n, err
}

// grpcConn 组合包装器：将 grpc 的读写器与底层的 net.Conn 绑定
type grpcConn struct {
	net.Conn
	gw *grpcWriter
	gr *grpcReader
}

func (g *grpcConn) Read(b []byte) (n int, err error)  { return g.gr.Read(b) }
func (g *grpcConn) Write(b []byte) (n int, err error) { return g.gw.Write(b) }

// ==========================================
// 3. 核心握手逻辑与注册
// ==========================================
func init() {
	// 提取 H2 和 gRPC 通用的握手逻辑
	// isTLS: 是否使用 TLS (区分 h2/h2c)
	// isGRPC: 是否套用 gRPC 协议头和封包器
	h2Handler := func(parentCtx context.Context, cfg ProxyConfig, baseConn net.Conn, isTLS bool, isGRPC bool) (net.Conn, error) {
		scheme := "http"
		protoName := "H2C"
		if isTLS {
			scheme = "https"
			protoName = "H2"
		}
		if isGRPC {
			protoName = "gRPC"
			if !isTLS {
				protoName = "gRPC-Cleartext"
			}
		}

		zlog.Infof("%s [Tunnel] 2. 准备进行 %s 隧道握手, 伪装 Host: %s", TAG, protoName, cfg.CustomHost)

		path := cfg.CustomPath
		if path == "" {
			path = "/tunnel"
		}

		reqUrl := fmt.Sprintf("%s://%s%s", scheme, cfg.ProxyAddr, path)

		pr, pw := io.Pipe()
		ctx, cancel := context.WithCancel(parentCtx)
		req, err := http.NewRequestWithContext(ctx, "POST", reqUrl, pr)
		if err != nil {
			baseConn.Close()
			cancel()
			return nil, err
		}

		req.Header.Set("Host", cfg.CustomHost)
		if cfg.CustomHost != "" {
			req.Host = cfg.CustomHost
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 16; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.50 Mobile Safari/537.36")
		req.Header.Set("X-Target", cfg.SshAddr) // 核心路由信息
		req.Header.Set("X-Network", "tcp")
		if cfg.ProxyAuthRequired {
			req.Header.Set("Proxy-Authorization", "Bearer "+cfg.ProxyAuthToken)
		}

		// 🌟 注入 gRPC 标准头部
		if isGRPC {
			req.Header.Set("Content-Type", "application/grpc")
			req.Header.Set("TE", "trailers")
		}

		transport := &http2.Transport{}
		if isTLS {
			// 这里的 ctx 是由 http2.Transport 在拨号时传入的，它已经自动继承了上面的 reqCtx
			transport.DialTLSContext = func(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
				utlsConfig := &utls.Config{
					ServerName:            cfg.ServerName,
					InsecureSkipVerify:    true,
					NextProtos:            []string{"h2", "http/1.1"},
					VerifyPeerCertificate: MakePeerCertVerifier(cfg.VerifyCertificateFingerprint, cfg.ServerCertificateFingerprint),
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
			zlog.Errorf("%s [Tunnel] ❌ %s 握手请求失败: %v", TAG, protoName, err)
			return nil, err
		case resp := <-respChan:
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				cancel()
				baseConn.Close()
				zlog.Errorf("%s [Tunnel] ❌ %s 服务端拒绝, 状态码: %d", TAG, protoName, resp.StatusCode)
				return nil, fmt.Errorf("HTTP status: %d", resp.StatusCode)
			}
			zlog.Infof("%s [Tunnel] ✅ %s 隧道握手成功", TAG, protoName)

			// 组装底层的 HTTP/2 流连接
			sConn := &streamConn{
				Conn:     baseConn,
				pw:       pw,
				respBody: resp.Body,
				cancel:   cancel,
			}

			var rConn net.Conn = sConn

			// 🌟 如果是 gRPC，给这个连接套上数据帧封包器
			if isGRPC {
				rConn = &grpcConn{
					Conn: sConn,
					gw:   &grpcWriter{w: sConn},
					gr:   &grpcReader{r: sConn},
				}
			}

			return WrapWithPadding(rConn), nil

		case <-time.After(15 * time.Second):
			cancel()
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ %s 握手超时", TAG, protoName)
			return nil, fmt.Errorf("%s handshake timeout", protoName)
		}
	}

	// 注册 H2 系列
	RegisterTunnel("h2c", "tcp", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return h2Handler(ctx, cfg, baseConn, false, false)
	})
	RegisterTunnel("h2", "tcp", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return h2Handler(ctx, cfg, baseConn, true, false)
	})

	// 注册 gRPC 系列
	RegisterTunnel("grpcc", "tcp", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return h2Handler(ctx, cfg, baseConn, false, true) // Cleartext gRPC
	})
	RegisterTunnel("grpc", "tcp", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return h2Handler(ctx, cfg, baseConn, true, true) // TLS gRPC
	})
}
