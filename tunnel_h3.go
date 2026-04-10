package myssh

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// h3Conn 实现了将 HTTP/3 的请求与响应 Body 包装为标准的 net.Conn
type h3Conn struct {
	remoteAddr string // 记录目标地址，用于伪装 RemoteAddr
	pw         *io.PipeWriter
	respBody   io.ReadCloser
	cancel     context.CancelFunc
}

func (s *h3Conn) Read(b []byte) (n int, err error)  { return s.respBody.Read(b) }
func (s *h3Conn) Write(b []byte) (n int, err error) { return s.pw.Write(b) }
func (s *h3Conn) Close() error {
	if s.cancel != nil {
		s.cancel() // 触发销毁 context 和释放底层的 RoundTripper
	}
	if s.pw != nil {
		s.pw.Close()
	}
	if s.respBody != nil {
		s.respBody.Close()
	}
	return nil
}

// 🌟 核心修改 1：彻底移除对 baseConn 的依赖，手动提供虚拟的网络地址
// 这样上层 SSH 模块不管是取 Local 还是 Remote 地址，都不会 panic
func (s *h3Conn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

func (s *h3Conn) RemoteAddr() net.Addr {
	addr, err := net.ResolveUDPAddr("udp", s.remoteAddr)
	if err == nil && addr != nil {
		return addr
	}
	return &net.UDPAddr{IP: net.IPv4zero, Port: 443} // 兜底处理
}

// 屏蔽原生超时设置，避免 SSH 客户端设置超时导致报错
func (s *h3Conn) SetDeadline(t time.Time) error      { return nil }
func (s *h3Conn) SetReadDeadline(t time.Time) error  { return nil }
func (s *h3Conn) SetWriteDeadline(t time.Time) error { return nil }

func init() {
	RegisterTunnel("h3", "udp", func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {

		zlog.Infof("%s [Tunnel] 2. 准备进行 HTTP/3 (UDP) 隧道握手, 伪装 Host: %s", TAG, cfg.CustomHost)

		path := cfg.CustomPath
		if path == "" {
			path = "/tunnel"
		}

		reqUrl := fmt.Sprintf("https://%s%s", cfg.ProxyAddr, path)

		// 构造 io.Pipe 实现上行流 (Request Body)
		pr, pw := io.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		req, err := http.NewRequestWithContext(ctx, "POST", reqUrl, pr)
		if err != nil {
			cancel()
			return nil, err
		}

		req.Header.Set("Host", cfg.CustomHost)
		if cfg.CustomHost != "" {
			req.Host = cfg.CustomHost
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("X-Target", cfg.SshAddr) // 核心路由信息

		tlsConf := &tls.Config{
			ServerName:         cfg.CustomHost,
			InsecureSkipVerify: true,
		}

		// 🌟 核心引擎：使用最新版的 http3.Transport
		rt := &http3.Transport{
			TLSClientConfig: tlsConf,
			QUICConfig: &quic.Config{  // ⚠️ 注意：新版本的 QuicConfig 变成了全大写的 QUICConfig
				MaxIdleTimeout:  30 * time.Second,
				KeepAlivePeriod: 15 * time.Second, // 维持 UDP NAT 映射
			},
		}

		client := &http.Client{Transport: rt}
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
			rt.Close()
			zlog.Errorf("%s [Tunnel] ❌ HTTP/3 握手请求失败: %v", TAG, err)
			return nil, err
		case resp := <-respChan:
			if resp.StatusCode != http.StatusOK {
				cancel()
				rt.Close()
				zlog.Errorf("%s [Tunnel] ❌ HTTP/3 服务端拒绝, 状态码: %d", TAG, resp.StatusCode)
				return nil, fmt.Errorf("HTTP status: %d", resp.StatusCode)
			}
			zlog.Infof("%s [Tunnel] ✅ HTTP/3 隧道握手成功，底层 UDP 数据流已就绪", TAG)

			// 🌟 核心修改 2：去掉了 Conn: baseConn 的赋值，改为传入 remoteAddr
			return &h3Conn{
				remoteAddr: cfg.ProxyAddr,
				pw:         pw,
				respBody:   resp.Body,
				cancel: func() {
					cancel()
					rt.Close() // 连接断开时，彻底关闭 RoundTripper 释放 UDP 端口
				},
			}, nil
		case <-time.After(15 * time.Second):
			cancel()
			rt.Close()
			zlog.Errorf("%s [Tunnel] ❌ HTTP/3 握手超时", TAG)
			return nil, fmt.Errorf("h3 handshake timeout")
		}
	})
}