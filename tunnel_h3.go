package myssh

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// 🌟 新增：HTTP/3 传输层全局复用池
// 这将彻底发挥 QUIC 的多路复用优势，所有代理请求共享同一条底层的 UDP/QUIC 物理连接
var (
	h3TransportCache sync.Map
	h3ClientCache    sync.Map
)

// getH3Client 获取或初始化复用的 HTTP/3 客户端
func getH3Client(proxyAddr string, host string) *http.Client {
	if client, ok := h3ClientCache.Load(proxyAddr); ok {
		return client.(*http.Client)
	}

	tlsConf := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}

	rt := &http3.Transport{
		TLSClientConfig: tlsConf,
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
			HandshakeIdleTimeout: 10 * time.Second, // 握手超时，防止 UDP 黑洞卡死
			MaxIdleTimeout:       60 * time.Second,
			KeepAlivePeriod:      8 * time.Second,
		},
	}

	client := &http.Client{Transport: rt}
	
	// 缓存起来，下次请求直接复用这套连接
	h3TransportCache.Store(proxyAddr, rt)
	h3ClientCache.Store(proxyAddr, client)

	return client
}

// h3Conn 实现了将 HTTP/3 的请求与响应 Body 包装为标准的 net.Conn
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
		s.cancel() // 触发销毁 context
	}
	if s.pw != nil {
		s.pw.Close()
	}
	if s.respBody != nil {
		s.respBody.Close()
	}
	// 🌟 核心优化：千万不要在这里调用 rt.Close()！
	// 让底层的 QUIC 连接一直活着，供下一个代理请求复用（0-RTT 极速连接）
	return nil
}

// 提供虚拟的网络地址防止 Panic
func (s *h3Conn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

func (s *h3Conn) RemoteAddr() net.Addr {
	addr, err := net.ResolveUDPAddr("udp", s.remoteAddr)
	if err == nil && addr != nil {
		return addr
	}
	return &net.UDPAddr{IP: net.IPv4zero, Port: 443} 
}

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

		pr, pw := io.Pipe()
		// 这个 ctx 控制着单次代理流的生命周期
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
		req.Header.Set("X-Target", cfg.SshAddr) 

		// 🌟 调用复用器获取单例 Client
		client := getH3Client(cfg.ProxyAddr, cfg.CustomHost)

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
			zlog.Errorf("%s [Tunnel] ❌ HTTP/3 握手请求失败: %v", TAG, err)
			return nil, err
		case resp := <-respChan:
			if resp.StatusCode != http.StatusOK {
				cancel()
				zlog.Errorf("%s [Tunnel] ❌ HTTP/3 服务端拒绝, 状态码: %d", TAG, resp.StatusCode)
				return nil, fmt.Errorf("HTTP status: %d", resp.StatusCode)
			}
			zlog.Infof("%s [Tunnel] ✅ HTTP/3 隧道握手成功，底层数据流已就绪", TAG)

			return &h3Conn{
				remoteAddr: cfg.ProxyAddr,
				pw:         pw,
				respBody:   resp.Body,
				cancel:     cancel, // 赋值给 Close 方法去调用
			}, nil
		case <-time.After(15 * time.Second):
			cancel() // 如果 15 秒了连首字节都没收到，果断取消并抛错
			zlog.Errorf("%s [Tunnel] ❌ HTTP/3 握手超时 (疑似遭遇 UDP 阻断)", TAG)
			return nil, fmt.Errorf("h3 handshake timeout")
		}
	})
}