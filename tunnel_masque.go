package myssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

func init() {
	// 禁用硬件加速，兼容 ARM 路由器
	os.Setenv("QUIC_GO_DISABLE_GSO", "true")
	os.Setenv("QUIC_GO_DISABLE_ECN", "true")

	RegisterTunnel("masque", "udp", func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {

		zlog.Infof("%s [Tunnel] 2. 准备进行 MASQUE (CONNECT-TCP) 隧道握手, 目标: %s", TAG, cfg.SshAddr)

		// 🌟 核心修复 1：解析 host 和 port 以符合 MASQUE 路径规范
		path := cfg.CustomPath
		if path == "" {
			host, port, err := net.SplitHostPort(cfg.SshAddr)
			if err != nil {
				zlog.Warnf("%s [Tunnel] SSH 地址缺少端口，默认使用 22: %v", TAG, err)
				host = cfg.SshAddr
				port = "22"
			}
			// 规范: /.well-known/masque/tcp/{target_host}/{target_port}/
			path = fmt.Sprintf("/.well-known/masque/tcp/%s/%s/", url.PathEscape(host), url.PathEscape(port))
		}

		reqUrlStr := fmt.Sprintf("https://%s%s", cfg.ProxyAddr, path)
		reqUrl, _ := url.Parse(reqUrlStr)

		pr, pw := io.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		
		// 发起 CONNECT 请求
		req, err := http.NewRequestWithContext(ctx, http.MethodConnect, reqUrl.String(), pr)
		if err != nil {
			cancel()
			return nil, err
		}

		// 🌟 核心修复 2：强制设定 HTTP/3 协议，防止退化为 H1 代理语义
		req.Proto = "HTTP/3"
		req.ProtoMajor = 3
		req.ProtoMinor = 0

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
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("X-Accel-Buffering", "no")

		// 获取复用客户端
		client := getH3Client(cfg.ProxyAddr, cfg.CustomHost)

		respChan := make(chan *http.Response, 1)
		errChan := make(chan error, 1)

		go func() {
			// 🌟 核心修复 3：绕过 http.Client 限制，直接使用底层 Transport
			var resp *http.Response
			var rtErr error
			
			if rt, ok := client.Transport.(http.RoundTripper); ok {
				resp, rtErr = rt.RoundTrip(req)
			} else {
				resp, rtErr = client.Do(req)
			}

			if rtErr != nil {
				errChan <- rtErr
				return
			}
			respChan <- resp
		}()

		select {
		case err := <-errChan:
			cancel()
			zlog.Errorf("%s [Tunnel] ❌ MASQUE TCP 握手失败: %v", TAG, err)
			return nil, err
		case resp := <-respChan:
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				cancel()
				zlog.Errorf("%s [Tunnel] ❌ MASQUE 服务端拒绝, 状态码: %d", TAG, resp.StatusCode)
				return nil, fmt.Errorf("masque proxy returned status %d", resp.StatusCode)
			}
			zlog.Infof("%s [Tunnel] ✅ MASQUE TCP 隧道握手成功，底层双向流已建立", TAG)

			return &h3Conn{
				remoteAddr: cfg.ProxyAddr,
				pw:         pw,
				respBody:   resp.Body,
				cancel:     cancel, 
			}, nil
		case <-time.After(15 * time.Second):
			cancel() 
			zlog.Errorf("%s [Tunnel] ❌ MASQUE 握手超时", TAG)
			return nil, fmt.Errorf("masque handshake timeout")
		}
	})
}