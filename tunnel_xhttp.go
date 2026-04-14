package myssh

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ==========================================
// 1. 高性能随机 ID 生成器 (Cache Buster)
// ==========================================

func fastCacheBuster() string {
	// 使用纳秒时间戳的十六进制，几乎不消耗 CPU
	now := time.Now().UnixNano()
	return fmt.Sprintf("%x", now)
}

// ==========================================
// 2. XHTTP 连接适配器
// ==========================================
type xhttpConn struct {
	net.Conn
	reader io.Reader
	mu     sync.Mutex
}

func (c *xhttpConn) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

func (c *xhttpConn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.Write(b)
}

// ==========================================
// 3. 核心处理逻辑
// ==========================================

func init() {
	xhttpHandler := func(cfg ProxyConfig, baseConn net.Conn, isTLS bool) (net.Conn, error) {
		protoName := "XHTTP"
		if isTLS {
			protoName = "XHTTPS"
		}

		path := cfg.CustomPath
		if path == "" {
			path = "/api/v1/stream"
		}

		// 🌟 核心改进：拼接高性能随机 ID 
		cb := fastCacheBuster()
		if strings.Contains(path, "?") {
			path = fmt.Sprintf("%s&_t=%s", path, cb)
		} else {
			path = fmt.Sprintf("%s?_t=%s", path, cb)
		}

		zlog.Infof("%s [Tunnel] 准备进行 %s 握手, Path: %s", TAG, protoName, path)

		// 1. 处理 TLS 伪装
		var tunnelConn net.Conn = baseConn
		if isTLS {
			sni := cfg.ServerName
			if sni == "" {
				sni = cfg.CustomHost
			}
			utlsConfig := &utls.Config{
				ServerName:         sni,
				InsecureSkipVerify: true,
				NextProtos:         []string{"http/1.1"},
			}
			uConn := utls.UClient(baseConn, utlsConfig, utls.HelloChrome_Auto)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := uConn.HandshakeContext(ctx); err != nil {
				baseConn.Close()
				return nil, fmt.Errorf("TLS handshake failed: %v", err)
			}
			tunnelConn = uConn
		}

		// 2. 构造 HTTP POST 流请求
		host := cfg.CustomHost
		if host == "" {
			host, _, _ = net.SplitHostPort(cfg.ProxyAddr)
		}

		ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
		
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("POST %s HTTP/1.1\r\n", path))
		sb.WriteString(fmt.Sprintf("Host: %s\r\n", host))
		sb.WriteString(fmt.Sprintf("User-Agent: %s\r\n", ua))
		sb.WriteString("Content-Type: application/octet-stream\r\n")
		sb.WriteString("Transfer-Encoding: chunked\r\n")
		sb.WriteString("Connection: keep-alive\r\n")
		sb.WriteString("X-Target: " + cfg.SshAddr + "\r\n")
		sb.WriteString("X-Network: tcp\r\n")

		// 注入用户名密码认证
		if cfg.ProxyAuthRequired {
			auth := cfg.ProxyAuthUser + ":" + cfg.ProxyAuthPass
			encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))
			sb.WriteString(fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", encodedAuth))
		}

		if cfg.HttpPayload != "" {
			sb.WriteString(cfg.HttpPayload)
			if !strings.HasSuffix(cfg.HttpPayload, "\r\n") {
				sb.WriteString("\r\n")
			}
		}

		sb.WriteString("\r\n")

		// 3. 发送请求头
		if _, err := tunnelConn.Write([]byte(sb.String())); err != nil {
			tunnelConn.Close()
			return nil, err
		}

		// 4. 读取并校验响应头
		br := bufio.NewReader(tunnelConn)
		resp, err := http.ReadResponse(br, &http.Request{Method: "POST"})
		if err != nil {
			tunnelConn.Close()
			return nil, fmt.Errorf("read response failed: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			tunnelConn.Close()
			return nil, fmt.Errorf("server rejected: %d", resp.StatusCode)
		}

		zlog.Infof("%s [Tunnel] ✅ %s 隧道已建立, 进入流模式", TAG, protoName)

		return &xhttpConn{
			Conn:   tunnelConn,
			reader: resp.Body,
		}, nil
	}

	RegisterTunnel("xhttp", "tcp", func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return xhttpHandler(cfg, baseConn, false)
	})
	RegisterTunnel("xhttps", "tcp", func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return xhttpHandler(cfg, baseConn, true)
	})
}