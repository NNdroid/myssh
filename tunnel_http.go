package myssh

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
)

// BufferedConn 包装原始 net.Conn 和 bufio.Reader
// 确保后续的读取优先消耗掉 bufio 里残留的数据
type BufferedConn struct {
	net.Conn
	r *bufio.Reader
}

// 拦截 Read 方法，强制从 bufio.Reader 中读取
func (b *BufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func init() {
	RegisterTunnel("http", "tcp", func(parentCtx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		if strings.TrimSpace(cfg.HttpPayload) == "" {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ Error: HttpPayload is empty", TAG)
			return nil, fmt.Errorf("HttpPayload is required")
		}

		// 基础变量替换
		rawPayload := cfg.HttpPayload
		rawPayload = strings.ReplaceAll(rawPayload, "[host_and_port]", cfg.SshAddr)
		rawPayload = strings.ReplaceAll(rawPayload, "[host]", cfg.CustomHost)
		rawPayload = strings.ReplaceAll(rawPayload, "[user_agent]", "Mozilla/5.0 (Linux; Android 16; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.50 Mobile Safari/537.36")
		rawPayload = strings.ReplaceAll(rawPayload, "[crlf]", "\r\n")

		// 用户名密码认证逻辑
		if cfg.ProxyAuthRequired {
			auth := cfg.ProxyAuthUser + ":" + cfg.ProxyAuthPass
			encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))
			authHeader := fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", encodedAuth)

			if strings.Contains(rawPayload, "[auth]") {
				rawPayload = strings.ReplaceAll(rawPayload, "[auth]", authHeader)
			} else {
				if firstLineEnd := strings.Index(rawPayload, "\r\n"); firstLineEnd != -1 {
					rawPayload = rawPayload[:firstLineEnd+2] + authHeader + rawPayload[firstLineEnd+2:]
				} else if firstLineEnd := strings.Index(rawPayload, "\n"); firstLineEnd != -1 {
					rawPayload = rawPayload[:firstLineEnd+1] + authHeader + rawPayload[firstLineEnd+1:]
				}
			}
			zlog.Debugf("%s [Tunnel] 🔑 Injected authentication info (User: %s)", TAG, cfg.ProxyAuthUser)
		}

		// 提取 Method 用于日志
		method := "UNKNOWN"
		trimmedPayload := strings.TrimSpace(rawPayload)
		if firstSpace := strings.Index(trimmedPayload, " "); firstSpace != -1 {
			method = strings.ToUpper(trimmedPayload[:firstSpace])
		}

		// ==========================================
		// 打印即将发送的完整 Payload (使用 %q 显式打印 \r\n 等不可见字符)
		// ==========================================
		zlog.Infof("%s [Tunnel] 🚀 Preparing to send request (Method: %s)", TAG, method)
		if Debug {
			zlog.Debugf("%s [Tunnel] ⬆️ Sent full Payload data:\n%q", TAG, rawPayload)
		}

		// 发送请求
		n, err := baseConn.Write([]byte(rawPayload))
		if err != nil {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ Failed to send Payload: %v", TAG, err)
			return nil, fmt.Errorf("failed to send Payload: %v", err)
		}
		if Debug {
			zlog.Debugf("%s [Tunnel] ⬆️ Payload sent successfully | Bytes Written: %d", TAG, n)
		}

		// 解析响应
		br := bufio.NewReader(baseConn)
		line, err := br.ReadString('\n')
		if err != nil {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ Failed to read response line: %v", TAG, err)
			return nil, fmt.Errorf("failed to read response: %v", err)
		}

		// ==========================================
		// 打印收到的第一行状态行
		// ==========================================
		if Debug {
			zlog.Debugf("%s [Tunnel] ⬇️ Received proxy server response line: %q", TAG, strings.TrimSpace(line))
		}

		if !strings.HasPrefix(line, "HTTP/") {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ Protocol error, non-HTTP response: %q", TAG, line)
			return nil, fmt.Errorf("invalid protocol: %s", line)
		}

		var proto string
		var statusCode int
		_, err = fmt.Sscanf(line, "%s %d", &proto, &statusCode)
		if err != nil {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ Status line parsing error: %v", TAG, err)
			return nil, fmt.Errorf("status line parsing error: %v", err)
		}

		// 状态校验
		if !cfg.DisableStatusCheck {
			if statusCode == 401 || statusCode == 407 {
				baseConn.Close()
				zlog.Errorf("%s [Tunnel] ❌ Proxy authentication failed [Status: %d]", TAG, statusCode)
				return nil, fmt.Errorf("Proxy Auth Failed: %d", statusCode)
			}
			if statusCode < 200 || statusCode >= 300 {
				baseConn.Close()
				zlog.Errorf("%s [Tunnel] ❌ Proxy server rejected connection [Status: %d]", TAG, statusCode)
				return nil, fmt.Errorf("HTTP Refused: %d", statusCode)
			}
		}

		// ==========================================
		// 打印所有返回的 Headers，直到遇到空行
		// ==========================================
		if Debug {
			zlog.Debugf("%s [Tunnel] ⬇️ Start reading the response header...", TAG)
		}
		// 消耗头部直到空行
		for {
			l, err := br.ReadString('\n')
			if err != nil || l == "\r\n" || l == "\n" || l == "" {
				break
			}
			if Debug {
				zlog.Debugf("%s [Tunnel] ⬇️ Received header line: %q", TAG, strings.TrimSpace(l))
			}
		}

		zlog.Infof("%s [Tunnel] ✅ HTTP %s tunnel established", TAG, method)

		// 返回我们包装过的 BufferedConn，把含有残留 SSH 握手数据的 br 缝合进去
		wrappedConn := &BufferedConn{
			Conn: baseConn,
			r:    br,
		}

		return wrappedConn, nil
	})
}
