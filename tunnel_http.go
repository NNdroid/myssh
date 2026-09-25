package myssh

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"
)

// BufferedConn 将 net.Conn 与已缓冲的 bufio.Reader 组合：
// http 隧道握手期间读响应头会产生 bufio 内部缓冲，直接丢弃会吞掉
// SSH 通道的前几个字节；包装后 SSH 层从同一个 bufio.Reader 继续读。
type BufferedConn struct {
	net.Conn
	r *bufio.Reader
}

// Read 优先消费 bufio.Reader 内已缓冲的数据。
func (b *BufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func init() {
	RegisterTunnel("http", "tcp", dialHTTPTunnel)
}

// dialHTTPTunnel 在预拨的 baseConn 上完成 HTTP 明文代理握手：
// 按 HttpPayload 模板渲染请求（占位符替换 + 可选 Basic 认证注入），
// 校验状态行，排空响应头，最后把连接连同残余缓冲交还给 SSH 层。
func dialHTTPTunnel(_ context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
	if strings.TrimSpace(cfg.HttpPayload) == "" {
		baseConn.Close()
		zlog.Errorf("%s [Tunnel] ❌ Error: HttpPayload is empty", TAG)
		return nil, fmt.Errorf("HttpPayload is required")
	}

	rawPayload := renderHTTPTemplate(cfg)

	// 解析 Method 仅用于日志展示
	method := "UNKNOWN"
	trimmedPayload := strings.TrimSpace(rawPayload)
	if firstSpace := strings.Index(trimmedPayload, " "); firstSpace != -1 {
		method = strings.ToUpper(trimmedPayload[:firstSpace])
	}

	// ==========================================
	// 发送 Payload（%q 打印以显式呈现 \r\n）
	// ==========================================
	zlog.Infof("%s [Tunnel] 🚀 Preparing to send request (Method: %s)", TAG, method)
	if Debug {
		zlog.Debugf("%s [Tunnel] ⬆️ Sent full Payload data:\n%q", TAG, rawPayload)
	}

	n, err := baseConn.Write([]byte(rawPayload))
	if err != nil {
		baseConn.Close()
		zlog.Errorf("%s [Tunnel] ❌ Failed to send Payload: %v", TAG, err)
		return nil, fmt.Errorf("failed to send Payload: %v", err)
	}
	if Debug {
		zlog.Debugf("%s [Tunnel] ⬆️ Payload sent successfully | Bytes Written: %d", TAG, n)
	}

	// 握手读响应必须有 deadline，否则恶意/卡死的代理会让拨号永久挂起
	// （只能靠 TCP keepalive 在约 75s 后兜底）。
	baseConn.SetReadDeadline(time.Now().Add(10 * time.Second))

	br := bufio.NewReader(baseConn)
	line, err := br.ReadString('\n')
	if err != nil {
		baseConn.Close()
		zlog.Errorf("%s [Tunnel] ❌ Failed to read response line: %v", TAG, err)
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	if Debug {
		zlog.Debugf("%s [Tunnel] ⬇️ Received proxy server response line: %q", TAG, strings.TrimSpace(line))
	}

	if err := checkHTTPStatusLine(line); err != nil {
		baseConn.Close()
		zlog.Errorf("%s [Tunnel] ❌ %v", TAG, err)
		return nil, err
	}

	var proto string
	var statusCode int
	if _, err := fmt.Sscanf(line, "%s %d", &proto, &statusCode); err != nil {
		baseConn.Close()
		zlog.Errorf("%s [Tunnel] ❌ Status line parsing error: %v", TAG, err)
		return nil, fmt.Errorf("status line parsing error: %v", err)
	}

	// 状态码校验（可经 DisableStatusCheck 跳过）
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

	// 排空响应头（读到空行为止）
	if Debug {
		zlog.Debugf("%s [Tunnel] ⬇️ Start reading the response header...", TAG)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ Failed to read response header line: %v", TAG, err)
			return nil, fmt.Errorf("failed to read header: %w", err)
		}
		if l == "\r\n" || l == "\n" || l == "" {
			break
		}
		if Debug {
			zlog.Debugf("%s [Tunnel] ⬇️ Received header line: %q", TAG, strings.TrimSpace(l))
		}
	}

	zlog.Infof("%s [Tunnel] ✅ HTTP %s tunnel established", TAG, method)

	// 握手完成，解除读 deadline，交给 SSH 传输层正常收发。
	baseConn.SetReadDeadline(time.Time{})

	return &BufferedConn{Conn: baseConn, r: br}, nil
}

// renderHTTPTemplate 渲染 HttpPayload 模板：替换占位符并按需注入 Basic 认证头。
func renderHTTPTemplate(cfg ProxyConfig) string {
	rawPayload := cfg.HttpPayload
	rawPayload = strings.ReplaceAll(rawPayload, "[host_and_port]", cfg.SshAddr)
	rawPayload = strings.ReplaceAll(rawPayload, "[host]", cfg.CustomHost)
	rawPayload = strings.ReplaceAll(rawPayload, "[user_agent]", spoofChromeMobileUA)
	rawPayload = strings.ReplaceAll(rawPayload, "[crlf]", "\r\n")

	if cfg.ProxyAuthRequired {
		auth := cfg.ProxyAuthUser + ":" + cfg.ProxyAuthPass
		encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))
		authHeader := fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", encodedAuth)

		if strings.Contains(rawPayload, "[auth]") {
			rawPayload = strings.ReplaceAll(rawPayload, "[auth]", authHeader)
		} else {
			// 无 [auth] 占位符时插到请求头首行之后
			if firstLineEnd := strings.Index(rawPayload, "\r\n"); firstLineEnd != -1 {
				rawPayload = rawPayload[:firstLineEnd+2] + authHeader + rawPayload[firstLineEnd+2:]
			} else if firstLineEnd := strings.Index(rawPayload, "\n"); firstLineEnd != -1 {
				rawPayload = rawPayload[:firstLineEnd+1] + authHeader + rawPayload[firstLineEnd+1:]
			}
		}
		zlog.Debugf("%s [Tunnel] 🔑 Injected authentication info (User: %s)", TAG, cfg.ProxyAuthUser)
	}
	return rawPayload
}

// checkHTTPStatusLine 校验代理响应首行是否为合法 HTTP 状态行。
func checkHTTPStatusLine(line string) error {
	if !strings.HasPrefix(line, "HTTP/") {
		return fmt.Errorf("invalid protocol: %s", line)
	}
	return nil
}
