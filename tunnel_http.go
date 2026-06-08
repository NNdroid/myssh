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
			zlog.Errorf("%s [Tunnel] ❌ 错误: HttpPayload 为空", TAG)
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
			zlog.Debugf("%s [Tunnel] 🔑 已注入认证信息 (User: %s)", TAG, cfg.ProxyAuthUser)
		}

		// 提取 Method 用于日志
		method := "UNKNOWN"
		trimmedPayload := strings.TrimSpace(rawPayload)
		if firstSpace := strings.Index(trimmedPayload, " "); firstSpace != -1 {
			method = strings.ToUpper(trimmedPayload[:firstSpace])
		}

		// ==========================================
		// 🐛 DEBUG: 打印即将发送的完整 Payload (使用 %q 显式打印 \r\n 等不可见字符)
		// ==========================================
		zlog.Infof("%s [Tunnel] 🚀 准备发送请求 (Method: %s)", TAG, method)
		zlog.Debugf("%s [Tunnel] ⬆️ 发送的完整 Payload 数据:\n%q", TAG, rawPayload)

		// 发送请求
		n, err := baseConn.Write([]byte(rawPayload))
		if err != nil {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ 发送 Payload 失败: %v", TAG, err)
			return nil, fmt.Errorf("发送 Payload 失败: %v", err)
		}
		zlog.Debugf("%s [Tunnel] ⬆️ 成功发送了 %d bytes", TAG, n)

		// 解析响应
		br := bufio.NewReader(baseConn)
		line, err := br.ReadString('\n')
		if err != nil {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ 读取响应行失败: %v", TAG, err)
			return nil, fmt.Errorf("读取响应失败: %v", err)
		}

		// ==========================================
		// 🐛 DEBUG: 打印收到的第一行状态行
		// ==========================================
		zlog.Debugf("%s [Tunnel] ⬇️ 收到代理服务器响应行: %q", TAG, strings.TrimSpace(line))

		if !strings.HasPrefix(line, "HTTP/") {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ 协议错误，非 HTTP 响应: %q", TAG, line)
			return nil, fmt.Errorf("Invalid Protocol: %s", line)
		}

		var proto string
		var statusCode int
		_, err = fmt.Sscanf(line, "%s %d", &proto, &statusCode)
		if err != nil {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ 状态行解析错误: %v", TAG, err)
			return nil, fmt.Errorf("状态行解析错误: %v", err)
		}

		// 状态校验
		if !cfg.DisableStatusCheck {
			if statusCode == 401 || statusCode == 407 {
				baseConn.Close()
				zlog.Errorf("%s [Tunnel] ❌ 代理认证失败 [Status: %d]", TAG, statusCode)
				return nil, fmt.Errorf("Proxy Auth Failed: %d", statusCode)
			}
			if statusCode < 200 || statusCode >= 300 {
				baseConn.Close()
				zlog.Errorf("%s [Tunnel] ❌ 代理服务器拒绝连接 [Status: %d]", TAG, statusCode)
				return nil, fmt.Errorf("HTTP Refused: %d", statusCode)
			}
		}

		// ==========================================
		// 🐛 DEBUG: 打印所有返回的 Headers，直到遇到空行
		// ==========================================
		zlog.Debugf("%s [Tunnel] ⬇️ 开始读取响应 Header...", TAG)
		// 消耗头部直到空行
		for {
			l, err := br.ReadString('\n')
			if err != nil || l == "\r\n" || l == "\n" || l == "" {
				break
			}
		}

		zlog.Infof("%s [Tunnel] ✅ HTTP %s 隧道已建立", TAG, method)
		
		// 返回我们包装过的 BufferedConn，把含有残留 SSH 握手数据的 br 缝合进去
		wrappedConn := &BufferedConn{
			Conn: baseConn,
			r:    br,
		}
		
		return wrappedConn, nil
	})
}