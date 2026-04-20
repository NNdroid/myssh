package myssh

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
)

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
			// 对 user:pass 进行 Base64 编码
			encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))
			authHeader := fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", encodedAuth)

			// 逻辑：将认证头插入到第一行之后，或者替换自定义占位符
			if strings.Contains(rawPayload, "[auth]") {
				// 如果 Payload 里有 [auth] 占位符，直接替换
				rawPayload = strings.ReplaceAll(rawPayload, "[auth]", authHeader)
			} else {
				// 否则，自动尝试插入到第一个回车符后面（即请求行之后）
				if firstLineEnd := strings.Index(rawPayload, "\r\n"); firstLineEnd != -1 {
					rawPayload = rawPayload[:firstLineEnd+2] + authHeader + rawPayload[firstLineEnd+2:]
				} else if firstLineEnd := strings.Index(rawPayload, "\n"); firstLineEnd != -1 {
					rawPayload = rawPayload[:firstLineEnd+1] + authHeader + rawPayload[firstLineEnd+1:]
				}
			}
			zlog.Infof("%s [Tunnel] 已注入认证信息 (User: %s)", TAG, cfg.ProxyAuthUser)
		}

		// 提取 Method 用于日志
		method := "UNKNOWN"
		trimmedPayload := strings.TrimSpace(rawPayload)
		if firstSpace := strings.Index(trimmedPayload, " "); firstSpace != -1 {
			method = strings.ToUpper(trimmedPayload[:firstSpace])
		}

		zlog.Infof("%s [Tunnel] 准备发送请求 (Method: %s)", TAG, method)

		// 发送请求
		if _, err := baseConn.Write([]byte(rawPayload)); err != nil {
			baseConn.Close()
			return nil, fmt.Errorf("发送 Payload 失败: %v", err)
		}

		// 解析响应
		br := bufio.NewReader(baseConn)
		line, err := br.ReadString('\n')
		if err != nil {
			baseConn.Close()
			return nil, fmt.Errorf("读取响应失败: %v", err)
		}

		if !strings.HasPrefix(line, "HTTP/") {
			baseConn.Close()
			return nil, fmt.Errorf("Invalid Protocol: %s", line)
		}

		var proto string
		var statusCode int
		_, err = fmt.Sscanf(line, "%s %d", &proto, &statusCode)
		if err != nil {
			baseConn.Close()
			return nil, fmt.Errorf("状态行解析错误: %v", err)
		}

		// 状态校验
		if !cfg.DisableStatusCheck {
			// 如果收到 401 或 407，说明认证失败
			if statusCode == 401 || statusCode == 407 {
				baseConn.Close()
				zlog.Errorf("%s [Tunnel] ❌ 认证失败 [Status: %d]", TAG, statusCode)
				return nil, fmt.Errorf("Proxy Auth Failed: %d", statusCode)
			}
			if statusCode < 200 || statusCode >= 300 {
				baseConn.Close()
				zlog.Errorf("%s [Tunnel] ❌ 代理拒绝 [Status: %d]", TAG, statusCode)
				return nil, fmt.Errorf("HTTP Refused: %d", statusCode)
			}
		}

		// 消耗头部直到空行
		for {
			l, err := br.ReadString('\n')
			if err != nil || l == "\r\n" || l == "\n" || l == "" {
				break
			}
		}

		zlog.Infof("%s [Tunnel] ✅ HTTP %s 隧道已建立", TAG, method)
		return baseConn, nil
	})
}
