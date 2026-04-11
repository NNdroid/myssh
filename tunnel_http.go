package myssh

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

func init() {
	RegisterTunnel("http", "tcp", func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		// 1. 严格校验 Payload 不能为空
		if strings.TrimSpace(cfg.HttpPayload) == "" {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ 错误: HttpPayload 为空，无法建立隧道", TAG)
			return nil, fmt.Errorf("HttpPayload is required but got empty")
		}

		// 2. 构造完整的 Payload
		rawPayload := cfg.HttpPayload
		rawPayload = strings.ReplaceAll(rawPayload, "[host_and_port]", cfg.SshAddr)
		rawPayload = strings.ReplaceAll(rawPayload, "[host]", cfg.CustomHost)
		rawPayload = strings.ReplaceAll(rawPayload, "[crlf]", "\r\n")

		// 3. 从 Payload 中动态提取 Method 供日志使用
		// 逻辑：去掉首尾空白后，取第一个空格前的字符串
		method := "UNKNOWN"
		trimmedPayload := strings.TrimSpace(rawPayload)
		if firstSpace := strings.Index(trimmedPayload, " "); firstSpace != -1 {
			method = strings.ToUpper(trimmedPayload[:firstSpace])
		}

		zlog.Infof("%s [Tunnel] 准备发送请求 (Method: %s)", TAG, method)
		zlog.Infof("%s [Tunnel] Payload 详情:\n%s", TAG, rawPayload)
		
		// 发送请求
		if _, err := baseConn.Write([]byte(rawPayload)); err != nil {
			baseConn.Close()
			return nil, fmt.Errorf("发送 Payload 失败: %v", err)
		}

		// 4. 解析响应
		br := bufio.NewReader(baseConn)
		line, err := br.ReadString('\n')
		if err != nil {
			baseConn.Close()
			return nil, fmt.Errorf("读取响应行失败: %v", err)
		}

		// 校验是否为 HTTP 协议响应
		if !strings.HasPrefix(line, "HTTP/") {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ 非法协议响应: %s", TAG, strings.TrimSpace(line))
			return nil, fmt.Errorf("Invalid Protocol: %s", line)
		}

		// 解析状态码
		var proto string
		var statusCode int
		_, err = fmt.Sscanf(line, "%s %d", &proto, &statusCode)
		if err != nil {
			baseConn.Close()
			return nil, fmt.Errorf("状态行格式错误: %v", err)
		}

		if !cfg.DisableStatusCheck {
			// 判断 2xx 成功范围
			if statusCode < 200 || statusCode >= 300 {
				baseConn.Close()
				zlog.Errorf("%s [Tunnel] ❌ 代理拒绝 [Status: %d] [Line: %s]", TAG, statusCode, strings.TrimSpace(line))
				return nil, fmt.Errorf("HTTP Refused: %d", statusCode)
			}
		} else {
			zlog.Errorf("%s [Tunnel] HTTP响应 [Status: %d] [Line: %s]", TAG, statusCode, strings.TrimSpace(line))
		}

		// 5. 消耗掉 Header 直到空行，完成握手
		for {
			l, err := br.ReadString('\n')
			if err != nil || l == "\r\n" || l == "\n" || l == "" {
				break
			}
		}

		zlog.Infof("%s [Tunnel] ✅ HTTP %s 隧道已建立 (Status: %d)", TAG, method, statusCode)
		return baseConn, nil
	})
}