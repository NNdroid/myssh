package myssh

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

func init() {
	RegisterTunnel("http", "tcp", func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		zlog.Infof("%s [Tunnel] 2. 准备发送 HTTP CONNECT 代理请求, 目标: %s", TAG, cfg.SshAddr)
		
		payload := cfg.HttpPayload
		if payload == "" {
			payload = "CONNECT [host_and_port] HTTP/1.1[crlf]Host: [host][crlf][crlf]"
		}

		payload = strings.ReplaceAll(payload, "[host_and_port]", cfg.SshAddr)
		payload = strings.ReplaceAll(payload, "[host]", cfg.CustomHost)
		payload = strings.ReplaceAll(payload, "[crlf]", "\r\n")

		zlog.Infof("%s [Tunnel] 发送的 HTTP Payload:\n%s", TAG, payload)
		if _, err := baseConn.Write([]byte(payload)); err != nil {
			baseConn.Close()
			return nil, err
		}

		br := bufio.NewReader(baseConn)
		line, _ := br.ReadString('\n')
		if !strings.Contains(line, "200") {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ HTTP 代理拒绝连接: %s", TAG, line)
			return nil, fmt.Errorf("HTTP Proxy Refused: %s", line)
		}
		
		for {
			l, _ := br.ReadString('\n')
			if l == "\r\n" || l == "" { break }
		}
		zlog.Infof("%s [Tunnel] ✅ HTTP CONNECT 代理建立成功", TAG)
		return baseConn, nil
	})
}