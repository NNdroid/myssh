package myssh

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
)

// BufferedConn  info  net.Conn  info  bufio.Reader
//
//	info  bufio  info
type BufferedConn struct {
	net.Conn
	r *bufio.Reader
}

// info  Read  info ， info  bufio.Reader  info
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

		//  info
		rawPayload := cfg.HttpPayload
		rawPayload = strings.ReplaceAll(rawPayload, "[host_and_port]", cfg.SshAddr)
		rawPayload = strings.ReplaceAll(rawPayload, "[host]", cfg.CustomHost)
		rawPayload = strings.ReplaceAll(rawPayload, "[user_agent]", "Mozilla/5.0 (Linux; Android 16; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.50 Mobile Safari/537.36")
		rawPayload = strings.ReplaceAll(rawPayload, "[crlf]", "\r\n")

		//  info
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

		//  info  Method  info
		method := "UNKNOWN"
		trimmedPayload := strings.TrimSpace(rawPayload)
		if firstSpace := strings.Index(trimmedPayload, " "); firstSpace != -1 {
			method = strings.ToUpper(trimmedPayload[:firstSpace])
		}

		// ==========================================
		//  info send info  Payload ( info  %q  info  \r\n  info )
		// ==========================================
		zlog.Infof("%s [Tunnel] 🚀 Preparing to send request (Method: %s)", TAG, method)
		if Debug {
			zlog.Debugf("%s [Tunnel] ⬆️ Sent full Payload data:\n%q", TAG, rawPayload)
		}

		// send info
		n, err := baseConn.Write([]byte(rawPayload))
		if err != nil {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ Failed to send Payload: %v", TAG, err)
			return nil, fmt.Errorf("failed to send Payload: %v", err)
		}
		if Debug {
			zlog.Debugf("%s [Tunnel] ⬆️ Payload sent successfully | Bytes Written: %d", TAG, n)
		}

		//  info
		br := bufio.NewReader(baseConn)
		line, err := br.ReadString('\n')
		if err != nil {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ Failed to read response line: %v", TAG, err)
			return nil, fmt.Errorf("failed to read response: %v", err)
		}

		// ==========================================
		//  info
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

		//  info
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
		//  info  Headers， info
		// ==========================================
		if Debug {
			zlog.Debugf("%s [Tunnel] ⬇️ Start reading the response header...", TAG)
		}
		//  info
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

		//  info  BufferedConn， info  SSH  info  br  info
		wrappedConn := &BufferedConn{
			Conn: baseConn,
			r:    br,
		}

		return wrappedConn, nil
	})
}
