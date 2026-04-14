package myssh

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"nhooyr.io/websocket"
)

func init() {
	wsHandler := func(cfg ProxyConfig, baseConn net.Conn, isWSS bool) (net.Conn, error) {
		scheme := "ws"
		if isWSS {
			scheme = "wss"
		}
		zlog.Infof("%s [Tunnel] 2. 准备进行 %s 握手, 伪装 Host: %s", TAG, strings.ToUpper(scheme), cfg.CustomHost)

		path := cfg.CustomPath
		if path == "" {
			path = "/"
		}

		u := url.URL{Scheme: scheme, Host: cfg.ProxyAddr, Path: path}

		// 1. 构造基础 Header
		fakeHeaders := http.Header{
			"Host":                     []string{cfg.CustomHost},
			"User-Agent":               []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36"},
			"Sec-WebSocket-Extensions": []string{"permessage-deflate; client_max_window_bits"},
		}

		// 2. 用户名密码认证逻辑
		if cfg.ProxyAuthRequired {
			auth := cfg.ProxyAuthUser + ":" + cfg.ProxyAuthPass
			encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))
			// 在 WS 握手中，标准通常使用 Proxy-Authorization 或 Authorization
			// 大多数 CDN 或代理服务器（如 Nginx, Cloudflare）识别这个头
			fakeHeaders.Set("Proxy-Authorization", "Basic "+encodedAuth)
			zlog.Infof("%s [Tunnel] WS 握手注入认证信息 (User: %s)", TAG, cfg.ProxyAuthUser)
		}

		transport := &http.Transport{ForceAttemptHTTP2: false}

		if isWSS {
			transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				utlsConfig := &utls.Config{ServerName: cfg.ServerName, InsecureSkipVerify: true}
				uConn := utls.UClient(baseConn, utlsConfig, utls.HelloChrome_Auto)
				if err := uConn.HandshakeContext(ctx); err != nil {
					return nil, err
				}
				return uConn, nil
			}
		} else {
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return baseConn, nil
			}
		}

		opts := &websocket.DialOptions{
			HTTPClient:   &http.Client{Transport: transport},
			HTTPHeader:   fakeHeaders,
			Subprotocols: []string{"binary"},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		wsConn, resp, err := websocket.Dial(ctx, u.String(), opts)
		if err != nil {
			// 3. 🌟 增加认证失败的日志识别
			if resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 407) {
				zlog.Errorf("%s [Tunnel] ❌ WebSocket 认证失败, 状态码: %d", TAG, resp.StatusCode)
			}
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ WebSocket 握手失败: %v", TAG, err)
			return nil, err
		}
		
		zlog.Infof("%s [Tunnel] ✅ WebSocket 握手成功 (Status: %d), 协商协议: %s", TAG, resp.StatusCode, resp.Header.Get("Sec-WebSocket-Protocol"))

		return websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary), nil
	}

	RegisterTunnel("ws", "tcp", func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return wsHandler(cfg, baseConn, false)
	})
	RegisterTunnel("wss", "tcp", func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return wsHandler(cfg, baseConn, true)
	})
}