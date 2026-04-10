package myssh

import (
	"context"
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

		fakeHeaders := http.Header{
			"Host":                     []string{cfg.CustomHost},
			"User-Agent":               []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36"},
			"Sec-WebSocket-Extensions": []string{"permessage-deflate; client_max_window_bits"},
		}

		transport := &http.Transport{ForceAttemptHTTP2: false}

		if isWSS {
			transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				utlsConfig := &utls.Config{ServerName: cfg.CustomHost, InsecureSkipVerify: true}
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
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ WebSocket 握手失败: %v", TAG, err)
			return nil, err
		}
		zlog.Infof("%s [Tunnel] ✅ WebSocket 握手成功, 协商协议: %s", TAG, resp.Header.Get("Sec-WebSocket-Protocol"))

		return websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary), nil
	}

	RegisterTunnel("ws", "tcp", func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return wsHandler(cfg, baseConn, false)
	})
	RegisterTunnel("wss", "tcp", func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return wsHandler(cfg, baseConn, true)
	})
}