package myssh

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lxzan/gws"
)

// wsStream 将 gws 的消息型连接适配为 net.Conn 字节流，
// 语义等价于按二进制消息收发的流式传输：
// 每次 Write 发送一条二进制消息，Read 将消息负载重组为连续字节流。
type wsStream struct {
	conn *gws.Conn
	buf  []byte // 最近一条消息中尚未消费完的负载
}

func (s *wsStream) Read(p []byte) (int, error) {
	for len(s.buf) == 0 {
		msg, err := s.conn.ReadMessage()
		if err != nil {
			return 0, err
		}
		// msg.Close() 会将负载归还内存池，必须先复制。
		s.buf = append(s.buf, msg.Bytes()...)
		_ = msg.Close()
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

func (s *wsStream) Write(p []byte) (int, error) {
	if err := s.conn.WriteMessage(gws.OpcodeBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *wsStream) Close() error {
	// WriteClose 成功或连接已被关闭时，底层 TCP/TLS 连接均已关闭。
	err := s.conn.WriteClose(1000, nil)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func (s *wsStream) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *wsStream) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *wsStream) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *wsStream) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *wsStream) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }

func init() {
	wsHandler := func(parentCtx context.Context, cfg ProxyConfig, baseConn net.Conn, isWSS bool) (net.Conn, error) {
		scheme := "ws"
		if isWSS {
			scheme = "wss"
		}
		zlog.Infof("%s [Tunnel] 2. Preparing %s handshake, spoofed Host: %s", TAG, strings.ToUpper(scheme), cfg.CustomHost)

		path := cfg.CustomPath
		if path == "" {
			path = "/"
		}

		u := url.URL{Scheme: scheme, Host: cfg.ProxyAddr, Path: path}

		// Header
		header := http.Header{}
		header.Set("Host", cfg.CustomHost)
		header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 16; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.50 Mobile Safari/537.36")
		header.Set("Sec-WebSocket-Protocol", "binary")

		//  info
		if cfg.ProxyAuthRequired {
			auth := cfg.ProxyAuthUser + ":" + cfg.ProxyAuthPass
			encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))
			//  info  WS  info ， info  Proxy-Authorization  info  Authorization
			//  info  CDN  info server（ info  Nginx, Cloudflare） info
			header.Set("Proxy-Authorization", "Basic "+encodedAuth)
			zlog.Infof("%s [Tunnel] Injected authentication info for WS handshake (User: %s)", TAG, cfg.ProxyAuthUser)
		}

		// wss 模式下先在 baseConn 上完成 UTLS 握手，再交给 gws 做 WebSocket 升级。
		handshakeConn := baseConn
		if isWSS {
			utlsConfig := buildUTLSConfig(cfg, []string{"http/1.1"})
			uConn, err := handshakeUTLS(parentCtx, baseConn, utlsConfig)
			if err != nil {
				baseConn.Close()
				zlog.Errorf("%s [Tunnel] ❌ WebSocket handshake failed: %v", TAG, err)
				return nil, err
			}
			handshakeConn = uConn
		}

		option := &gws.ClientOption{
			Addr:             u.String(),
			RequestHeader:    header,
			HandshakeTimeout: 10 * time.Second,
			PermessageDeflate: gws.PermessageDeflate{
				Enabled:               true,
				ClientContextTakeover: true,
				ServerContextTakeover: true,
			},
			ReadMaxPayloadSize: 16 * 1024 * 1024,
		}

		wsConn, resp, err := gws.NewClientFromConn(gws.BuiltinEventHandler{}, option, handshakeConn)
		if err != nil {
			// Authentication failed
			if resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 407) {
				zlog.Errorf("%s [Tunnel] ❌ WebSocket authentication failed, status code: %d", TAG, resp.StatusCode)
			}
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ WebSocket handshake failed: %v", TAG, err)
			return nil, err
		}

		zlog.Infof("%s [Tunnel] ✅ WebSocket handshake successful (Status: %d), Negotiated protocol: %s", TAG, resp.StatusCode, resp.Header.Get("Sec-WebSocket-Protocol"))
		return &wsStream{conn: wsConn}, nil
	}

	RegisterTunnel("ws", "tcp", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return wsHandler(ctx, cfg, baseConn, false)
	})
	RegisterTunnel("wss", "tcp", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return wsHandler(ctx, cfg, baseConn, true)
	})
}
