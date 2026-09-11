package myssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	xhttptunnel "github.com/NNdroid/xhttptunnel/tunnel"
)

func dialXHTTPSDK(ctx context.Context, cfg ProxyConfig, tlsEnabled bool) (net.Conn, error) {
	scheme := "http"
	if tlsEnabled {
		scheme = "https"
	}
	endpoint, path, err := sdkProxyEndpoint(cfg, scheme, "/stream")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.SshAddr) == "" {
		return nil, errors.New("ssh_addr is required")
	}
	if cfg.XhttpChunkSizeKB < 0 {
		return nil, errors.New("xhttp_chunk_size_kb must be non-negative")
	}
	if cfg.XhttpChunkSizeKB > 900 {
		return nil, errors.New("xhttp_chunk_size_kb must be <= 900")
	}
	psk := ""
	if cfg.ProxyAuthRequired {
		psk = strings.TrimSpace(cfg.ProxyAuthToken)
		if psk == "" {
			return nil, errors.New("proxy_auth_token is required when proxy_auth_required is true")
		}
	}
	// 下行传输模式：空/auto（默认）由 SDK 自适应（流式优先、轮询回退），
	// 也可强制 stream 或 poll。
	streamMode, err := normalizeXHTTPStreamMode(cfg.XhttpStreamMode)
	if err != nil {
		return nil, err
	}
	serverURL := strings.TrimRight(endpoint, "/") + path
	client, err := xhttptunnel.NewClient(xhttptunnel.ClientConfig{
		ServerURL:   serverURL,
		PSK:         psk,
		StreamMode:  streamMode,
		SNI:         strings.TrimSpace(cfg.ServerName),
		Host:        strings.TrimSpace(cfg.CustomHost),
		ALPN:        normalizeXHTTPALPN(cfg.Alpn),
		Fingerprint: sdkCertificateFingerprint(cfg),
		DialContext: sdkTCPDialer(cfg),
		QUICDial:    sdkQUICDialer(cfg),
		ChunkSizeKB: cfg.XhttpChunkSizeKB,
		Logger:      sdkZap("xhttp"),
	})
	if err != nil {
		return nil, fmt.Errorf("create xhttptunnel client: %w", err)
	}
	client.SetEventHandler(emitXhttpEvent)
	conn, err := client.DialContext(ctx, "tcp", cfg.SshAddr)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	zlog.Infof("%s [Tunnel] ✅ xhttptunnel SDK connected | endpoint=%s target=%s", TAG, serverURL, cfg.SshAddr)
	return ownSDKConn(conn, client.Close), nil
}

// normalizeXHTTPStreamMode 归一化 xhttp_stream_mode 配置：
// 空值返回 ""（SDK 端等同于 auto 自适应），非法值报错。
func normalizeXHTTPStreamMode(value string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(value))
	switch mode {
	case "", "auto", "stream", "poll":
		return mode, nil
	default:
		return "", fmt.Errorf("xhttp_stream_mode must be one of: auto, stream, poll (got %q)", value)
	}
}

// emitXhttpEvent 将 xhttptunnel 的 typed 事件归一化后转发。
func emitXhttpEvent(ev xhttptunnel.Event) {
	e := TunnelEvent{Source: "xhttp"}
	switch ev := ev.(type) {
	case xhttptunnel.TunnelEstablished:
		e.Type = TunnelEventEstablished
		e.Session = ev.SessionID
		e.Detail = fmt.Sprintf("%s://%s", ev.Network, ev.Target)
	case xhttptunnel.TunnelDied:
		e.Type = TunnelEventDied
		e.Session = ev.SessionID
		e.Detail = "reason=" + ev.Reason
		e.ErrText = ev.Detail
	case xhttptunnel.Reconnecting:
		e.Type = TunnelEventReconnecting
		e.Session = ev.SessionID
		e.Attempt = ev.Nth
		e.Detail = "previous round ended: " + ev.Reason
	case xhttptunnel.TargetDenied:
		e.Type = TunnelEventTargetDenied
		e.Session = ev.SessionID
		e.Detail = "target=" + ev.Target + " remote=" + ev.Remote
	case xhttptunnel.AuthRejected:
		e.Type = TunnelEventTargetDenied // 归并为策略拒绝类
		e.Detail = "auth rejected by server"
	default:
		return
	}
	emitTunnelEvent(e)
}

func init() {
	// xhttp：TLS 由配置开关决定（明文 xhttp 与 TLS xhttp 同一类型）。
	RegisterTunnel("xhttp", "custom", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		if baseConn != nil {
			_ = baseConn.Close()
		}
		return dialXHTTPSDK(ctx, cfg, cfg.TunnelTLSEnabled)
	})
}
