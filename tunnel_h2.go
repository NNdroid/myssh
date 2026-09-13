package myssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	h2tunnel "github.com/NNdroid/h2tunnel"
)

func dialH2SDK(ctx context.Context, cfg ProxyConfig, transport h2tunnel.Transport, tlsEnabled bool) (net.Conn, error) {
	scheme := "http"
	if tlsEnabled {
		scheme = "https"
	}
	endpoint, path, err := sdkProxyEndpoint(cfg, scheme, "/tunnel")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.SshAddr) == "" {
		return nil, errors.New("ssh_addr is required")
	}

	var credentials h2tunnel.CredentialProvider
	if cfg.ProxyAuthRequired {
		credentials, err = h2tunnel.NewTokenCredentials(strings.TrimSpace(cfg.ProxyAuthToken))
		if err != nil {
			return nil, fmt.Errorf("h2tunnel credentials: %w", err)
		}
	}

	var heartbeat time.Duration
	if cfg.HeartbeatIntervalMs < 0 {
		return nil, errors.New("heartbeat_interval_ms must be non-negative")
	}
	if cfg.HeartbeatIntervalMs > 0 {
		heartbeat = time.Duration(cfg.HeartbeatIntervalMs) * time.Millisecond
	}

	options := h2tunnel.ClientOptions{
		Endpoint:    endpoint,
		Path:        path,
		Transport:   transport,
		Host:        strings.TrimSpace(cfg.CustomHost),
		Credentials: credentials,
		Tuning: h2tunnel.ClientTuning{
			HeartbeatInterval: heartbeat,
			PaddingMinBytes:   resolveH2PaddingMin(cfg.PaddingMinBytes), // 0 => myssh 默认 1420；正数按值；负数关闭
		},
		EventHandler: emitH2Event,
		Logger:       sdkSlog("h2tunnel"),
		Dialer:       sdkTCPDialer(cfg),
	}
	// QUIC 类（h3/webtransport/masque）由 quic-go 内部做 TLS，不接受 uTLS 伪装；
	// 只有走 crypto/tls-over-TCP 的 h2/grpc 才支持浏览器 ClientHello 指纹。
	// 固定成 Chrome（HelloChrome_Auto），与 raw/ws/xhttp 一致。证书指纹 pinning
	// 仍由 sdkTLSConfig→MakePeerCertVerifier 生效：h2tunnel 7c6d201 起 uTLS 路径
	// 会搬运 VerifyPeerCertificate（并刻意不复用会话票据，避免 resumed 连接跳过
	// pinning），故伪装与指纹校验可安全共存。
	isQUIC := transport == h2tunnel.TransportH3 ||
		transport == h2tunnel.TransportWebTransport ||
		transport == h2tunnel.TransportMASQUE
	options.UtlxFingerprint = h2UtlxFingerprint(tlsEnabled, isQUIC)
	// MasqueALPN 仅对 masque 有意义（SDK 会拒绝其它 transport 上设置它）。
	if transport == h2tunnel.TransportMASQUE {
		if a := normalizeMasqueALPN(cfg.MasqueAlpn); a != "" {
			options.Tuning.MasqueALPN = a
		}
	}
	if tlsEnabled {
		options.TLSConfig = sdkTLSConfig(cfg)
		options.QUICDialer = sdkQUICDialer(cfg)
	}

	client, err := h2tunnel.NewClient(options)
	if err != nil {
		return nil, fmt.Errorf("create h2tunnel client: %w", err)
	}
	conn, err := client.DialContext(ctx, "tcp", cfg.SshAddr)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	zlog.Infof("%s [Tunnel] ✅ h2tunnel SDK connected | transport=%s endpoint=%s target=%s", TAG, transport, endpoint, cfg.SshAddr)
	return ownSDKConn(conn, client.Close), nil
}

func registerH2SDK(name string, transport h2tunnel.Transport, tlsEnabled bool) {
	RegisterTunnel(name, "custom", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		if baseConn != nil {
			_ = baseConn.Close()
		}
		return dialH2SDK(ctx, cfg, transport, tlsEnabled)
	})
}

// h2PaddingDefaultBytes 是 h2 家族出站帧最小填充字节的 myssh 默认值。
// h2tunnel SDK 把 0 视作 900，myssh 统一改用 1420（贴近典型路径 MTU）作为“未配置”时的取值。
const h2PaddingDefaultBytes = 1420

// resolveH2PaddingMin 把配置面的 padding_min_bytes 翻译为 SDK 取值：
//   - 0（未配置）=> 1420；
//   - 负数 => 原样（SDK：关闭填充）；
//   - 正数 => 原样（自定义下限，SDK 会夹到上限 0xFFFF）。
func resolveH2PaddingMin(v int) int {
	if v == 0 {
		return h2PaddingDefaultBytes
	}
	return v
}

// h2UtlxFingerprint 决定 TCP-TLS 的 h2/grpc 用哪个浏览器 ClientHello 伪装。
// 仅当 TLS 开启且非 QUIC 承载时返回 "chrome"（HelloChrome_Auto）；其余返回 ""
// （明文无 TLS 可伪装；QUIC 由 quic-go 内部做 TLS，不接受伪装）。证书指纹 pinning
// 自 h2tunnel 7c6d201 起可在伪装路径下正常生效，故不再按 verifyCertFP 关闭伪装。
func h2UtlxFingerprint(tlsEnabled, isQUIC bool) string {
	if tlsEnabled && !isQUIC {
		return "chrome"
	}
	return ""
}

// normalizeMasqueALPN 把配置面的 MASQUE 承载选择翻译为 h2tunnel SDK 取值：
//   - ""、auto、"h3,h2"、"h2,h3" => ""（SDK 自动协商）；
//   - "h3" => "h3"，"h2" => "h2"；
//   - 其它值小写后原样返回，交由 SDK 校验并拒绝（避免在此静默改写非法输入）。
func normalizeMasqueALPN(value string) string {
	v := strings.ToLower(strings.ReplaceAll(value, " ", ""))
	switch v {
	case "", "auto", "h3,h2", "h2,h3":
		return ""
	case "h3":
		return "h3"
	case "h2":
		return "h2"
	default:
		return v
	}
}

// emitH2Event 将 h2tunnel 事件归一化后转发。
func emitH2Event(ev h2tunnel.ClientEvent) {
	e := TunnelEvent{Source: "h2", Detail: ev.Reason, Attempt: ev.Attempt}
	if ev.Err != nil {
		e.ErrText = ev.Err.Error()
	}
	switch ev.Kind {
	case h2tunnel.EventTunnelEstablished:
		e.Type = TunnelEventEstablished
	case h2tunnel.EventTunnelDied:
		e.Type = TunnelEventDied
	case h2tunnel.EventReconnecting:
		e.Type = TunnelEventReconnecting
	case h2tunnel.EventTargetDenied:
		e.Type = TunnelEventTargetDenied
	default:
		return
	}
	emitTunnelEvent(e)
}

// registerH2SDKToggle 注册 TLS 由配置开关决定的 h2tunnel 隧道（grpc）。
func registerH2SDKToggle(name string, transport h2tunnel.Transport) {
	RegisterTunnel(name, "custom", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		if baseConn != nil {
			_ = baseConn.Close()
		}
		return dialH2SDK(ctx, cfg, transport, cfg.TunnelTLSEnabled)
	})
}

func init() {
	// h2：合并型——开关决定 TransportH2(TLS) / TransportH2C(明文)。
	RegisterTunnel("h2", "custom", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		if baseConn != nil {
			_ = baseConn.Close()
		}
		if cfg.TunnelTLSEnabled {
			return dialH2SDK(ctx, cfg, h2tunnel.TransportH2, true)
		}
		return dialH2SDK(ctx, cfg, h2tunnel.TransportH2C, false)
	})
	registerH2SDKToggle("grpc", h2tunnel.TransportGRPC)
}
