package myssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	dnstunnel "github.com/NNdroid/dns_custom"
)

func NewDNSTunnel(ctx context.Context, cfg ProxyConfig) (net.Conn, error) {
	if strings.TrimSpace(cfg.SshAddr) == "" {
		return nil, errors.New("ssh_addr is required")
	}
	psk := strings.TrimSpace(cfg.DnsTunnelPsk)
	if psk != "" {
		warnWeakPSK("dns_custom", psk)
	}
	client, err := dnstunnel.NewClient(dnstunnel.ClientConfig{
		Domain:       strings.TrimSpace(cfg.DnsTunnelDomain),
		Servers:      cfg.DnsTunnelServers,
		RecordType:   strings.TrimSpace(cfg.DnsTunnelType),
		PublicKey:    strings.TrimSpace(cfg.DnsTunnelPublicKey),
		Target:       "tcp://" + strings.TrimSpace(cfg.SshAddr),
		EDNS0:        cfg.DnsTunnelEDNS0,
		PSK:          psk,
		Marker:       strings.TrimSpace(cfg.DnsTunnelMarker),
		Logger:       sdkSugared("dns_custom"),
		EventHandler: emitDNSEvent,
		Dialer:       newProtectedDialer(cfg, 4*time.Second),
	})
	if err != nil {
		return nil, fmt.Errorf("create dns_custom client: %w", err)
	}
	conn, err := client.Dial(ctx)
	if err != nil {
		return nil, err
	}
	zlog.Infof("%s [Tunnel] ✅ dns_custom SDK connected | domain=%s target=%s", TAG, cfg.DnsTunnelDomain, cfg.SshAddr)
	return conn, nil
}

// emitDNSEvent 将 dns_custom 事件归一化后转发。
func emitDNSEvent(ev dnstunnel.ClientEvent) {
	e := TunnelEvent{Source: "dns_custom", Session: ev.Session, Attempt: ev.Attempt}
	parts := make([]string, 0, 3)
	if ev.Target != "" {
		parts = append(parts, "target="+ev.Target)
	}
	if ev.Transport != "" {
		parts = append(parts, "transport="+ev.Transport)
	}
	switch ev.Kind {
	case dnstunnel.ClientTunnelEstablished:
		e.Type = TunnelEventEstablished
	case dnstunnel.ClientTunnelDied:
		e.Type = TunnelEventDied
		parts = append(parts, "reason="+ev.Reason)
	case dnstunnel.ClientReconnecting:
		e.Type = TunnelEventReconnecting
		parts = append(parts, "retrying chunk")
	case dnstunnel.ClientTargetDenied:
		e.Type = TunnelEventTargetDenied
	default:
		return
	}
	if ev.Err != nil {
		e.ErrText = ev.Err.Error()
	}
	e.Detail = strings.Join(parts, " ")
	emitTunnelEvent(e)
}

func init() {
	RegisterTunnel("dns_custom", "custom", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		if baseConn != nil {
			_ = baseConn.Close()
		}
		return NewDNSTunnel(ctx, cfg)
	})
}
