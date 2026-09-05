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
	client, err := dnstunnel.NewClient(dnstunnel.ClientConfig{
		Domain:     strings.TrimSpace(cfg.DnsTunnelDomain),
		Servers:    cfg.DnsTunnelServers,
		RecordType: strings.TrimSpace(cfg.DnsTunnelType),
		PublicKey:  strings.TrimSpace(cfg.DnsTunnelPublicKey),
		Target:     "tcp://" + strings.TrimSpace(cfg.SshAddr),
		EDNS0:      cfg.DnsTunnelEDNS0,
		Dialer:     newProtectedDialer(cfg, 4*time.Second),
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

func init() {
	RegisterTunnel("dns_custom", "custom", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		if baseConn != nil {
			_ = baseConn.Close()
		}
		return NewDNSTunnel(ctx, cfg)
	})
}
