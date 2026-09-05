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
		},
		Dialer: sdkTCPDialer(cfg),
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

func init() {
	registerH2SDK("h2c", h2tunnel.TransportH2C, false)
	registerH2SDK("h2", h2tunnel.TransportH2, true)
	registerH2SDK("grpcc", h2tunnel.TransportGRPC, false)
	registerH2SDK("grpc", h2tunnel.TransportGRPC, true)
}
