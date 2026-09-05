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
	psk := ""
	if cfg.ProxyAuthRequired {
		psk = strings.TrimSpace(cfg.ProxyAuthToken)
		if psk == "" {
			return nil, errors.New("proxy_auth_token is required when proxy_auth_required is true")
		}
	}
	serverURL := strings.TrimRight(endpoint, "/") + path
	client, err := xhttptunnel.NewClient(xhttptunnel.ClientConfig{
		ServerURL:   serverURL,
		PSK:         psk,
		SNI:         strings.TrimSpace(cfg.ServerName),
		Host:        strings.TrimSpace(cfg.CustomHost),
		ALPN:        normalizeXHTTPALPN(cfg.Alpn),
		Fingerprint: sdkCertificateFingerprint(cfg),
		DialContext: sdkTCPDialer(cfg),
		QUICDial:    sdkQUICDialer(cfg),
		ChunkSizeKB: cfg.XhttpChunkSizeKB,
	})
	if err != nil {
		return nil, fmt.Errorf("create xhttptunnel client: %w", err)
	}
	conn, err := client.DialContext(ctx, "tcp", cfg.SshAddr)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	zlog.Infof("%s [Tunnel] ✅ xhttptunnel SDK connected | endpoint=%s target=%s", TAG, serverURL, cfg.SshAddr)
	return ownSDKConn(conn, client.Close), nil
}

func init() {
	RegisterTunnel("xhttpc", "custom", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		if baseConn != nil {
			_ = baseConn.Close()
		}
		return dialXHTTPSDK(ctx, cfg, false)
	})
	RegisterTunnel("xhttp", "custom", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		if baseConn != nil {
			_ = baseConn.Close()
		}
		return dialXHTTPSDK(ctx, cfg, true)
	})
}
