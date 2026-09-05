package myssh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

	udpclient "github.com/NNdroid/udp_custom/tunnel"
)

func parseUDPCMagicSDK(value string) (uint32, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return udpclient.UDPC_MAGIC_DEFAULT, nil
	}
	if len(value) != 4 {
		return 0, errors.New("udp_custom_magic must contain exactly 4 bytes")
	}
	return binary.BigEndian.Uint32([]byte(value)), nil
}

func dialUDPCustomSDK(ctx context.Context, cfg ProxyConfig) (net.Conn, error) {
	serverAddr := strings.TrimSpace(cfg.ProxyAddr)
	if serverAddr == "" {
		return nil, errors.New("proxy_addr is required")
	}
	if strings.TrimSpace(cfg.SshAddr) == "" {
		return nil, errors.New("ssh_addr is required")
	}
	psk := strings.TrimSpace(cfg.UdpCustomPsk)
	if psk == "" {
		return nil, errors.New("udp_custom_psk is required by udp_custom protocol v2")
	}
	magic, err := parseUDPCMagicSDK(cfg.UdpCustomMagic)
	if err != nil {
		return nil, err
	}

	paths := cfg.UdpCustomPaths
	if paths == 0 {
		paths = 32
	}
	clientCfg := udpclient.ClientConfig{
		ServerAddr: serverAddr,
		Passwords:  []string{psk},
		Magic:      magic,
		Sockets:    cfg.UdpCustomSockets,
		Paths:      paths,
		SendWindow: cfg.UdpCustomSendWindow,
		Logger:     udpclient.Nop,
		ListenUDP: func(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
			pc, err := rangeListenConfig(cfg).ListenPacket(ctx, network, laddr.String())
			if err != nil {
				return nil, err
			}
			udpConn, ok := pc.(*net.UDPConn)
			if !ok {
				_ = pc.Close()
				return nil, fmt.Errorf("protected UDP listener returned %T, want *net.UDPConn", pc)
			}
			return udpConn, nil
		},
	}
	if key := strings.TrimSpace(cfg.UdpCustomPublicKey); key != "" {
		clientCfg.ServerPub, err = udpclient.ParseNoiseKey(key)
		if err != nil {
			return nil, fmt.Errorf("invalid udp_custom_public_key: %w", err)
		}
	}

	client, err := udpclient.NewClient(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("create udp_custom client: %w", err)
	}
	target := "tcp://" + strings.TrimSpace(cfg.SshAddr)
	conn, err := client.DialTunnel(ctx, udpclient.DialOptions{Target: target})
	if err != nil {
		client.Close()
		return nil, err
	}
	zlog.Infof("%s [Tunnel] ✅ udp_custom SDK connected | server=%s target=%s", TAG, serverAddr, target)
	return ownSDKConn(conn, func() error { client.Close(); return nil }), nil
}

func init() {
	RegisterTunnel("udp_custom", "custom", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		if baseConn != nil {
			_ = baseConn.Close()
		}
		return dialUDPCustomSDK(ctx, cfg)
	})
}
