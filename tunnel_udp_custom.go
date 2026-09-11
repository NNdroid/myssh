package myssh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	udpclient "github.com/NNdroid/udp_custom/tunnel"
)

func parseUDPCMagicSDK(value string) (uint32, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return udpclient.UDPC_MAGIC_DEFAULT, nil
	}
	// 0x/0X 前缀：按十六进制数值解析（1-8 位），如 0x55445043 等价于 "UDPC"。
	if strings.HasPrefix(strings.ToLower(value), "0x") {
		return parseHexMagic(value[2:])
	}
	if len(value) != 4 {
		return 0, errors.New("udp_custom_magic must contain exactly 4 bytes (or 0x-prefixed hex)")
	}
	return binary.BigEndian.Uint32([]byte(value)), nil
}

// parseHexMagic 解析 1-8 位十六进制数字为 uint32（大端语义，不足左补零）。
// 两个 magic 解析器共用；输入不含 0x 前缀。
func parseHexMagic(digits string) (uint32, error) {
	if digits == "" {
		return 0, errors.New("magic is empty after 0x prefix")
	}
	if len(digits) > 8 {
		return 0, fmt.Errorf("magic hex digits too long: %q (want 1-8 hex digits)", digits)
	}
	v, err := strconv.ParseUint(digits, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid magic hex digits %q: %w", digits, err)
	}
	return uint32(v), nil
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
		Logger:     sdkUDPLogger("udp_custom"),
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
	client.SetEventHandler(emitUDPCEvent)
	target := "tcp://" + strings.TrimSpace(cfg.SshAddr)
	conn, err := client.DialTunnel(ctx, udpclient.DialOptions{Target: target})
	if err != nil {
		client.Close()
		return nil, err
	}
	zlog.Infof("%s [Tunnel] ✅ udp_custom SDK connected | server=%s target=%s", TAG, serverAddr, target)
	return ownSDKConn(conn, func() error { client.Close(); return nil }), nil
}

// emitUDPCEvent 将 udp_custom 事件归一化后转发。
func emitUDPCEvent(ev udpclient.ClientEvent) {
	e := TunnelEvent{Source: "udp_custom", Detail: ev.Detail, Attempt: ev.Attempt}
	if ev.Session != 0 {
		e.Session = fmt.Sprintf("%d", ev.Session)
	}
	switch ev.Kind {
	case udpclient.TunnelEstablished:
		e.Type = TunnelEventEstablished
	case udpclient.TunnelDied:
		e.Type = TunnelEventDied
	case udpclient.Reconnecting:
		e.Type = TunnelEventReconnecting
	case udpclient.HandshakeRetrying:
		e.Type = TunnelEventHandshakeRetrying
	default:
		return
	}
	emitTunnelEvent(e)
}

func init() {
	RegisterTunnel("udp_custom", "custom", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		if baseConn != nil {
			_ = baseConn.Close()
		}
		return dialUDPCustomSDK(ctx, cfg)
	})
}
