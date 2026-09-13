package myssh

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	udpclient "github.com/NNdroid/udp_custom/tunnel"
)

func parseUDPCMagicSDK(value string) (uint32, error) {
	v, err := parseMagicSDK(value, true, "udp_custom")
	if err != nil {
		return 0, err
	}
	if v == 0 {
		// 空输入（或显式 0x00000000）由 SDK 解析为默认魔数。
		return udpclient.UDPC_MAGIC_DEFAULT, nil
	}
	return v, nil
}

// normalizeUdpMtuProbe 解析 udp_custom_mtu_probe 配置为 SDK 的 *bool：
//   - ""/auto => nil（走 SDK 默认：开启，对端为旧版时自动回落）
//   - "on"/"true"/"1" => &true（强制开启路径 MTU 探测）
//   - "off"/"false"/"0" => &false（关闭探测，按 MaxPkt 固定分片）
//   - 其它值报错，不静默猜测。
func normalizeUdpMtuProbe(value string) (*bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto":
		return nil, nil
	case "on", "true", "1":
		t := true
		return &t, nil
	case "off", "false", "0":
		f := false
		return &f, nil
	default:
		return nil, fmt.Errorf("udp_custom_mtu_probe must be one of: auto, on, off (got %q)", value)
	}
}

// parseMagicSDK 两种自定义隧道的统一魔数解析核心：
//   - 空值 → 0（默认魔数的语义由调用方/SDK 决定）；
//   - 0x/0X 前缀 → 1-8 位十六进制，左补零；
//   - allowRaw（udp_custom）：恰好 4 字节原文，如 "UDPC" —— HTTP Custom
//     生态的传统，服务器侧真实存在可打印魔数；
//   - !allowRaw（icmp_custom）：必须 8 位 hex。ASCII 词被刻意拒绝——魔数
//     在 Echo 载荷里明文传输，可打印串会成为中间设备的静态匹配指纹，
//     且 icmp_custom 没有使用可打印魔数的存量服务器，拒绝零兼容成本。
//
// what 用于错误信息中的字段名（udp_custom_magic / icmp_custom_magic）。
func parseMagicSDK(value string, allowRaw bool, what string) (uint32, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	if strings.HasPrefix(strings.ToLower(value), "0x") {
		return parseHexMagic(value[2:])
	}
	if allowRaw {
		if len(value) != 4 {
			return 0, fmt.Errorf("%s_magic must contain exactly 4 bytes (or 0x-prefixed hex)", what)
		}
		return binary.BigEndian.Uint32([]byte(value)), nil
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 4 {
		return 0, fmt.Errorf("%s_magic must be 8 hex characters (or 0x-prefixed hex)", what)
	}
	return binary.BigEndian.Uint32(raw), nil
}

// parseHexMagic 解析 1-8 位十六进制数字为 uint32（大端语义，不足左补零）。
// 输入不含 0x 前缀。
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
	warnWeakPSK("udp_custom", psk)
	magic, err := parseUDPCMagicSDK(cfg.UdpCustomMagic)
	if err != nil {
		return nil, err
	}

	paths := cfg.UdpCustomPaths
	if paths <= 0 {
		paths = 32
	}
	sockets := cfg.UdpCustomSockets
	if sockets <= 0 {
		sockets = 1
	}
	sendWindow := cfg.UdpCustomSendWindow
	if sendWindow <= 0 {
		sendWindow = 256
	}
	clientCfg := udpclient.ClientConfig{
		ServerAddr: serverAddr,
		Passwords:  []string{psk},
		Magic:      magic,
		Sockets:    sockets,
		Paths:      paths,
		SendWindow: sendWindow,
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
	if cfg.UdpCustomMaxPkt < 0 {
		return nil, errors.New("udp_custom_max_pkt must be non-negative")
	}
	if cfg.UdpCustomMaxPkt > 0 {
		clientCfg.MaxPkt = cfg.UdpCustomMaxPkt // 0 => SDK 默认 1450，此处仅在显式设置时下发
	}
	if probe, err := normalizeUdpMtuProbe(cfg.UdpCustomMtuProbe); err != nil {
		return nil, err
	} else if probe != nil {
		clientCfg.MtuProbe = probe // nil 走 SDK 默认（开启）
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
