package myssh

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"

	icmpclient "github.com/NNdroid/icmp_custom/tunnel"
)

// parseICMPMagicSDK 解析记录魔数；空值返回 0，由 SDK 取 MagicDefault。
// 接受 8 位 hex 或 0x/0X 前缀的 1-8 位十六进制。刻意不接受 ASCII 词：
// 魔数在密文外明文传输，"UDPC" 这类可打印字符串会成为中间设备的静态
// 匹配指纹。
func parseICMPMagicSDK(value string) (uint32, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	if strings.HasPrefix(strings.ToLower(value), "0x") {
		return parseHexMagic(value[2:])
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 4 {
		return 0, errors.New("icmp_custom_magic must be 8 hex characters (or 0x-prefixed hex)")
	}
	return binary.BigEndian.Uint32(raw), nil
}

func dialICMPCustomSDK(ctx context.Context, cfg ProxyConfig) (net.Conn, error) {
	serverAddr := strings.TrimSpace(cfg.ProxyAddr)
	if serverAddr == "" {
		return nil, errors.New("proxy_addr is required (ICMP peer host, no port)")
	}
	if strings.TrimSpace(cfg.SshAddr) == "" {
		return nil, errors.New("ssh_addr is required")
	}
	psk := strings.TrimSpace(cfg.IcmpCustomPsk)
	if psk == "" {
		return nil, errors.New("icmp_custom_psk is required by icmp_custom protocol v2")
	}
	magic, err := parseICMPMagicSDK(cfg.IcmpCustomMagic)
	if err != nil {
		return nil, err
	}

	clientCfg := icmpclient.ClientConfig{
		ServerAddr: serverAddr,
		Passwords:  []string{psk},
		Magic:      magic,
		Logger:     sdkLogAdapter{log: sdkSugared("icmp_custom")},
		// Android 上 ICMP 载体 socket 必须豁免 VpnService，否则 Echo 流量
		// 被自己的 VPN 捕获形成回环；桌面平台返回 nil（SDK 视为不设防）。
		ProtectFD: icmpProtectFD(),
	}
	if key := strings.TrimSpace(cfg.IcmpCustomPublicKey); key != "" {
		clientCfg.ServerPub, err = icmpclient.ParseNoiseKey(key)
		if err != nil {
			return nil, fmt.Errorf("invalid icmp_custom_public_key: %w", err)
		}
	}
	// 空值交给 SDK 默认：family=auto，mtu_mode=probe。
	clientCfg.ICMP.Family = strings.ToLower(strings.TrimSpace(cfg.IcmpCustomFamily))
	clientCfg.ICMP.MTUMode = strings.ToLower(strings.TrimSpace(cfg.IcmpCustomMtuMode))
	if v := cfg.IcmpCustomMaxPayload; v > 0 {
		clientCfg.ICMP.MaxPayload = v
	}
	if v := cfg.IcmpCustomPaceMS; v > 0 {
		clientCfg.ICMP.PaceMS = v
	}
	clientCfg.ICMP.IDRange = strings.TrimSpace(cfg.IcmpCustomIdRange)

	client, err := icmpclient.NewClient(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("create icmp_custom client: %w", err)
	}
	client.SetEventHandler(emitICMPEvent)

	conn, err := client.DialTunnel(ctx, icmpclient.DialOptions{Target: "tcp://" + strings.TrimSpace(cfg.SshAddr)})
	if err != nil {
		client.Close()
		return nil, err
	}
	zlog.Infof("%s [Tunnel] ✅ icmp_custom SDK connected | server=%s target=%s", TAG, serverAddr, cfg.SshAddr)
	return ownSDKConn(conn, func() error { client.Close(); return nil }), nil
}

// emitICMPEvent 将 icmp_custom 事件归一化后转发；事件形状与 udp_custom 一致。
func emitICMPEvent(ev icmpclient.ClientEvent) {
	e := TunnelEvent{Source: "icmp_custom", Detail: ev.Detail, Attempt: ev.Attempt}
	if ev.Session != 0 {
		e.Session = fmt.Sprintf("%d", ev.Session)
	}
	switch ev.Kind {
	case icmpclient.TunnelEstablished:
		e.Type = TunnelEventEstablished
	case icmpclient.TunnelDied:
		e.Type = TunnelEventDied
	case icmpclient.Reconnecting:
		e.Type = TunnelEventReconnecting
	case icmpclient.HandshakeRetrying:
		e.Type = TunnelEventHandshakeRetrying
	default:
		return
	}
	emitTunnelEvent(e)
}

func init() {
	// ICMP 载体由 SDK 自行开 socket（raw/ping socket），无需底层拨号。
	RegisterTunnel("icmp_custom", "custom", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		if baseConn != nil {
			_ = baseConn.Close()
		}
		return dialICMPCustomSDK(ctx, cfg)
	})
}
