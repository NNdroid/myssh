package myssh

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"net"
	"strings"

	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/pbkdf2"

	kcptun "myssh/pkg/kcptun"
)

// kcptun 隧道：兼容 kcptun 协议（原 Go kcptun / kcptun-rs）的客户端实现。
//
// 协议栈（与 kcptun 客户端 createConn 一致）：
//
//	SSH → SMUX stream → [Snappy 会话压缩（可关）] → KCP 会话（kcptun 密钥派生
//	+ BlockCrypt + FEC）→ UDP
//
// 服务端侧：kcptun-rs / 原 Go kcptun，用 -t/--target 固定转发到 sshd——
// 与 kcptun 的 SOCKS5 动态寻址不同，这里整条 SSH 会话走一条 SMUX stream。
func dialKcptunSDK(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
	packetConn, ok := baseConn.(net.PacketConn)
	if baseConn == nil || !ok {
		return nil, fmt.Errorf("kcptun tunnel requires a net.PacketConn, got %T", baseConn)
	}
	serverAddr := strings.TrimSpace(cfg.ProxyAddr)
	if serverAddr == "" {
		return nil, errors.New("proxy_addr is required")
	}
	if strings.TrimSpace(cfg.SshAddr) == "" {
		return nil, errors.New("ssh_addr is required")
	}
	psk := strings.TrimSpace(cfg.KcpPassword)
	if psk == "" {
		return nil, errors.New("kcp_password is required")
	}

	// kcptun 兼容密钥派生：PBKDF2-HMAC-SHA1, salt "kcp-go", 4096 轮, 32 字节。
	pass := pbkdf2.Key([]byte(psk), []byte("kcp-go"), 4096, 32, sha1.New)
	block, effectiveCrypt := kcptun.SelectBlockCrypt(strings.ToLower(strings.TrimSpace(cfg.KcpCrypt)), pass)

	dataShards, parityShards := cfg.KcpDataShards, cfg.KcpParityShards
	if dataShards <= 0 {
		dataShards = 10
	}
	if parityShards < 0 {
		parityShards = 3
	}

	sess, err := kcp.NewConn(serverAddr, block, dataShards, parityShards, packetConn)
	if err != nil {
		baseConn.Close()
		return nil, fmt.Errorf("create kcp session: %w", err)
	}

	sess.SetStreamMode(true)
	sess.SetWriteDelay(false)
	// mode 预设（kcptun std.PredefinedModes）：normal/fast/fast2/fast3，
	// 未知值回落 fast——KCP 参数只影响性能，不影响 wire 兼容。
	noDelay, interval, resend, noCongestion := 0, 30, 2, 1 // "normal"
	if params, ok := kcptun.PredefinedModes[strings.ToLower(strings.TrimSpace(cfg.KcpMode))]; ok {
		noDelay, interval, resend, noCongestion = params.NoDelay, params.Interval, params.Resend, params.NoCongestion
	}
	sess.SetNoDelay(noDelay, interval, resend, noCongestion)
	snd, rcv := cfg.KcpSndWnd, cfg.KcpRcvWnd
	if snd <= 0 {
		snd = 128
	}
	if rcv <= 0 {
		rcv = 512
	}
	sess.SetWindowSize(snd, rcv)
	mtu := cfg.KcpMtu
	if mtu <= 0 {
		mtu = 1350
	}
	sess.SetMtu(mtu)
	sess.SetACKNoDelay(true)

	// 会话层：Snappy 压缩（NoComp 关闭时启用）→ SMUX（v1/v2）。
	var carrier net.Conn = sess
	if !cfg.KcpNoComp {
		carrier = kcptun.NewCompStream(sess)
	}
	smuxVer := cfg.KcpSmuxVer
	if smuxVer <= 0 {
		smuxVer = 2
	}
	keepAlive := cfg.KcpKeepAlive
	if keepAlive <= 0 {
		keepAlive = 10
	}
	smuxCfg, err := kcptun.BuildSmuxConfig(smuxVer, 4194304, 2097152, 8192, keepAlive)
	if err != nil {
		sess.Close()
		baseConn.Close()
		return nil, fmt.Errorf("build smux config: %w", err)
	}
	smuxSession, err := smux.Client(carrier, smuxCfg)
	if err != nil {
		sess.Close()
		baseConn.Close()
		return nil, fmt.Errorf("create smux session: %w", err)
	}

	stream, err := smuxSession.OpenStream()
	if err != nil {
		smuxSession.Close()
		sess.Close()
		baseConn.Close()
		return nil, fmt.Errorf("open smux stream: %w", err)
	}

	zlog.Infof("%s [Tunnel] ✅ kcptun connected | server=%s crypt=%s(fallback=%s) fec=%d/%d smux=v%d target=%s",
		TAG, serverAddr, cfg.KcpCrypt, effectiveCrypt, dataShards, parityShards, smuxVer, cfg.SshAddr)

	// SSH 会话整体跑在这一条 SMUX stream 上；stream/SMUX 会话/KCP 会话
	// 任一关闭即级联，ctx 取消由 watchEngineCtx 触发整条链关闭。
	return watchEngineCtx(ctx, ownSDKConn(stream, func() error {
		_ = smuxSession.Close()
		return sess.Close()
	})), nil
}

func init() {
	// kcptun：协议客户端（KCP + [Snappy] + SMUX），服务端为 kcptun-rs /
	// 原 Go kcptun（-t 固定转发到 sshd）。载体 socket 由 dialTunnel 的
	// "udp" 网络提供（已做 bind/protect）。
	RegisterTunnel("kcptun", "udp", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		return dialKcptunSDK(ctx, cfg, baseConn)
	})
}
