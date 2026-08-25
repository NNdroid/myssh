package myssh

import (
	"context"
	"crypto/sha1"
	"fmt"
	"net"
	"strings"

	kcp "github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

func createKcpBlockCrypt(key string, method string) (kcp.BlockCrypt, error) {
	if key == "" || strings.ToLower(method) == "none" || method == "" {
		return nil, nil
	}

	pass := pbkdf2.Key([]byte(key), []byte("kcp-salt"), 4096, 32, sha1.New)

	switch strings.ToLower(method) {
	case "aes", "aes-128":
		return kcp.NewAESBlockCrypt(pass[:16])
	case "aes-192":
		return kcp.NewAESBlockCrypt(pass[:24])
	case "aes-256":
		return kcp.NewAESBlockCrypt(pass[:32])
	case "aes-gcm":
		return kcp.NewAESGCMCrypt(pass[:16])
	case "salsa20":
		return kcp.NewSalsa20BlockCrypt(pass[:32])
	case "sm4":
		return kcp.NewSM4BlockCrypt(pass[:16])
	case "twofish":
		return kcp.NewTwofishBlockCrypt(pass[:32])
	case "blowfish":
		return kcp.NewBlowfishBlockCrypt(pass[:32])
	case "cast5":
		return kcp.NewCast5BlockCrypt(pass[:16])
	case "3des":
		return kcp.NewTripleDESBlockCrypt(pass[:24])
	case "tea":
		return kcp.NewTEABlockCrypt(pass[:16])
	case "xtea":
		return kcp.NewXTEABlockCrypt(pass[:16])
	case "xor":
		return kcp.NewSimpleXORBlockCrypt(pass[:16])
	default:
		return kcp.NewAESBlockCrypt(pass[:16])
	}
}

func init() {
	RegisterTunnel("kcp", "udp", func(parentCtx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {
		target := cfg.ProxyAddr
		if target == "" {
			target = cfg.SshAddr
		}
		zlog.Infof("%s [Tunnel] 2. Preparing KCP (UDP) handshake, Target: %s, Crypt: %s", TAG, target, cfg.KcpCrypt)

		packetConn, ok := baseConn.(net.PacketConn)
		if !ok || packetConn == nil {
			return nil, fmt.Errorf("KCP tunnel requires a valid net.PacketConn, got %T", baseConn)
		}

		block, err := createKcpBlockCrypt(cfg.KcpPassword, cfg.KcpCrypt)
		if err != nil {
			zlog.Errorf("%s [Tunnel] ❌ Failed to create KCP BlockCrypt: %v", TAG, err)
			return nil, err
		}

		dataShards := cfg.KcpDataShards
		parityShards := cfg.KcpParityShards
		if dataShards <= 0 || parityShards < 0 {
			dataShards = 10
			parityShards = 3
		}

		sess, err := kcp.NewConn(target, block, dataShards, parityShards, packetConn)
		if err != nil {
			zlog.Errorf("%s [Tunnel] ❌ Failed to create KCP session: %v", TAG, err)
			return nil, err
		}

		sess.SetStreamMode(true)
		sess.SetWriteDelay(false)
		sess.SetACKNoDelay(true)

		if cfg.KcpNoDelay {
			// 极速模式: nodelay=1, interval=10ms, resend=2, nc=1
			sess.SetNoDelay(1, 10, 2, 1)
			sess.SetWindowSize(128, 512)
			zlog.Infof("%s [Tunnel] ⚡ KCP turbo mode (nodelay=1, interval=10ms, resend=2) enabled", TAG)
		} else {
			// 普通低延迟模式: nodelay=1, interval=20ms, resend=1, nc=1
			sess.SetNoDelay(1, 20, 1, 1)
			sess.SetWindowSize(64, 256)
		}

		go func() {
			<-parentCtx.Done()
			if sess != nil {
				sess.Close()
			}
		}()

		zlog.Infof("%s [Tunnel] ✅ KCP session established with %s", TAG, target)
		return sess, nil
	})
}
