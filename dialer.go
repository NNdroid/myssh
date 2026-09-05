package myssh

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func newProtectedDialer(cfg ProxyConfig, timeout time.Duration) *net.Dialer {
	dialer := &net.Dialer{Timeout: timeout}
	if cfg.BindInterface != "" {
		zlog.Debugf("%s [Dialer] bind interface: %s", TAG, cfg.BindInterface)
		bindDevice(dialer, cfg.BindInterface)
	}
	return wrapAndroidProtect(dialer)
}

func dialProtected(ctx context.Context, cfg ProxyConfig, network, address string, timeout time.Duration) (net.Conn, error) {
	return newProtectedDialer(cfg, timeout).DialContext(ctx, network, address)
}

// info  TCP  info  Socket  info
// info  Nagle  info  (SetNoDelay)  info  ( info  SSH/ info )
// info  4MB， info  BDP ( info )  info
// info keepalive  info 15s
func applyOptimiseForTcpConnection(conn net.Conn) {
	//  info  net.Conn  info  *net.TCPConn
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		//  info  Nagle  info
		if err := tcpConn.SetNoDelay(true); err != nil {
			zlog.Warnf("%s [TCP Tune] Failed to set NoDelay: %v", TAG, err)
		}

		//  info
		if err := tcpConn.SetReadBuffer(tcpOptimizeBufferSize); err != nil {
			zlog.Warnf("%s [TCP Tune] Failed to set ReadBuffer: %v", TAG, err)
		}

		//  info
		if err := tcpConn.SetWriteBuffer(tcpOptimizeBufferSize); err != nil {
			zlog.Warnf("%s [TCP Tune] Failed to set WriteBuffer: %v", TAG, err)
		}

		//  info  TCP Keep-Alive
		if err := tcpConn.SetKeepAlive(true); err != nil {
			zlog.Warnf("%s [TCP Tune] Failed to enable KeepAlive: %v", TAG, err)
		} else {
			//  info  KeepAlive  info  15  info
			if err := tcpConn.SetKeepAlivePeriod(time.Duration(tcpKeepaliveIntervalSec) * time.Second); err != nil {
				zlog.Warnf("%s [TCP Tune] Failed to set KeepAlive period: %v", TAG, err)
			}
		}

		zlog.Debugf("%s [TCP Tune] 🚀 Successfully applied Socket optimizations (%dKB Buffer, NoDelay, KeepAlive)", TAG, tcpOptimizeBufferSize/1024)
	} else {
		zlog.Debugf("%s [TCP Tune] ⚠️ Current connection is not TCP, skipping optimization", TAG)
	}
}

// dialSocket is the unified entry point for creating all underlying sockets.
// It handles timeouts and interface binding.
func dialSocket(ctx context.Context, cfg ProxyConfig, network, address string) (net.Conn, error) {
	zlog.Debugf("%s [Dialer] 🎬 Starting dial (network=%s, address=%s)", TAG, network, address)

	dialer := &net.Dialer{Timeout: 10 * time.Second}

	// Apply interface binding if specified in the config.
	if cfg.BindInterface != "" {
		zlog.Debugf("%s [Dialer] 🌐 Attempting to bind to specified network interface: %s", TAG, cfg.BindInterface)
		bindDevice(dialer, cfg.BindInterface)
	} else {
		zlog.Debugf("%s [Dialer] 🌐 No bind interface specified, using default routing", TAG)
	}

	// Apply Android VpnService Protect.
	safeDialer := wrapAndroidProtect(dialer)

	zlog.Debugf("%s [Dialer] 📞 Executing DialContext...", TAG)
	conn, err := safeDialer.DialContext(ctx, network, address)
	if err != nil {
		zlog.Errorf("%s [Socket] ❌ Underlying %s connection failed: %v", TAG, strings.ToUpper(network), err)
		return nil, err
	}
	zlog.Infof("%s [Socket] ✅ Underlying %s connection established successfully: %s", TAG, strings.ToUpper(network), address)

	return conn, nil
}

// dialTCP is a wrapper for creating a TCP socket.
func dialTCP(ctx context.Context, cfg ProxyConfig, target string) (net.Conn, error) {
	tcpConn, err := dialSocket(ctx, cfg, "tcp", target)
	if err != nil {
		return nil, err
	}
	applyOptimiseForTcpConnection(tcpConn)
	return tcpConn, nil
}

// dialUDP is a wrapper for creating a UDP socket.
func dialUDP(ctx context.Context, cfg ProxyConfig, target string) (net.Conn, error) {
	return dialSocket(ctx, cfg, "udp", target)
}

// dialTunnel  info tunnel info ， info
func dialTunnel(ctx context.Context, cfg ProxyConfig) (net.Conn, error) {
	tunnelType := strings.ToLower(cfg.TunnelType)
	if tunnelType == "" {
		tunnelType = "base"
	}

	proto, exists := tunnelRegistry[tunnelType]
	if !exists {
		return nil, fmt.Errorf("unsupported tunnel type: %s", tunnelType)
	}

	target := cfg.ProxyAddr
	if tunnelType == "base" {
		target = cfg.SshAddr
	}

	zlog.Infof("%s [Tunnel] 1. Preparing to establish underlying connection, Target: %s, Mode: %s, Network requirement: %s", TAG, target, tunnelType, proto.Network)

	var baseConn net.Conn
	var err error

	//  info
	switch proto.Network {
	case "tcp":
		baseConn, err = dialTCP(ctx, cfg, target)
	case "udp":
		baseConn, err = dialUDP(ctx, cfg, target)
	case "custom":
		zlog.Infof("%s [Tunnel] ⚡ Underlying dialing taken over by protocol (on-demand lazy loading)", TAG)
		baseConn = nil
	default:
		baseConn = nil
	}

	//  info Failed to establish， info ， info  Handler
	if err != nil {
		return nil, err
	}

	//  info  baseConn  info tunnel info  ( info  HTTP/3, WebSocket, Base SSH  info )
	targetConn, err := proto.Handler(ctx, cfg, baseConn)
	if err == nil {
		//if Debug {
		//	targetConn = &DumpConn{Conn: targetConn, Prefix: "Client Local - Android"}
		//}
	}

	return targetConn, err
}

// DialNode is the unified function for establishing a tunnel and an SSH connection
func DialNode(ctx context.Context, cfg ProxyConfig, isPing bool) (*ssh.Client, net.Conn, error) {
	conn, err := dialTunnel(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("tunnel err: %v", err)
	}

	client, err := dialSSH(ctx, conn, cfg, isPing)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("ssh err: %v", err)
	}
	return client, conn, nil
}
