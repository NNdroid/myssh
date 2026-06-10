package myssh

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// 針對 TCP 連線進行底層 Socket 最佳化
// 關閉 Nagle 演算法 (SetNoDelay) 以保證極低延遲 (適用於 SSH/即時指令)
// 擴大作業系統讀寫緩衝區至 4MB，以適應跨國高 BDP (頻寬延遲乘積) 網路
// 设置keepalive 为15s
func applyOptimiseForTcpConnection(conn net.Conn) {
	// 嘗試將 net.Conn 轉型為底層的 *net.TCPConn
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		// 關閉 Nagle 演算法
		if err := tcpConn.SetNoDelay(true); err != nil {
			zlog.Warnf("%s [TCP Tune] 無法設定 NoDelay: %v", TAG, err)
		}

		// 設定讀取緩衝區
		if err := tcpConn.SetReadBuffer(tcpOptimizeBufferSize); err != nil {
			zlog.Warnf("%s [TCP Tune] 無法設定 ReadBuffer: %v", TAG, err)
		}

		// 設定寫入緩衝區
		if err := tcpConn.SetWriteBuffer(tcpOptimizeBufferSize); err != nil {
			zlog.Warnf("%s [TCP Tune] 無法設定 WriteBuffer: %v", TAG, err)
		}

		// 啟用 TCP Keep-Alive
		if err := tcpConn.SetKeepAlive(true); err != nil {
			zlog.Warnf("%s [TCP Tune] 無法啟用 KeepAlive: %v", TAG, err)
		} else {
			// 設定 KeepAlive 週期為 15 秒
			if err := tcpConn.SetKeepAlivePeriod(time.Duration(tcpKeepaliveIntervalSec) * time.Second); err != nil {
				zlog.Warnf("%s [TCP Tune] 無法設定 KeepAlive 週期: %v", TAG, err)
			}
		}

		zlog.Debugf("%s [TCP Tune] 已成功套用 Socket 最佳化 (4MB Buffer, NoDelay, KeepAlive)", TAG)
	}
}

// dialSocket is the unified entry point for creating all underlying sockets.
// It handles timeouts and interface binding.
func dialSocket(ctx context.Context, cfg ProxyConfig, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	// Apply interface binding if specified in the config.
	if cfg.BindInterface != "" {
		bindDevice(dialer, cfg.BindInterface)
	}

	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		zlog.Errorf("%s [Socket] ❌ 底层 %s 连接失败: %v", TAG, strings.ToUpper(network), err)
		return nil, err
	}
	zlog.Infof("%s [Socket] ✅ 底层 %s 连接建立成功: %s", TAG, strings.ToUpper(network), address)

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

// dialTunnel 是隧道建立的统一入口，负责策略分发
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

	zlog.Infof("%s [Tunnel] 1. 准备建立底层连接，目标: %s, 模式: %s, 网络要求: %s", TAG, target, tunnelType, proto.Network)

	var baseConn net.Conn
	var err error

	// 根据协议要求调用拆分好的拨号函数
	switch proto.Network {
	case "tcp":
		baseConn, err = dialTCP(ctx, cfg, target)
	case "udp":
		baseConn, err = dialUDP(ctx, cfg, target)
	case "custom":
		zlog.Infof("%s [Tunnel] ⚡ 采用协议接管底层拨号 (按需懒加载)", TAG)
		baseConn = nil
	default:
		baseConn = nil
	}

	// 如果前置物理连接建立失败，直接阻断，无需进入 Handler
	if err != nil {
		return nil, err
	}

	// 将底层的 baseConn 移交给具体的隧道协议处理器 (如 HTTP/3, WebSocket, Base SSH 等)
	targetConn, err := proto.Handler(ctx, cfg, baseConn)
	if err == nil {
		//if Debug {
		//	targetConn = &DumpConn{Conn: targetConn, Prefix: "Client Local - Android"}
		//}
	}

	return targetConn, err
}