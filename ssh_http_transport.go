package myssh

import (
	"context"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/ssh"
)

// newSSHHTTPTransport 构造一个经 sshClient 拨号、绑定单个节点的独立 HTTP Transport。
//
// 每次探测都需指向该节点的 sshClient，因此无法全局复用；调用方使用完毕后
// 必须调用 transport.CloseIdleConnections() 释放空闲连接，否则批量 ping / 测速
// 会累积残留的 Transport 与底层连接。
//
// DialContext 复用 sshClient.Dial 的 TCP 转发通道；DisableKeepAlives 关闭连接复用
// （探测是一次性的）；ResponseHeaderTimeout 由调用方按探测超时传入。
func newSSHHTTPTransport(sshClient *ssh.Client, timeout time.Duration) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return sshClient.Dial("tcp", addr)
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: timeout,
	}
}
