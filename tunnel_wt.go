package myssh

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
)

// WebTransport 全局会话池
// 用于完美实现 QUIC 多路复用，避免疯狂发起 UDP 握手触发运营商 QoS 阻断
var (
	wtSessionCache sync.Map
	wtMutex        sync.Mutex // 防止并发请求引发的“拨号风暴”
)

// getWTSession 获取或新建一个复用的 WebTransport 会话
func getWTSession(ctx context.Context, cfg ProxyConfig, reqUrl string) (*webtransport.Session, error) {
	// 直接从缓存中取
	if val, ok := wtSessionCache.Load(cfg.ProxyAddr); ok {
		return val.(*webtransport.Session), nil
	}

	// 加锁防止并发拨号
	wtMutex.Lock()
	defer wtMutex.Unlock()

	// Double Check: 获取锁后再次检查，可能被其他协程刚刚建好了
	if val, ok := wtSessionCache.Load(cfg.ProxyAddr); ok {
		return val.(*webtransport.Session), nil
	}

	zlog.Infof("%s [Tunnel] ⚡ 正在建立底层 WebTransport 全新会话...", TAG)

	tlsConf := &tls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}

	// 防断流 QUIC 配置
	dialer := &webtransport.Dialer{
		TLSClientConfig: tlsConf,
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
			HandshakeIdleTimeout:             10 * time.Second, // 防止 UDP 黑洞卡死
			MaxIdleTimeout:                   30 * time.Second,
			KeepAlivePeriod:                  8 * time.Second, // 8秒超强心跳，强行撑开 NAT 网关
		},
	}

	headers := make(http.Header)
	headers.Set("Host", cfg.CustomHost)
	if cfg.CustomHost != "" {
		headers.Set("Host", cfg.CustomHost)
	}
	headers.Set("User-Agent", "Mozilla/5.0 (Linux; Android 16; LM-Q720) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.50 Mobile Safari/537.36")
	headers.Set("X-Target", cfg.SshAddr) // 路由信息在 Session 握手阶段传给服务器
	headers.Set("X-Network", "tcp")
	if cfg.ProxyAuthRequired {
		headers.Set("Proxy-Authorization", "Bearer "+cfg.ProxyAuthToken)
	}

	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	_, session, err := dialer.Dial(dialCtx, reqUrl, headers)
	if err != nil {
		return nil, err
	}

	zlog.Infof("%s [Tunnel] ✅ 底层 WebTransport 会话建立成功！", TAG)

	// 存入缓存供后续并发请求复用
	wtSessionCache.Store(cfg.ProxyAddr, session)
	return session, nil
}

// wtConn 将 webtransport.Stream 包装为 net.Conn
type wtConn struct {
	*webtransport.Stream
	remoteAddr string
}

// 手动提供虚拟的本地和远端地址，防止上层获取地址时发生 Panic
func (w *wtConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

func (w *wtConn) RemoteAddr() net.Addr {
	addr, err := net.ResolveUDPAddr("udp", w.remoteAddr)
	if err == nil && addr != nil {
		return addr
	}
	return &net.UDPAddr{IP: net.IPv4zero, Port: 443}
}

// 只关闭当前流，绝不关闭复用的 Session！
func (w *wtConn) Close() error {
	w.Stream.CancelRead(0)
	w.Stream.CancelWrite(0)
	return w.Stream.Close()
}

func init() {
	RegisterTunnel("wt", "udp", func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error) {

		path := cfg.CustomPath
		if path == "" {
			path = "/tunnel"
		}
		reqUrl := fmt.Sprintf("https://%s%s", cfg.ProxyAddr, path)

		// 获取复用的 WebTransport 会话 (Session)
		session, err := getWTSession(ctx, cfg, reqUrl)
		if err != nil {
			zlog.Errorf("%s [Tunnel] ❌ WebTransport 会话获取失败: %v", TAG, err)
			return nil, err
		}

		// 在复用会话上开启极速双向数据流 (Stream)
		// 这里的 Background() 不能传超时 ctx，因为这个 ctx 会跟随 stream 的整个生命周期
		stream, err := session.OpenStreamSync(ctx)
		if err != nil {
			// 如果流打开失败，说明底层的 Session 已经因为网络波动死掉了
			// 我们需要从缓存中把它踢除，并关闭死掉的会话
			zlog.Warnf("%s [Tunnel] ⚠️ 发现 WebTransport 僵尸会话，正在清理并重试...", TAG)
			wtSessionCache.Delete(cfg.ProxyAddr)
			session.CloseWithError(1, "stream open failed due to dead session")

			// 抛出错误，外层的 autoSSH 重连机制会自动触发下一轮全新的拨号
			return nil, fmt.Errorf("open stream failed: %w", err)
		}

		zlog.Debugf("%s [Tunnel] ⚡ 已分配新的 WT 虚拟流通道", TAG)

		return &wtConn{
			Stream:     stream,
			remoteAddr: cfg.ProxyAddr,
		}, nil
	})
}
