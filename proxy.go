package myssh

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/txthinking/socks5"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/singleflight"
)

// 本文件持有引擎的包级共享状态与隧道注册表；职责划分：
//   - engine.go      引擎生命周期（startSshTProxy / stopSshTProxy / keepalive）
//   - socks5.go      SOCKS5 入站处理（TCP / UDP / DNS 劫持）
//   - ssh_client.go  SSH 拨号、主机密钥校验、握手信息缓存

const TAG = "[M]"

var (
	sshClient    *ssh.Client
	socksServer  *socks5.Server
	mu           sync.Mutex
	globalConfig atomic.Pointer[GlobalConfig]
	globalRouter atomic.Pointer[GeoRouter]

	engineCancel context.CancelFunc

	// engineCtxHolder 存当前引擎 ctx：Stop 时置换为 Background，让新建连接
	// 立即脱离旧引擎。用 atomic.Pointer[context.Context] 而非 atomic.Value：
	// 后者 Store 不同具体类型（*emptyCtx 与 *cancelCtx）会 inconsistent store panic。
	engineCtxHolder atomic.Pointer[context.Context]

	udpNatMap  sync.Map
	tcpConnMap sync.Map
	udpgwMap   sync.Map // client 侧 UDP session -> 承载 UDPGW 的 TCP 连接

	// 后台任务计数（替代 sync.WaitGroup）。WgWait 暴露给 Java 且可能长期阻塞，
	// 若在 Wait 尚未返回时下一次 Start/连接处理器又对同一 WaitGroup 执行
	// Add(1)（计数器 0→正），运行时会 panic：
	// "sync: WaitGroup is reused before previous Wait has returned"。
	// 互斥锁 + Cond 计数对任意 Add/Wait 交错都安全。
	taskMu    sync.Mutex
	taskCond  = sync.NewCond(&taskMu)
	liveTasks int

	// udpDialGroup 对同一 UDPGW sessionKey 的并发 Dial 去重：SOCKS5 UDP
	// 每包独立触发建连，并发 channel open 会让 SSH 服务端回复
	// "unexpected packet in response to channel open" 并断连。
	udpDialGroup singleflight.Group
)

// init 预置 globalConfig 为空值，防止 startSshTProxy 未先执行
// loadGlobalConfigFromJson 时，DNS 劫持等路径 globalConfig.Load() 拿到 nil 而 panic。
func init() {
	globalConfig.Store(&GlobalConfig{})
}

// init GOMAXPROCS 交给运行时默认（Go 1.26 已按容器/进程亲和自动设置），
// 这里显式对齐物理核数，移动端与 gomobile 场景下保持一致行为。
func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

// currentEngineCtx 返回当前引擎 ctx；引擎未启动时返回 Background。
func currentEngineCtx() context.Context {
	if v := engineCtxHolder.Load(); v != nil {
		return *v
	}
	return context.Background()
}

// ----- tunnel 注册表 -----

type TunnelHandler func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error)

type TunnelProtocol struct {
	Network string        // 底层网络: "tcp", "udp", "custom"（协议自拨）, "none"
	Handler TunnelHandler // 隧道握手处理
}

var tunnelRegistry = make(map[string]TunnelProtocol)

// RegisterTunnel 注册隧道实现。各 tunnel_*.go 在 init 中自注册；
// name 为配置名（如 "h2"/"grpc"），network 为底层网络需求，handler 为握手逻辑。
func RegisterTunnel(name string, network string, handler TunnelHandler) {
	tunnelRegistry[name] = TunnelProtocol{
		Network: network,
		Handler: handler,
	}
}

// GetTunnel 按名查找隧道协议；未注册时报错。
func GetTunnel(name string) (TunnelProtocol, error) {
	if proto, ok := tunnelRegistry[name]; ok {
		return proto, nil
	}
	return TunnelProtocol{}, fmt.Errorf("unsupported tunnel type: %s", name)
}

// ----- 后台任务计数与连接清理 -----

// taskTrack / taskRelease 标记一个后台 goroutine 的存活期，供 wgWait 等待。
// 两者必须在同一 goroutine 内成对出现（Add 在启动 goroutine 前，Done 在其退出时）。
func taskTrack() {
	taskMu.Lock()
	liveTasks++
	taskMu.Unlock()
}

func taskRelease() {
	taskMu.Lock()
	liveTasks--
	if liveTasks == 0 {
		taskCond.Broadcast()
	}
	taskMu.Unlock()
}

// wgWait 阻塞直到当前全部后台任务退出。计数模型下，等待期间即使有任务
// 再次 track（如引擎重启），也只是延长等待，绝不会像 WaitGroup 复用那样 panic。
func wgWait() {
	zlog.Infof("%s [Core] Waiting for all background tasks to exit completely...", TAG)
	taskMu.Lock()
	for liveTasks > 0 {
		taskCond.Wait()
	}
	taskMu.Unlock()
	zlog.Infof("%s [Core] ✅ All background tasks safely cleaned up, program can exit safely", TAG)
}

func killActiveProxyConnections() {
	count := 0
	tcpConnMap.Range(func(key, value interface{}) bool {
		if conn, ok := value.(net.Conn); ok {
			conn.Close()
			count++
		}
		tcpConnMap.Delete(key)
		return true
	})
	if count > 0 {
		zlog.Infof("%s [AutoSSH] 🧹 Cleaned up %d residual TCP proxy sessions due to disconnection", TAG, count)
	}
}

// isSSHConnectionLost 判断 error 是否意味着 SSH 连接已不可用。
// golang.org/x/crypto/ssh 在连接断开后 openChannel 会得到各种 wrapped 错误，
// 其中 channel open 收到意外回复时 err 链顶层是 <nil> 而消息以
// "unexpected packet in response to channel open" 开头，只能按消息匹配。
func isSSHConnectionLost(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "unexpected packet in response to channel open") {
		return true
	}
	return false
}

// triggerSSHReconnect 在 UDPGW 建连失败且判定 SSH 已断时，立即清空会话并
// 触发 AutoSSH 重连循环接管。
//
//	清理 udpgwMap/tcpConnMap，关闭 SSH client；AutoSSH 的 client.Wait() 随即返回进入重连。
func triggerSSHReconnect() {
	mu.Lock()
	client := sshClient
	sshClient = nil
	mu.Unlock()

	if client == nil {
		return
	}

	zlog.Warnf("%s [AutoSSH] 🔥 SSH connection lost during UDPGW tunnel establishment, forcing reconnect...", TAG)

	udpgwMap.Range(func(key, value interface{}) bool {
		if conn, ok := value.(net.Conn); ok {
			conn.Close()
		}
		udpgwMap.Delete(key)
		return true
	})

	killActiveProxyConnections()

	client.Close()
}
