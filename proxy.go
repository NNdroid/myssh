package myssh

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/txthinking/socks5"
	"golang.org/x/crypto/ssh"
)

const TAG = "[M]"

var (
	sshClient    *ssh.Client
	socksServer  *socks5.Server
	mu           sync.Mutex
	globalConfig atomic.Pointer[GlobalConfig]
	globalRouter atomic.Pointer[GeoRouter]

	// 生命周期与守护进程管理
	engineCancel context.CancelFunc

	// 引擎上下文持有器：供短时直连拨号在 Stop 时及时取消，与重连 goroutine 的局部 ctx 解耦
	engineCtxHolder atomic.Value

	// 连接池与会话追踪管理
	udpNatMap  sync.Map
	tcpConnMap sync.Map
	udpgwMap   sync.Map // 用于存储本地 UDP 客户端 -> 远端 UDPGW 的 TCP 连接

	wg sync.WaitGroup
)

// ----- 隧道注册表机制 (策略模式) -----

// currentEngineCtx 返回当前引擎上下文，供直连拨号在停止时及时取消；未启动时回退 Background。
func currentEngineCtx() context.Context {
	if v := engineCtxHolder.Load(); v != nil {
		return v.(context.Context)
	}
	return context.Background()
}

type TunnelHandler func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error)

type TunnelProtocol struct {
	Network string        // 底层网络类型: "tcp", "udp", 或 "none"
	Handler TunnelHandler // 对应的处理逻辑
}

var tunnelRegistry = make(map[string]TunnelProtocol)

// RegisterTunnel 向全局隧道注册表注册一种隧道协议实现。
// name 为协议名（如 "h2"/"grpc"），network 为底层网络类型（"tcp"/"udp"/"none"），handler 为建连逻辑。
func RegisterTunnel(name string, network string, handler TunnelHandler) {
	tunnelRegistry[name] = TunnelProtocol{
		Network: network,
		Handler: handler,
	}
}

// GetTunnel 从注册表中获取指定协议名的隧道实现；未找到时返回错误。
func GetTunnel(name string) (TunnelProtocol, error) {
	if proto, ok := tunnelRegistry[name]; ok {
		return proto, nil
	}
	return TunnelProtocol{}, fmt.Errorf("unsupported tunnel type: %s", name)
}

// ----- 初始化与配置 -----

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

// ----- SOCKS5 代理处理器 -----

type SshProxyHandler struct {
	UdpgwAddr    string
	UdpgwVersion string
}

func (h *SshProxyHandler) TCPHandle(s *socks5.Server, c *net.TCPConn, r *socks5.Request) error {
	if r.Cmd == socks5.CmdUDP {
		localAddr := c.LocalAddr().(*net.TCPAddr)
		atyp := byte(socks5.ATYPIPv4)
		ip := localAddr.IP.To4()
		if ip == nil {
			atyp = socks5.ATYPIPv6
			ip = localAddr.IP.To16()
		}
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(localAddr.Port))

		rep := socks5.NewReply(socks5.RepSuccess, atyp, ip, portBytes)
		if _, err := rep.WriteTo(c); err != nil {
			return err
		}
		io.Copy(io.Discard, c)
		return nil
	}

	if r.Cmd == socks5.CmdConnect {
		wg.Add(1)
		defer wg.Done()

		connKey := c.RemoteAddr().String() + "->" + r.Address()
		tcpConnMap.Store(connKey, c)
		defer tcpConnMap.Delete(connKey)

		mu.Lock()
		client := sshClient
		mu.Unlock()

		if client == nil {
			if Debug {
				zlog.Debugf("%s [SOCKS5-TCP] ⚠️ Tunnel is reconnecting, rejecting connection: %s", TAG, r.Address())
			}
			rep := socks5.NewReply(socks5.RepServerFailure, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
			rep.WriteTo(c)
			return fmt.Errorf("ssh client is currently reconnecting")
		}

		target := r.Address()
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			host = target
		}

		var isDirect bool
		var dialHost string
		if gr := globalRouter.Load(); gr != nil {
			res := gr.ShouldDirect(host)
			isDirect = res.IsDirect
			dialHost = res.DialHost
		} else {
			isDirect = false
			dialHost = host
		}

		var remote net.Conn
		var dialErr error

		if isDirect {
			dialTarget := net.JoinHostPort(dialHost, port)
			remote, dialErr = dialProtected(currentEngineCtx(), ProxyConfig{}, "tcp", dialTarget, 5*time.Second)
		} else {
			remote, dialErr = client.Dial("tcp", target)
		}

		if dialErr != nil {
			rep := socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
			_, _ = rep.WriteTo(c)
			return dialErr
		}

		// --- Wrap the outbound connection ---
		remote = WrapConn(remote, target)
		// ------------------------------------

		defer remote.Close()
		rep := socks5.NewReply(socks5.RepSuccess, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
		if _, err := rep.WriteTo(c); err != nil {
			return err
		}

		errc := make(chan error, 2)
		go func() {
			// Proxy -> Client (Rx for local, Tx for proxy logic if viewed from client's download)
			// remote = ssh channel (download data)
			// c = local client
			_, err := tcpRelay(c, remote)
			errc <- err
		}()
		go func() {
			// Client -> Proxy (Tx for local, Rx for proxy logic if viewed from client's upload)
			// c = local client (upload data)
			// remote = ssh channel
			_, err := tcpRelay(remote, c)
			errc <- err
		}()

		<-errc
		remote.Close()
		c.Close()
		<-errc

		return nil
	}

	rep := socks5.NewReply(socks5.RepCommandNotSupported, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
	_, _ = rep.WriteTo(c)
	return fmt.Errorf("unsupported command: %v", r.Cmd)
}

func (h *SshProxyHandler) UDPHandle(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	// 🛡️ Panic 捕获兜底，防止单个 UDP 异常包干掉整个代理服务
	defer func() {
		if err := recover(); err != nil {
			zlog.Errorf("%s [SOCKS5-UDP] 💥 Severe crash (Panic) occurred -> Client: %s, Error: %v", TAG, addr.String(), err)
		}
	}()
	dstPort := binary.BigEndian.Uint16(d.DstPort)

	// ==========================================
	// 拦截 UDP 443 (QUIC) 强制客户端降级到 TCP
	// ==========================================
	if dstPort == 443 {
		if Debug {
			zlog.Debugf("%s [SOCKS5-UDP] 🛡️ Intercepted and silently dropped UDP 443 (QUIC) packet -> Source: %s", TAG, addr.String())
		}
		return nil
	}

	// 提前解析目标地址
	var targetHost string
	switch d.Atyp {
	case socks5.ATYPIPv4, socks5.ATYPIPv6:
		targetHost = net.IP(d.DstAddr).String()
	case socks5.ATYPDomain:
		if len(d.DstAddr) > 1 {
			targetHost = string(d.DstAddr[1:])
		} else {
			targetHost = "unknown_domain"
		}
	default:
		zlog.Warnf("%s [SOCKS5-UDP] ⚠️ Unknown address type: %v", TAG, d.Atyp)
		return nil
	}

	targetAddrStr := net.JoinHostPort(targetHost, strconv.Itoa(int(dstPort)))

	if Debug {
		zlog.Debugf("%s [SOCKS5-UDP] 📨 Received uplink data | Client: %s | Target: %s | Length: %d bytes", TAG, addr.String(), targetAddrStr, len(d.Data))
	}

	// 劫持 DNS
	if dstPort == 53 {
		gc := globalConfig.Load()
		isConfiguredDNS := strings.Contains(gc.LocalDnsServer, targetAddrStr) ||
			strings.Contains(gc.RemoteDnsServer, targetAddrStr)

		if !isConfiguredDNS {
			if Debug {
				zlog.Debugf("%s [SOCKS5-UDP] 🔍 Triggered DNS hijack -> Target: %s", TAG, targetAddrStr)
			}
			reqMsg := new(dns.Msg)
			if err := reqMsg.Unpack(d.Data); err != nil {
				zlog.Errorf("%s [SOCKS5-UDP] ❌ Failed to parse native DNS: %v", TAG, err)
				return err
			}

			if lds := localDnsServer.Load(); lds != nil {
				replyMsg, err := lds.HandleDnsRequest(reqMsg)
				if err == nil && replyMsg != nil {
					replyData, _ := replyMsg.Pack()
					h.sendSocks5UDPResponse(s, addr, d.Atyp, d.DstAddr, d.DstPort, replyData)
				}
				// 无论成败，被劫持的 DNS 请求都不再往下继续走真实 UDP 转发
				return err
			}
		} else {
			if Debug {
				zlog.Debugf("%s [SOCKS5-UDP] 🛡️ Target is a configured DNS server (%s), skipping hijack and executing standard routing", TAG, targetAddrStr)
			}
		}
	}

	var isDirect bool
	var dialHost string

	if gr := globalRouter.Load(); gr != nil {
		res := gr.ShouldDirect(targetHost)
		isDirect = res.IsDirect
		dialHost = res.DialHost
	} else {
		isDirect = false
	}

	cloneSlice := func(b []byte) []byte {
		c := make([]byte, len(b))
		copy(c, b)
		return c
	}

	// ==========================================
	// 命中直连规则，走本地传统 UDP 拨号
	// ==========================================
	if isDirect {
		directTarget := net.JoinHostPort(dialHost, strconv.Itoa(int(dstPort)))
		sessionKey := addr.String() + "<->" + directTarget

		var uc net.Conn
		if val, ok := udpNatMap.Load(sessionKey); ok {
			uc = val.(net.Conn)
			if Debug {
				zlog.Debugf("%s [ROUTER-Direct] ♻️ Reusing local direct session -> %s", TAG, sessionKey)
			}
		} else {
			rawConn, err := dialProtected(currentEngineCtx(), ProxyConfig{}, "udp", directTarget, 5*time.Second)
			if err != nil {
				zlog.Errorf("%s [ROUTER-Direct] ❌ Failed to establish direct UDP: %v", TAG, err)
				return err
			}

			// --- Wrap the outbound connection ---
			uc = WrapConn(rawConn, directTarget)
			// ------------------------------------

			// 使用 LoadOrStore 防止并发同一目标造成重拨泄漏
			actual, loaded := udpNatMap.LoadOrStore(sessionKey, uc)
			if loaded {
				uc.Close() // 另一个协程抢先建好了，关掉当前多余的
				uc = actual.(net.Conn)
			} else {
				if Debug {
					zlog.Debugf("%s [ROUTER-Direct] 🟢 Created new local direct session -> %s", TAG, sessionKey)
				}
				wg.Add(1)
				// 仅在新建会话时深拷贝地址信息，彻底避免复用已有会话时的无意义堆分配
				dstAddrCopy := cloneSlice(d.DstAddr)
				dstPortCopy := cloneSlice(d.DstPort)
				go func(conn net.Conn, key string, dstAtyp byte, dstAddr []byte, dstPortBytes []byte, clientAddr *net.UDPAddr) {
					defer wg.Done()
					defer conn.Close()
					defer udpNatMap.Delete(key)

					bufPtr := udpBufPool.Get().(*[]byte)
					// 从内存池取出后，利用 cap 恢复其最大切片长度，防止复用引发的 0 长度截断
					buf := (*bufPtr)[:cap(*bufPtr)]
					defer udpBufPool.Put(bufPtr)

					for {
						conn.SetReadDeadline(time.Now().Add(60 * time.Second))
						n, err := conn.Read(buf)
						if err != nil {
							if Debug {
								zlog.Debugf("%s [ROUTER-Direct] 🔴 Direct downlink read ended -> Session: %s | Reason: %v", TAG, key, err)
							}
							break
						}
						if Debug {
							zlog.Debugf("%s [ROUTER-Direct] 📥 Received downlink direct data -> Session: %s | Length: %d bytes", TAG, key, n)
						}
						h.sendSocks5UDPResponse(s, clientAddr, dstAtyp, dstAddr, dstPortBytes, buf[:n])
					}
				}(uc, sessionKey, d.Atyp, dstAddrCopy, dstPortCopy, addr)
			}
		}

		n, err := uc.Write(d.Data)
		if err != nil {
			if Debug {
				zlog.Errorf("%s [ROUTER-Direct] ❌ Failed to write uplink data -> %s: %v", TAG, sessionKey, err)
			}
		} else {
			if Debug {
				zlog.Debugf("%s [ROUTER-Direct] 📤 Successfully wrote uplink data -> %s | Length: %d bytes", TAG, sessionKey, n)
			}
		}
		return nil
	}

	// ==========================================
	// 命中代理规则，通过 UDPGW 虚拟连接处理
	// ==========================================
	if h.UdpgwAddr == "" {
		if Debug {
			zlog.Warnf("%s [ROUTER-Proxy] ⚠️ Intercepted UDP packet -> Target: %s | Reason: UDPGW is not configured", TAG, targetAddrStr)
		}
		return nil
	}

	sessionKey := addr.String() + "<->" + targetAddrStr
	var uConn net.Conn

	if val, ok := udpgwMap.Load(sessionKey); ok {
		uConn = val.(net.Conn)
		if Debug {
			zlog.Debugf("%s [ROUTER-Proxy] ♻️ Reusing proxy session (UDPGW) -> Client: %s", TAG, sessionKey)
		}
	} else {
		mu.Lock()
		client := sshClient
		mu.Unlock()

		if client == nil {
			if Debug {
				zlog.Warnf("%s [ROUTER-Proxy] ⚠️ Rejected UDP packet -> Target: %s | Reason: SSH is not connected", TAG, targetAddrStr)
			}
			return fmt.Errorf("ssh client not ready")
		}

		// 直接拨号目标地址，DialUdpgw 内部会自动处理域名解析和 IPv6 优先
		var err error
		if h.UdpgwVersion == "badvpn" {
			if Debug {
				zlog.Debugf("%s [ROUTER-Proxy] 🚀 Selected Badvpn protocol to establish UDPGW tunnel", TAG)
			}
			uConn, err = DialBadvpnUdpgw(client, h.UdpgwAddr, targetAddrStr)
		} else {
			// 默认走 Tun2Proxy
			if Debug {
				zlog.Debugf("%s [ROUTER-Proxy] 🚀 Selected Tun2Proxy protocol to establish UDPGW tunnel", TAG)
			}
			uConn, err = DialTun2proxyUdpgw(client, h.UdpgwAddr, targetAddrStr)
		}
		if err != nil {
			zlog.Errorf("%s [ROUTER-Proxy] ❌ Failed to establish UDPGW tunnel -> Target: %s | Error: %v", TAG, targetAddrStr, err)
			return err
		}

		// --- Wrap the UDPGW connection ---
		uConn = WrapConn(uConn, fmt.Sprintf("UDPGW->%s", targetAddrStr))
		// ---------------------------------

		// 使用 LoadOrStore 防止并发引发双重代理
		actual, loaded := udpgwMap.LoadOrStore(sessionKey, uConn)
		if loaded {
			uConn.Close()
			uConn = actual.(net.Conn)
		} else {
			if Debug {
				zlog.Debugf("%s [ROUTER-Proxy] 🟢 Created new proxy session (UDPGW) -> Client: %s | Tunnel target: %s", TAG, sessionKey, targetAddrStr)
			}
			wg.Add(1)
			// 仅在新建会话时深拷贝地址信息
			dstAddrCopy := cloneSlice(d.DstAddr)
			dstPortCopy := cloneSlice(d.DstPort)
			go func(conn net.Conn, clientAddr *net.UDPAddr, key string, dstAtyp byte, dstAddr []byte, dstPortBytes []byte) {
				defer wg.Done()
				defer conn.Close()
				defer udpgwMap.Delete(key)

				// 从内存池取出后，利用 cap 恢复其最大切片长度
				bufPtr := udpBufPool.Get().(*[]byte)
				buf := (*bufPtr)[:cap(*bufPtr)]
				defer udpBufPool.Put(bufPtr)

				for {
					conn.SetReadDeadline(time.Now().Add(60 * time.Second))
					n, err := conn.Read(buf)
					if err != nil {
						if Debug {
							zlog.Debugf("%s [ROUTER-Proxy] 🔴 Proxy downlink read ended -> Session: %s | Reason: %v", TAG, key, err)
						}
						break
					}

					if Debug {
						zlog.Debugf("%s [ROUTER-Proxy] 📥 Received downlink proxy data -> Session: %s | Payload: %d bytes", TAG, key, n)
					}
					h.sendSocks5UDPResponse(s, clientAddr, dstAtyp, dstAddr, dstPortBytes, buf[:n])
				}
			}(uConn, addr, sessionKey, d.Atyp, dstAddrCopy, dstPortCopy)
		}
	}

	// 写入数据：UdpgwConn.Write 会自动进行 UDPGW 封包
	n, err := uConn.Write(d.Data)
	if err != nil {
		if Debug {
			zlog.Errorf("%s [ROUTER-Proxy] ❌ Failed to write proxy data -> Session: %s | Error: %v", TAG, sessionKey, err)
		}
		uConn.Close()
		udpgwMap.Delete(sessionKey)
	} else {
		if Debug {
			zlog.Debugf("%s [ROUTER-Proxy] 📤 Successfully wrote proxy data -> Session: %s | Length: %d bytes", TAG, sessionKey, n)
		}
	}
	return err
}

// 封装 SOCKS5 UDP 响应格式
func (h *SshProxyHandler) sendSocks5UDPResponse(s *socks5.Server, clientAddr *net.UDPAddr, atyp byte, addr []byte, port []byte, data []byte) {
	outLen := 3 + 1 + len(addr) + 2 + len(data)
	outBufPtr := udpBufPool.Get().(*[]byte)
	outBuf := *outBufPtr
	defer udpBufPool.Put(outBufPtr)

	var outPkt []byte
	if outLen <= cap(outBuf) {
		outPkt = outBuf[:outLen]
	} else {
		// 兜底：极端情况下如果超大封包越过了内存池的最大容量，使用动态分配防止静默丢包
		outPkt = make([]byte, outLen)
	}

	outPkt[0], outPkt[1], outPkt[2] = 0x00, 0x00, 0x00
	outPkt[3] = atyp
	copy(outPkt[4:], addr)
	copy(outPkt[4+len(addr):], port)
	copy(outPkt[4+len(addr)+2:], data)
	s.UDPConn.WriteToUDP(outPkt, clientAddr)
}

// ----- 核心引擎调度 -----

func WgWait() {
	zlog.Infof("%s [Core] Waiting for all background tasks to exit completely...", TAG)
	wg.Wait()
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

func maintainKeepAlive(ctx context.Context, client *ssh.Client) {
	// 每 18 秒发起一次探测
	ticker := time.NewTicker(18 * time.Second)
	defer ticker.Stop()

	type keepAliveResult struct {
		err      error
		duration time.Duration
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			resCh := make(chan keepAliveResult, 1)

			go func() {
				start := time.Now() // 🌟 开始计时
				// 发送 SSH 标准保活探测包
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				duration := time.Since(start) // 🌟 计算耗时

				resCh <- keepAliveResult{
					err:      err,
					duration: duration,
				}
			}()

			select {
			case <-ctx.Done():
				return

			case res := <-resCh:
				if res.err != nil {
					zlog.Warnf("%s [AutoSSH] ⚠️ Failed to send heartbeat: %v (Preparing to disconnect and rebuild)", TAG, res.err)
					client.Close()
					return
				}
				zlog.Infof("%s [AutoSSH] 💓 Heartbeat normal | Latency: %dms", TAG, res.duration.Milliseconds())

			case <-time.After(8 * time.Second):
				zlog.Warnf("%s [AutoSSH] ⚠️ Heartbeat response timed out severely (suspected network freeze), forcibly cutting off and rebuilding", TAG)
				client.Close()
				return
			}
		}
	}
}

// StartSshTProxy2 启动 AutoSSH 模式的代理引擎：初始化 DNS 服务、SOCKS5 服务，
// 并后台维护 SSH 隧道的自动重连。返回 0 表示启动成功，非 0 为各阶段错误码。
func StartSshTProxy2(configJson string) int {
	StopSshTProxy()

	PrintAndroidUserInfo()

	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(configJson), &cfg); err != nil {
		zlog.Errorf("%s [Core] ❌ Failed to parse config JSON: %v", TAG, err)
		return -1
	}

	var ctx context.Context
	ctx, engineCancel = context.WithCancel(context.Background())
	engineCtxHolder.Store(ctx)

	zlog.Infof("%s [Core] ==================== Starting proxy engine (AutoSSH mode) ====================", TAG)

	// 初始化 DNS 服务
	NewLocalDnsServer(cfg.UdpgwAddr, cfg.UdpgwVersion)

	// 启动本地 DNS 监听
	if lds := localDnsServer.Load(); lds != nil {
		lds.Start(cfg.DnsAddr)
	}

	srv, err := socks5.NewClassicServer(cfg.LocalAddr, "", "", "", 0, 60)
	if err != nil {
		zlog.Errorf("%s [SOCKS5] ❌ Failed to create SOCKS5 server instance: %v", TAG, err)
		return -4
	}

	mu.Lock()
	socksServer = srv
	mu.Unlock()

	handler := &SshProxyHandler{
		UdpgwAddr:    cfg.UdpgwAddr, // 完全由配置决定，为空则禁用 UDPGW
		UdpgwVersion: cfg.UdpgwVersion,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		zlog.Infof("%s [SOCKS5] 🚀 SOCKS5 proxy service started: %s", TAG, cfg.LocalAddr)
		if err := srv.ListenAndServe(handler); err != nil && !strings.Contains(err.Error(), "closed network connection") {
			zlog.Errorf("%s [SOCKS5] ❌ Service exited abnormally: %v", TAG, err)
		}
		zlog.Infof("%s [SOCKS5] 🛑 SOCKS5 service has completely stopped", TAG)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				zlog.Infof("%s [AutoSSH] Received global stop signal, daemon exiting", TAG)
				return
			default:
			}

			zlog.Infof("%s [AutoSSH] 🔄 Attempting to establish tunnel and SSH connection...", TAG)
			client, _, err := DialNode(ctx, cfg, false)
			if err != nil {
				zlog.Errorf("%s [AutoSSH] ❌ Connection failed: %v", TAG, err)
				time.Sleep(3 * time.Second)
				continue
			}

			mu.Lock()
			sshClient = client
			mu.Unlock()
			zlog.Infof("%s [AutoSSH] ✅ SSH tunnel established successfully, global traffic taken over!", TAG)

			go maintainKeepAlive(ctx, client)

			err = client.Wait()
			zlog.Warnf("%s [AutoSSH] ⚠️ Tunnel disconnected (%v), preparing to reconnect automatically...", TAG, err)

			mu.Lock()
			sshClient = nil
			mu.Unlock()

			killActiveProxyConnections()

			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()

	return 0
}

// StopSshTProxy 停止代理引擎，并清理所有 SSH/代理连接、DNS 与 SOCKS5 资源。
func StopSshTProxy() {
	mu.Lock()
	defer mu.Unlock()

	if engineCancel != nil {
		engineCancel()
		engineCancel = nil
	}
	engineCtxHolder.Store(context.Background())

	zlog.Infof("%s [Core] Stopping resources...", TAG)

	if lds := localDnsServer.Load(); lds != nil {
		lds.Stop()
	}
	localDnsServer.Store(nil)

	if socksServer != nil {
		socksServer.Shutdown()
		socksServer = nil
	}
	if sshClient != nil {
		sshClient.Close()
		sshClient = nil
	}

	killActiveProxyConnections()

	udpSessionCount := 0
	udpNatMap.Range(func(key, value interface{}) bool {
		// 修复了这里的类型断言：原本是 value.(*net.UDPConn)，但此时存放的是包装过的 TrackedConn
		if conn, ok := value.(net.Conn); ok {
			conn.Close()
			udpSessionCount++
		}
		udpNatMap.Delete(key)
		return true
	})
	if udpSessionCount > 0 {
		zlog.Infof("%s [Core] Forcibly disconnected %d active UDP sessions", TAG, udpSessionCount)
	}

	udpgwSessionCount := 0
	udpgwMap.Range(func(key, value interface{}) bool {
		if conn, ok := value.(net.Conn); ok {
			conn.Close()
			udpgwSessionCount++
		}
		udpgwMap.Delete(key)
		return true
	})
	if udpgwSessionCount > 0 {
		zlog.Infof("%s [Core] Forcibly disconnected %d UDPGW proxy sessions", TAG, udpgwSessionCount)
	}

	zlog.Infof("%s [Core] All active SSH/Proxy connections destroyed", TAG)
}

func dialSSH(ctx context.Context, conn net.Conn, cfg ProxyConfig, isPing bool) (*ssh.Client, error) {
	var sshAuthMethod []ssh.AuthMethod
	if cfg.AuthType == "password" {
		sshAuthMethod = []ssh.AuthMethod{
			ssh.Password(cfg.Pass),
		}
	} else {
		signer, err := parsePrivateKeySshSigner([]byte(cfg.PrivateKey), []byte(cfg.PrivateKeyPassphrase))
		if err != nil {
			return nil, fmt.Errorf("unable to parse private key: %v", err)
		}
		sshAuthMethod = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}
	}

	var hostKeyCallback ssh.HostKeyCallback
	if isPing {
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	} else {
		hostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			fpSHA256 := ssh.FingerprintSHA256(key)
			fpMD5 := ssh.FingerprintLegacyMD5(key)
			algo := key.Type()
			pubKey := string(ssh.MarshalAuthorizedKey(key))
			zlog.Debugf("%s [SSH-Handshake] ==== SSH Host Key Info ====", TAG)
			zlog.Debugf("%s [SSH-Handshake] Host: %s", TAG, hostname)
			zlog.Debugf("%s [SSH-Handshake] Remote: %s", TAG, remote.String())
			zlog.Debugf("%s [SSH-Handshake] Algorithm: %s", TAG, algo)
			zlog.Debugf("%s [SSH-Handshake] Fingerprint (SHA256): %s", TAG, fpSHA256)
			zlog.Debugf("%s [SSH-Handshake] Fingerprint (MD5): %s", TAG, fpMD5)
			zlog.Debugf("%s [SSH-Handshake] PublicKey: %s", TAG, pubKey)
			zlog.Debugf("%s [SSH-Handshake] ===========================", TAG)
			if cfg.VerifySSHFingerprint {
				if !(fpMD5 == cfg.ServerSSHFingerprint || fpSHA256 == cfg.ServerSSHFingerprint) {
					return fmt.Errorf("host key [%s,%s] mismatch: %s", fpMD5, fpSHA256, cfg.ServerSSHFingerprint)
				}
			}
			return nil
		}
	}

	timeout := 15 * time.Second
	if isPing {
		if d, ok := ctx.Deadline(); ok {
			timeout = time.Until(d)
		} else {
			timeout = 5 * time.Second
		}
	}

	sshConfig := &ssh.ClientConfig{
		User: cfg.User,
		Auth: sshAuthMethod,
		BannerCallback: func(message string) error {
			if !isPing {
				zlog.Warnf("===== SSH Banner START =====\n%s\n===== SSH Banner END =====", message)
			}
			return nil
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         timeout,
		Config: ssh.Config{
			KeyExchanges: []string{
				"curve25519-sha256",
				"curve25519-sha256@libssh.org",
			},
			Ciphers: []string{
				"chacha20-poly1305@openssh.com",
				"aes256-gcm@openssh.com",
				"aes128-gcm@openssh.com",
			},
			MACs: []string{
				"hmac-sha2-512-etm@openssh.com",
				"hmac-sha2-256-etm@openssh.com",
			},
		},
		HostKeyAlgorithms: []string{
			"ssh-ed25519",
		},
	}

	scc, chans, reqs, err := ssh.NewClientConn(conn, cfg.SshAddr, sshConfig)
	if err != nil {
		return nil, err
	}

	if !isPing {
		cv := string(scc.ClientVersion())
		sv := string(scc.ServerVersion())
		zlog.Warnf("%s [SSH-Handshake] SSH ClientVersion: %s", TAG, cv)
		zlog.Warnf("%s [SSH-Handshake] SSH ServerVersion: %s", TAG, sv)
	}

	client := ssh.NewClient(scc, chans, reqs)
	return client, nil
}
