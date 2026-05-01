package myssh

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/txthinking/socks5"
	"golang.org/x/crypto/ssh"
)

const TAG = "[M]"

type ProxyConfig struct {
	LocalAddr                    string `json:"local_addr"`
	SshAddr                      string `json:"ssh_addr"`
	User                         string `json:"user"`
	AuthType                     string `json:"auth_type"`
	PrivateKey                   string `json:"private_key"`
	PrivateKeyPassphrase         string `json:"private_key_passphrase"`
	Pass                         string `json:"pass"`
	VerifySSHFingerprint         bool   `json:"verify_ssh_finger_print"`
	ServerSSHFingerprint         string `json:"server_ssh_finger_print"`
	TunnelType                   string `json:"tunnel_type"`
	ProxyAddr                    string `json:"proxy_addr"`
	ProxyAuthRequired            bool   `json:"proxy_auth_required"`
	ProxyAuthToken               string `json:"proxy_auth_token"`
	ProxyAuthUser                string `json:"proxy_auth_user"`
	ProxyAuthPass                string `json:"proxy_auth_pass"`
	CustomHost                   string `json:"custom_host"`
	ServerName                   string `json:"server_name"`
	HttpPayload                  string `json:"http_payload"`
	CustomPath                   string `json:"custom_path"`
	UdpgwAddr                    string `json:"udpgw_addr"` // 留空则不开启 UDPGW
	DisableStatusCheck           bool   `json:"disable_status_check"`
	Alpn                         string `json:"alpn"`
	VerifyCertificateFingerprint bool   `json:"verify_certificate_finger_print"`
	ServerCertificateFingerprint string `json:"server_certificate_finger_print"`
	DnsAddr                      string `json:"dns_addr"`
	UdpgwVersion                 string `json:"udpgw_version"`
}

type GlobalConfig struct {
	LocalDnsServer  string   `json:"local_dns_server"`
	RemoteDnsServer string   `json:"remote_dns_server"`
	GeoSiteFilePath string   `json:"geosite_filepath"`
	GeoIPFilePath   string   `json:"geoip_filepath"`
	DirectSiteTags  []string `json:"direct_site_tags"`
	DirectIPTags    []string `json:"direct_ip_tags"`
}

var (
	sshClient    *ssh.Client
	socksServer  *socks5.Server
	mu           sync.Mutex
	globalConfig GlobalConfig
	globalRouter *GeoRouter

	// 生命周期与守护进程管理
	engineCtx    context.Context
	engineCancel context.CancelFunc

	// 连接池与会话追踪管理
	udpNatMap  sync.Map
	tcpConnMap sync.Map
	udpgwMap   sync.Map // 用于存储本地 UDP 客户端 -> 远端 UDPGW 的 TCP 连接

	wg sync.WaitGroup
)

// ----- 隧道注册表机制 (策略模式) -----

type TunnelHandler func(ctx context.Context, cfg ProxyConfig, baseConn net.Conn) (net.Conn, error)

type TunnelProtocol struct {
	Network string        // 底层网络类型: "tcp", "udp", 或 "none"
	Handler TunnelHandler // 对应的处理逻辑
}

var tunnelRegistry = make(map[string]TunnelProtocol)

func RegisterTunnel(name string, network string, handler TunnelHandler) {
	tunnelRegistry[name] = TunnelProtocol{
		Network: network,
		Handler: handler,
	}
}

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

func LoadGlobalConfigFromJson(configJson string) int {
	if err := json.Unmarshal([]byte(configJson), &globalConfig); err != nil {
		zlog.Errorf("%s [Config] ❌ 解析全局配置 JSON 失败: %v\n传入的JSON内容: %s", TAG, err, configJson)
		return -2
	}
	return loadGlobalConfig(globalConfig)
}

func loadGlobalConfig(cfg GlobalConfig) int {
	mu.Lock()
	defer mu.Unlock()

	if cfg.LocalDnsServer == "" {
		cfg.LocalDnsServer = "223.5.5.5:53"
	}
	if cfg.RemoteDnsServer == "" {
		cfg.RemoteDnsServer = "8.8.8.8:53"
	}
	if cfg.GeoSiteFilePath == "" {
		cfg.GeoSiteFilePath = "geosite.dat"
	}
	if cfg.GeoIPFilePath == "" {
		cfg.GeoIPFilePath = "geoip.dat"
	}

	zlog.Infof("%s [Config] ✅ 已应用全局配置: LocalDNS=[%s], RemoteDNS=[%s]", TAG, cfg.LocalDnsServer, cfg.RemoteDnsServer)

	globalRouter = newGeoRouter()

	if _, err := os.Stat(cfg.GeoSiteFilePath); err == nil {
		if err := globalRouter.LoadGeoSite(cfg.GeoSiteFilePath, cfg.DirectSiteTags); err != nil {
			zlog.Errorf("%s [Config] ❌ 加载 GeoSite 失败: %v", TAG, err)
		} else {
			zlog.Infof("%s [Config] ✅ GeoSite 加载成功", TAG)
		}
	} else if os.IsNotExist(err) {
		zlog.Warnf("%s [Config] ⚠️ 未找到 GeoSite 文件 (%s)，域名直连分流已禁用", TAG, cfg.GeoSiteFilePath)
	}

	if _, err := os.Stat(cfg.GeoIPFilePath); err == nil {
		if err := globalRouter.LoadGeoIP(cfg.GeoIPFilePath, cfg.DirectIPTags); err != nil {
			zlog.Errorf("%s [Config] ❌ 加载 GeoIP 失败: %v", TAG, err)
		} else {
			zlog.Infof("%s [Config] ✅ GeoIP 加载成功", TAG)
		}
	} else if os.IsNotExist(err) {
		zlog.Warnf("%s [Config] ⚠️ 未找到 GeoIP 文件 (%s)，IP直连分流已禁用", TAG, cfg.GeoIPFilePath)
	}

	return 0
}

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

	switch proto.Network {
	case "tcp":
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		baseConn, err = dialer.DialContext(ctx, "tcp", target)
		if err != nil {
			zlog.Errorf("%s [Tunnel] ❌ 底层 TCP 连接失败: %v", TAG, err)
			return nil, err
		}
		zlog.Infof("%s [Tunnel] ✅ 底层 TCP 连接建立成功", TAG)
		TuneTCPConn(baseConn)
	case "udp":
		zlog.Infof("%s [Tunnel] ⚡ 检测到 UDP 需求，已跳过常规 TCP 拨号", TAG)
		baseConn = nil
	default:
		zlog.Infof("%s [Tunnel] ⚡ 采用自定义拨号", TAG)
		baseConn = nil
	}

	targetConn, err := proto.Handler(ctx, cfg, baseConn)
	if err == nil {
		//if Debug {
		//	targetConn = &DumpConn{Conn: targetConn, Prefix: "Client Local - Android"}
		//}
	}
	return targetConn, err
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
				zlog.Debugf("%s [SOCKS5-TCP] ⚠️ 隧道正在重连中，拒绝本次连接: %s", TAG, r.Address())
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
		if globalRouter != nil {
			res := globalRouter.ShouldDirect(host)
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
			remote, dialErr = net.DialTimeout("tcp", dialTarget, 5*time.Second)
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
			zlog.Errorf("%s [SOCKS5-UDP] 💥 发生严重崩溃 (Panic) -> 客户端: %s, 错误: %v", TAG, addr.String(), err)
		}
	}()
	dstPort := binary.BigEndian.Uint16(d.DstPort)

	// ==========================================
	// 拦截 UDP 443 (QUIC) 强制客户端降级到 TCP
	// ==========================================
	if dstPort == 443 {
		if Debug {
			zlog.Debugf("%s [SOCKS5-UDP] 🛡️ 拦截并静默丢弃 UDP 443 (QUIC) 数据包 -> 来源: %s", TAG, addr.String())
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
		zlog.Warnf("%s [SOCKS5-UDP] ⚠️ 未知地址类型: %v", TAG, d.Atyp)
		return nil
	}

	targetAddrStr := net.JoinHostPort(targetHost, strconv.Itoa(int(dstPort)))

	if Debug {
		zlog.Debugf("%s [SOCKS5-UDP] 📨 收到上行数据 | 客户端: %s | 目标: %s | 长度: %d bytes", TAG, addr.String(), targetAddrStr, len(d.Data))
	}

	// 劫持 DNS
	if dstPort == 53 {
		isConfiguredDNS := strings.Contains(globalConfig.LocalDnsServer, targetAddrStr) ||
			strings.Contains(globalConfig.RemoteDnsServer, targetAddrStr)

		if !isConfiguredDNS {
			if Debug {
				zlog.Debugf("%s [SOCKS5-UDP] 🔍 触发 DNS 劫持 -> 目标: %s", TAG, targetAddrStr)
			}
			reqMsg := new(dns.Msg)
			if err := reqMsg.Unpack(d.Data); err != nil {
				zlog.Errorf("%s [SOCKS5-UDP] ❌ 解析原生 DNS 失败: %v", TAG, err)
				return err
			}

			if localDnsServer != nil {
				replyMsg, err := localDnsServer.HandleDnsRequest(reqMsg)
				if err == nil && replyMsg != nil {
					replyData, _ := replyMsg.Pack()
					h.sendSocks5UDPResponse(s, addr, d.Atyp, d.DstAddr, d.DstPort, replyData)
				}
				// 无论成败，被劫持的 DNS 请求都不再往下继续走真实 UDP 转发
				return err
			}
		} else {
			if Debug {
				zlog.Debugf("%s [SOCKS5-UDP] 🛡️ 目标为配置的 DNS 服务器 (%s)，跳过劫持，执行标准路由", TAG, targetAddrStr)
			}
		}
	}

	var isDirect bool
	var dialHost string

	if globalRouter != nil {
		res := globalRouter.ShouldDirect(targetHost)
		isDirect = res.IsDirect
		dialHost = res.DialHost
	} else {
		isDirect = false
	}

	// ==========================================
	// 命中直连规则，走本地传统 UDP 拨号
	// ==========================================
	if isDirect {
		targetAddrStr := net.JoinHostPort(dialHost, strconv.Itoa(int(dstPort)))
		sessionKey := addr.String() + "<->" + targetAddrStr

		var uc net.Conn
		if val, ok := udpNatMap.Load(sessionKey); ok {
			uc = val.(net.Conn)
			if Debug {
				zlog.Debugf("%s [ROUTER-Direct] ♻️ 复用本地直连会话 -> %s", TAG, sessionKey)
			}
		} else {
			rawConn, err := net.Dial("udp", targetAddrStr)
			if err != nil {
				zlog.Errorf("%s [ROUTER-Direct] ❌ 建立直连 UDP 失败: %v", TAG, err)
				return err
			}

			// --- Wrap the outbound connection ---
			uc = WrapConn(rawConn, targetAddrStr)
            // ------------------------------------

			if Debug {
				zlog.Debugf("%s [ROUTER-Direct] 🟢 新建本地直连会话 -> %s", TAG, sessionKey)
			}
			udpNatMap.Store(sessionKey, uc)

			wg.Add(1)
			go func(conn net.Conn, key string, dstAtyp byte, dstAddr []byte, dstPortBytes []byte, clientAddr *net.UDPAddr) {
				defer wg.Done()
				defer conn.Close()
				defer udpNatMap.Delete(key)

				bufPtr := udpBufPool.Get().(*[]byte)
				// 🌟 从内存池取出后，利用 cap 恢复其最大切片长度，防止复用引发的 0 长度截断
				buf := (*bufPtr)[:cap(*bufPtr)]
				defer udpBufPool.Put(bufPtr)

				for {
					conn.SetReadDeadline(time.Now().Add(60 * time.Second))
					n, err := conn.Read(buf)
					if err != nil {
						if Debug {
							zlog.Debugf("%s [ROUTER-Direct] 🔴 直连下行读取结束 -> 会话: %s | 原因: %v", TAG, key, err)
						}
						break
					}
					if Debug {
						zlog.Debugf("%s [ROUTER-Direct] 📥 收到下行直连数据 -> 会话: %s | 长度: %d bytes", TAG, key, n)
					}
					h.sendSocks5UDPResponse(s, clientAddr, dstAtyp, dstAddr, dstPortBytes, buf[:n])
				}
			}(uc, sessionKey, d.Atyp, d.DstAddr, d.DstPort, addr)
		}

		n, err := uc.Write(d.Data)
		if err != nil {
			if Debug {
				zlog.Errorf("%s [ROUTER-Direct] ❌ 上行数据写入失败 -> %s: %v", TAG, sessionKey, err)
			}
		} else {
			if Debug {
				zlog.Debugf("%s [ROUTER-Direct] 📤 成功写入上行数据 -> %s | 长度: %d bytes", TAG, sessionKey, n)
			}
		}
		return nil
	}

	// ==========================================
	// 命中代理规则，通过 UDPGW 虚拟连接处理
	// ==========================================
	if h.UdpgwAddr == "" {
		if Debug {
			zlog.Warnf("%s [ROUTER-Proxy] ⚠️ 拦截 UDP 报文 -> 目标: %s | 原因: UDPGW 未配置", TAG, targetAddrStr)
		}
		return nil
	}

	sessionKey := addr.String()
	var uConn net.Conn

	if val, ok := udpgwMap.Load(sessionKey); ok {
		uConn = val.(net.Conn)
		if Debug {
			zlog.Debugf("%s [ROUTER-Proxy] ♻️ 复用代理会话 (UDPGW) -> 客户端: %s", TAG, sessionKey)
		}
	} else {
		mu.Lock()
		client := sshClient
		mu.Unlock()

		if client == nil {
			if Debug {
				zlog.Warnf("%s [ROUTER-Proxy] ⚠️ 拒绝 UDP 报文 -> 目标: %s | 原因: SSH 未连接", TAG, targetAddrStr)
			}
			return fmt.Errorf("ssh client not ready")
		}

		// 🌟 直接拨号目标地址，DialUdpgw 内部会自动处理域名解析和 IPv6 优先
		var err error
		if h.UdpgwVersion == "badvpn" {
			if Debug {
				zlog.Debugf("%s [ROUTER-Proxy] 🚀 选用 Badvpn 协议建立UDPGW隧道", TAG)
			}
			uConn, err = DialBadvpnUdpgw(client, h.UdpgwAddr, targetAddrStr)
		} else {
			// 默认走 Tun2Proxy
			if Debug {
				zlog.Debugf("%s [ROUTER-Proxy] 🚀 选用 Tun2Proxy 协议建立UDPGW隧道", TAG)
			}
			uConn, err = DialTun2proxyUdpgw(client, h.UdpgwAddr, targetAddrStr)
		}
		if err != nil {
			zlog.Errorf("%s [ROUTER-Proxy] ❌ 建立 UDPGW 隧道失败 -> 目标: %s | 错误: %v", TAG, targetAddrStr, err)
			return err
		}

		// --- Wrap the UDPGW connection ---
		uConn = WrapConn(uConn, fmt.Sprintf("UDPGW->%s", targetAddrStr))
		// ---------------------------------
		udpgwMap.Store(sessionKey, uConn)
		if Debug {
			zlog.Debugf("%s [ROUTER-Proxy] 🟢 新建代理会话 (UDPGW) -> 客户端: %s | 隧道目标: %s", TAG, sessionKey, targetAddrStr)
		}

		wg.Add(1)
		go func(conn net.Conn, clientAddr *net.UDPAddr, key string, dstAtyp byte, dstAddr []byte, dstPortBytes []byte) {
			defer wg.Done()
			defer conn.Close()
			defer udpgwMap.Delete(key)

			// 🌟 从内存池取出后，利用 cap 恢复其最大切片长度
			bufPtr := udpBufPool.Get().(*[]byte)
			buf := (*bufPtr)[:cap(*bufPtr)]
			defer udpBufPool.Put(bufPtr)

			for {
				conn.SetReadDeadline(time.Now().Add(60 * time.Second))
				n, err := conn.Read(buf)
				if err != nil {
					if Debug {
						zlog.Debugf("%s [ROUTER-Proxy] 🔴 代理下行读取结束 -> 会话: %s | 原因: %v", TAG, key, err)
					}
					break
				}

				if Debug {
					zlog.Debugf("%s [ROUTER-Proxy] 📥 收到下行代理数据 -> 会话: %s | 净载荷: %d bytes", TAG, key, n)
				}
				h.sendSocks5UDPResponse(s, clientAddr, dstAtyp, dstAddr, dstPortBytes, buf[:n])
			}
		}(uConn, addr, sessionKey, d.Atyp, d.DstAddr, d.DstPort)
	}

	// 🌟 写入数据：UdpgwConn.Write 会自动进行 UDPGW 封包
	n, err := uConn.Write(d.Data)
	if err != nil {
		if Debug {
			zlog.Errorf("%s [ROUTER-Proxy] ❌ 写入代理数据失败 -> 会话: %s | 错误: %v", TAG, sessionKey, err)
		}
		uConn.Close()
		udpgwMap.Delete(sessionKey)
	} else {
		if Debug {
			zlog.Debugf("%s [ROUTER-Proxy] 📤 成功写入代理数据 -> 会话: %s | 长度: %d bytes", TAG, sessionKey, n)
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

	if outLen <= cap(outBuf) {
		outPkt := outBuf[:outLen]
		outPkt[0], outPkt[1], outPkt[2] = 0x00, 0x00, 0x00
		outPkt[3] = atyp
		copy(outPkt[4:], addr)
		copy(outPkt[4+len(addr):], port)
		copy(outPkt[4+len(addr)+2:], data)
		s.UDPConn.WriteToUDP(outPkt, clientAddr)
	}
}

// ----- 核心引擎调度 -----

func WgWait() {
	zlog.Infof("%s [Core] 正在等待所有后台任务彻底退出...", TAG)
	wg.Wait()
	zlog.Infof("%s [Core] ✅ 所有后台任务已安全清理完毕，程序可安全退出", TAG)
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
		zlog.Infof("%s [AutoSSH] 🧹 清理了 %d 个因断线残留的 TCP 代理会话", TAG, count)
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
					zlog.Warnf("%s [AutoSSH] ⚠️ 心跳发送失败: %v (准备断开重建)", TAG, res.err)
					client.Close()
					return
				}
				// 🌟 打印耗时，使用 .Milliseconds() 获取 ms 数值
				zlog.Infof("%s [AutoSSH] 💓 心跳正常 | 延迟: %dms", TAG, res.duration.Milliseconds())

			case <-time.After(8 * time.Second):
				zlog.Warnf("%s [AutoSSH] ⚠️ 心跳响应严重超时 (疑似网络假死)，强行切断重建", TAG)
				client.Close()
				return
			}
		}
	}
}

func parsePrivateKeySshSigner(privateKey []byte, passphrase []byte) (ssh.Signer, error) {
	// 尝试直接解析
	signer, err := ssh.ParsePrivateKey(privateKey)
	// 如果报错提示需要密码 (Passphrase)
	var passphraseMissingError *ssh.PassphraseMissingError
	if errors.As(err, &passphraseMissingError) {
		return ssh.ParsePrivateKeyWithPassphrase(privateKey, passphrase)
	}
	return signer, err
}

func StartSshTProxy2(configJson string) int {
	StopSshTProxy()

	PrintAndroidUserInfo()

	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(configJson), &cfg); err != nil {
		zlog.Errorf("%s [Core] ❌ 解析配置 JSON 失败: %v", TAG, err)
		return -1
	}

	var ctx context.Context
	ctx, engineCancel = context.WithCancel(context.Background())
	engineCtx = ctx

	zlog.Infof("%s [Core] ==================== 启动代理引擎 (AutoSSH模式) ====================", TAG)

	// 初始化 DNS 服务
	NewLocalDnsServer(cfg.UdpgwAddr, cfg.UdpgwVersion)

	// 启动本地 DNS 监听
	if localDnsServer != nil {
		localDnsServer.Start(cfg.DnsAddr)
	}

	srv, err := socks5.NewClassicServer(cfg.LocalAddr, "", "", "", 0, 60)
	if err != nil {
		zlog.Errorf("%s [SOCKS5] ❌ 创建 SOCKS5 服务器实例失败: %v", TAG, err)
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
		zlog.Infof("%s [SOCKS5] 🚀 SOCKS5 代理服务已启动: %s", TAG, cfg.LocalAddr)
		if err := srv.ListenAndServe(handler); err != nil && !strings.Contains(err.Error(), "closed network connection") {
			zlog.Errorf("%s [SOCKS5] ❌ 服务异常退出: %v", TAG, err)
		}
		zlog.Infof("%s [SOCKS5] 🛑 SOCKS5 服务已完全停止", TAG)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		var sshAuthMethod []ssh.AuthMethod
		if cfg.AuthType == "password" {
			sshAuthMethod = []ssh.AuthMethod{
				ssh.Password(cfg.Pass),
			}
		} else {
			signer, err := parsePrivateKeySshSigner([]byte(cfg.PrivateKey), []byte(cfg.PrivateKeyPassphrase))
			if err != nil {
				zlog.Fatalf("unable to parse private key: %v", err)
			}
			sshAuthMethod = []ssh.AuthMethod{
				ssh.PublicKeys(signer),
			}
		}

		sshConfig := &ssh.ClientConfig{
			User: cfg.User,
			Auth: sshAuthMethod,
			BannerCallback: func(message string) error {
				zlog.Warnf("===== SSH Banner START =====\n%s\n===== SSH Banner END =====", message)
				return nil
			},
			HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				// 指纹（推荐用 SHA256）
				fpSHA256 := ssh.FingerprintSHA256(key)
				// 旧格式（MD5，不推荐但有时用于兼容）
				fpMD5 := ssh.FingerprintLegacyMD5(key)
				// 算法类型（例如 ssh-ed25519）
				algo := key.Type()
				// 原始公钥（authorized_keys 格式）
				pubKey := string(ssh.MarshalAuthorizedKey(key))
				zlog.Warnf("%s [SSH-Handshake] ==== SSH Host Key Info ====", TAG)
				zlog.Warnf("%s [SSH-Handshake] Host: %s", TAG, hostname)
				zlog.Warnf("%s [SSH-Handshake] Remote: %s", TAG, remote.String())
				zlog.Warnf("%s [SSH-Handshake] Algorithm: %s", TAG, algo)
				zlog.Warnf("%s [SSH-Handshake] Fingerprint (SHA256): %s", TAG, fpSHA256)
				zlog.Warnf("%s [SSH-Handshake] Fingerprint (MD5): %s", TAG, fpMD5)
				zlog.Warnf("%s [SSH-Handshake] PublicKey: %s", TAG, pubKey)
				zlog.Warnf("%s [SSH-Handshake] ===========================", TAG)
				if cfg.VerifySSHFingerprint {
					if !(fpMD5 == cfg.ServerSSHFingerprint || fpSHA256 == cfg.ServerSSHFingerprint) {
						return fmt.Errorf("host key [%s,%s] mismatch: %s", fpMD5, fpSHA256, cfg.ServerSSHFingerprint)
					}
				}
				return nil
			},
			Timeout: 15 * time.Second,
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

		for {
			select {
			case <-engineCtx.Done():
				zlog.Infof("%s [AutoSSH] 接收到全局停止信号，守护进程退出", TAG)
				return
			default:
			}

			zlog.Infof("%s [AutoSSH] 🔄 正在尝试与远端建立隧道...", TAG)
			conn, err := dialTunnel(engineCtx, cfg)
			if err != nil {
				zlog.Errorf("%s [AutoSSH] ❌ 隧道建立失败: %v", TAG, err)
				time.Sleep(3 * time.Second)
				continue
			}

			zlog.Infof("%s [AutoSSH] 正在进行SSH安全认证...", TAG)
			scc, chans, reqs, err := ssh.NewClientConn(conn, cfg.SshAddr, sshConfig)
			if err != nil {
				conn.Close()
				zlog.Errorf("%s [AutoSSH] ❌ SSH握手失败: %v", TAG, err)
				time.Sleep(3 * time.Second)
				continue
			}
			cv := string(scc.ClientVersion())
			sv := string(scc.ServerVersion())
			zlog.Warnf("%s [SSH-Handshake] SSH ClientVersion: %s", TAG, cv)
			zlog.Warnf("%s [SSH-Handshake] SSH ServerVersion: %s", TAG, sv)

			client := ssh.NewClient(scc, chans, reqs)

			mu.Lock()
			sshClient = client
			mu.Unlock()
			zlog.Infof("%s [AutoSSH] ✅ SSH隧道建立成功，已接管全局流量！", TAG)

			go maintainKeepAlive(engineCtx, client)

			err = client.Wait()
			zlog.Warnf("%s [AutoSSH] ⚠️ 隧道已断开 (%v)，准备自动重连...", TAG, err)

			mu.Lock()
			sshClient = nil
			mu.Unlock()

			killActiveProxyConnections()

			select {
			case <-engineCtx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()

	return 0
}

func StopSshTProxy() {
	if engineCancel != nil {
		engineCancel()
	}

	mu.Lock()
	defer mu.Unlock()
	zlog.Infof("%s [Core] 正在停止资源...", TAG)

	if localDnsServer != nil {
		localDnsServer.Stop()
	}

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
		if conn, ok := value.(*net.UDPConn); ok {
			conn.Close()
			udpSessionCount++
		}
		udpNatMap.Delete(key)
		return true
	})
	if udpSessionCount > 0 {
		zlog.Infof("%s [Core] 已强制断开 %d 个活跃的 UDP 会话", TAG, udpSessionCount)
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
		zlog.Infof("%s [Core] 已强制断开 %d 个 UDPGW 代理会话", TAG, udpgwSessionCount)
	}

	zlog.Infof("%s [Core] 代理引擎停止指令发送完成", TAG)
}
