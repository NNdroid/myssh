package myssh

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/txthinking/socks5"
	"golang.org/x/crypto/ssh"
)

const TAG = "[MySsh]"

type ProxyConfig struct {
	LocalAddr   string `json:"local_addr"`
	SshAddr     string `json:"ssh_addr"`
	User        string `json:"user"`
	AuthType    string `json:"auth_type"`
	PrivateKey  string `json:"private_key"`
	PrivateKeyPassphrase  string `json:"private_key_passphrase"`
	Pass        string `json:"pass"`
	VerifyFingerprint bool `json:"verify_finger_print"`
	ServerFingerprint string `json:"server_finger_print"`
	TunnelType  string `json:"tunnel_type"`
	ProxyAddr   string `json:"proxy_addr"`
	ProxyAuthRequired bool `json:"proxy_auth_required"`
	ProxyAuthToken string `json:"proxy_auth_token"`
	ProxyAuthUser string `json:"proxy_auth_user"`
	ProxyAuthPass string `json:"proxy_auth_pass"`
	CustomHost  string `json:"custom_host"`
	ServerName	string	`json:"server_name"`
	HttpPayload string `json:"http_payload"`
	CustomPath  string `json:"custom_path"`
	UdpgwAddr   string `json:"udpgw_addr"` // 留空则不开启 UDPGW
	DisableStatusCheck bool `json:"disable_status_check"`
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
	udpNatMap    sync.Map
	tcpConnMap   sync.Map
	udpgwMap     sync.Map // 用于存储本地 UDP 客户端 -> 远端 UDPGW 的 TCP 连接
	
	wg sync.WaitGroup
)

// ----- 隧道注册表机制 (策略模式) -----

type TunnelHandler func(cfg ProxyConfig, baseConn net.Conn) (net.Conn, error)

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

func dialTunnel(cfg ProxyConfig) (net.Conn, error) {
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
		baseConn, err = dialer.Dial("tcp", target)
		if err != nil {
			zlog.Errorf("%s [Tunnel] ❌ 底层 TCP 连接失败: %v", TAG, err)
			return nil, err
		}
		zlog.Infof("%s [Tunnel] ✅ 底层 TCP 连接建立成功", TAG)
	case "udp":
		zlog.Infof("%s [Tunnel] ⚡ 检测到 UDP 需求，已跳过常规 TCP 拨号", TAG)
		baseConn = nil
	default:
		baseConn = nil
	}

	return proto.Handler(cfg, baseConn)
}

// ----- SOCKS5 代理处理器 -----

type SshProxyHandler struct{
	UdpgwAddr string
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
			zlog.Warnf("%s [SOCKS5-TCP] ⚠️ 隧道正在重连中，拒绝本次连接: %s", TAG, r.Address())
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
		
		defer remote.Close()
		rep := socks5.NewReply(socks5.RepSuccess, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
		if _, err := rep.WriteTo(c); err != nil {
			return err
		}

		errc := make(chan error, 2)
		go func() {
			_, err := tcpRelay(remote, c)
			errc <- err
		}()
		go func() {
			_, err := tcpRelay(c, remote)
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
	dstPort := binary.BigEndian.Uint16(d.DstPort)

	// ==========================================
	// 拦截 UDP 443 (QUIC) 强制客户端降级到 TCP
	// ==========================================
	if dstPort == 443 {
		// 静默丢弃，不给客户端返回任何错误。
		// 浏览器发送 QUIC 超时后会立刻 fallback 到 HTTPS/TCP 443。
		zlog.Debugf("%s [SOCKS5-UDP] 🛡️ 拦截并静默丢弃 UDP 443 (QUIC) 数据包 -> 来源: %s", TAG, addr.String())
		return nil
	}

	if dstPort == 53 {
		reqMsg := new(dns.Msg)
		if err := reqMsg.Unpack(d.Data); err != nil {
			zlog.Errorf("%s [SOCKS5-UDP] ❌ 解析原生 DNS 数据包失败: %v", TAG, err)
			return err
		}

		replyMsg, err := handleSshTcpDns(reqMsg)
		if err != nil || replyMsg == nil {
			return err
		}

		replyData, err := replyMsg.Pack()
		if err != nil {
			return err
		}

		res := socks5.NewDatagram(d.Atyp, d.DstAddr, d.DstPort, replyData)
		_, err = s.UDPConn.WriteToUDP(res.Bytes(), addr)
		return err
	}

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
		zlog.Warnf("%s [SOCKS5-UDP] ⚠️ 未知地址类型", TAG)
		return nil
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
		targetAddrStr := fmt.Sprintf("%s:%d", dialHost, dstPort)
		sessionKey := addr.String() + "<->" + targetAddrStr

		var uc *net.UDPConn

		if val, ok := udpNatMap.Load(sessionKey); ok {
			uc = val.(*net.UDPConn)
		} else {
			raddr, err := net.ResolveUDPAddr("udp", targetAddrStr)
			if err != nil {
				zlog.Errorf("%s [SOCKS5-UDP] ❌ 解析直连 UDP 地址失败: %v", TAG, err)
				return err
			}

			uc, err = net.DialUDP("udp", nil, raddr)
			if err != nil {
				zlog.Errorf("%s [SOCKS5-UDP] ❌ 建立本地 UDP 连接失败: %v", TAG, err)
				return err
			}
			
			zlog.Infof("%s [ROUTER] 🟢 建立本地 UDP 直连会话 -> 目标: %s", TAG, targetAddrStr)
			udpNatMap.Store(sessionKey, uc)

			wg.Add(1)
			go func(conn *net.UDPConn, key string, dstAtyp byte, dstAddr []byte, dstPortBytes []byte, clientAddr *net.UDPAddr) {
				defer wg.Done() 
				defer conn.Close()
				defer udpNatMap.Delete(key)
				
				buf := udpBufPool.Get().([]byte)
				defer udpBufPool.Put(buf)
				
				for {
					conn.SetReadDeadline(time.Now().Add(60 * time.Second))
					n, _, err := conn.ReadFromUDP(buf)
					if err != nil {
						break 
					}
					
					res := socks5.NewDatagram(dstAtyp, dstAddr, dstPortBytes, buf[:n])
					s.UDPConn.WriteToUDP(res.Bytes(), clientAddr)
				}
				zlog.Infof("%s [ROUTER] 🔴 UDP 直连会话已释放 -> %s", TAG, targetAddrStr)
			}(uc, sessionKey, d.Atyp, d.DstAddr, d.DstPort, addr)
		}

		_, err := uc.Write(d.Data)
		if err != nil {
			zlog.Errorf("%s [SOCKS5-UDP] ❌ 写入直连 UDP 数据失败: %v", TAG, err)
		}
		return nil
	}

	// ==========================================
	// 命中代理规则，判断是否配置了 UDPGW
	// ==========================================
	if h.UdpgwAddr == "" {
		zlog.Warnf("%s [SOCKS5-UDP] ⚠️ 拦截并丢弃代理 UDP 数据包 -> %s:%d (未配置 UDPGW)", TAG, targetHost, dstPort)
		return nil
	}

	sessionKey := addr.String()
	var udpgwConn net.Conn

	if val, ok := udpgwMap.Load(sessionKey); ok {
		udpgwConn = val.(net.Conn)
	} else {
		mu.Lock()
		client := sshClient
		mu.Unlock()

		if client == nil {
			zlog.Warnf("%s [SOCKS5-UDP] ⚠️ 隧道未连接，丢弃 UDP 报文 -> %s", TAG, targetHost)
			return fmt.Errorf("ssh client not ready")
		}

		conn, err := client.Dial("tcp", h.UdpgwAddr)
		if err != nil {
			zlog.Errorf("%s [SOCKS5-UDP] ❌ 建立远端 UDPGW 连接失败 (%s): %v", TAG, h.UdpgwAddr, err)
			return err
		}

		udpgwConn = conn
		udpgwMap.Store(sessionKey, udpgwConn)
		zlog.Infof("%s [UDPGW] 🟢 建立 UDPGW 代理会话 -> 客户端: %s, 远端节点: %s", TAG, sessionKey, h.UdpgwAddr)

		wg.Add(1)
		go func(uConn net.Conn, clientAddr *net.UDPAddr, key string) {
			defer wg.Done()
			defer uConn.Close()
			defer udpgwMap.Delete(key)

			keepaliveCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				ticker := time.NewTicker(15 * time.Second)
				defer ticker.Stop()
				keepalivePkt := []byte{0x00, 0x03, 0x01, 0x00, 0x01} 
				for {
					select {
					case <-ticker.C:
						if _, err := uConn.Write(keepalivePkt); err != nil {
							return
						}
					case <-keepaliveCtx.Done():
						return
					}
				}
			}()

			lenBuf := make([]byte, 2)
			for {
				uConn.SetReadDeadline(time.Now().Add(60 * time.Second))
				
				if _, err := io.ReadFull(uConn, lenBuf); err != nil {
					break
				}
				pktLen := binary.BigEndian.Uint16(lenBuf)
				if pktLen < 3 {
					io.CopyN(io.Discard, uConn, int64(pktLen))
					continue
				}

				pktBuf := make([]byte, pktLen)
				if _, err := io.ReadFull(uConn, pktBuf); err != nil {
					break
				}

				flags := pktBuf[0]
				if flags&0x02 == 0x02 {
					offset := 3 
					if offset >= int(pktLen) { continue }
					
					atyp := pktBuf[offset]
					offset++
					
					var dstAddr []byte
					if atyp == socks5.ATYPIPv4 {
						if offset+4 > int(pktLen) { continue }
						dstAddr = pktBuf[offset : offset+4]
						offset += 4
					} else if atyp == socks5.ATYPIPv6 {
						if offset+16 > int(pktLen) { continue }
						dstAddr = pktBuf[offset : offset+16]
						offset += 16
					} else if atyp == socks5.ATYPDomain {
						if offset >= int(pktLen) { continue }
						domainLen := int(pktBuf[offset])
						if offset+1+domainLen > int(pktLen) { continue }
						dstAddr = pktBuf[offset : offset+1+domainLen]
						offset += 1 + domainLen
					} else {
						continue
					}

					if offset+2 > int(pktLen) { continue }
					dstPortBytes := pktBuf[offset : offset+2]
					offset += 2
					
					payload := pktBuf[offset:]

					res := socks5.NewDatagram(atyp, dstAddr, dstPortBytes, payload)
					s.UDPConn.WriteToUDP(res.Bytes(), clientAddr)
				}
			}
			zlog.Infof("%s [UDPGW] 🔴 UDPGW 代理会话已释放 -> %s", TAG, key)
		}(udpgwConn, addr, sessionKey)
	}

	addrBytes := make([]byte, 0, 1+len(d.DstAddr)+2)
	addrBytes = append(addrBytes, d.Atyp)
	addrBytes = append(addrBytes, d.DstAddr...)
	addrBytes = append(addrBytes, d.DstPort...)

	payloadLen := len(d.Data)
	totalLen := 3 + len(addrBytes) + payloadLen 

	packet := make([]byte, 2+totalLen)
	binary.BigEndian.PutUint16(packet[0:2], uint16(totalLen))
	packet[2] = 0x02 
	binary.BigEndian.PutUint16(packet[3:5], 1) 
	
	copy(packet[5:], addrBytes)
	copy(packet[5+len(addrBytes):], d.Data)

	if _, err := udpgwConn.Write(packet); err != nil {
		udpgwConn.Close()
		udpgwMap.Delete(sessionKey)
		zlog.Errorf("%s [SOCKS5-UDP] ❌ 写入 UDPGW 数据失败: %v", TAG, err)
	}

	return nil
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
	// 每 15 秒发起一次探测
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 🌟 核心优化：将同步阻塞的发送放入子 Goroutine，通过 Channel 接收结果
			errCh := make(chan error, 1)
			go func() {
				// 发送 SSH 标准保活探测包，要求必须回复
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				errCh <- err
			}()

			// 🌟 核心优化：三重竞速选择（上下文退出 vs 心跳返回 vs 严格超时）
			select {
			case <-ctx.Done():
				return // 收到全局退出信号

			case err := <-errCh:
				if err != nil {
					// 真实的网络断开错误（如 EOF, connection reset）
					zlog.Warnf("%s [AutoSSH] ⚠️ 心跳发送失败: %v (准备断开重建)", TAG, err)
					client.Close() // 强制关闭死连接，触发 Wait() 返回
					return
				}
				zlog.Debugf("%s [AutoSSH] 💓 心跳正常", TAG)

			case <-time.After(8 * time.Second):
				// 🌟 杀手锏：如果 8 秒都没收到 SSH 服务器的回复，认定为遭遇“网络黑洞”
				zlog.Warnf("%s [AutoSSH] ⚠️ 心跳响应严重超时 (疑似网络假死)，强行切断重建", TAG)
				client.Close() // 强制物理切断，立刻触发外层重连！
				return
			}
		}
	}
}

func parsePrivateKeySshSigner(privateKey []byte, passphrase []byte) (ssh.Signer, error) {
    // 尝试直接解析
    signer, err := ssh.ParsePrivateKey(privateKey)
    // 如果报错提示需要密码 (Passphrase)
    if _, ok := err.(*ssh.PassphraseMissingError); ok {
        return ssh.ParsePrivateKeyWithPassphrase(privateKey, passphrase)
    }
    return signer, err
}

func StartSshTProxy2(configJson string) int {
	StopSshTProxy()

	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(configJson), &cfg); err != nil {
		zlog.Errorf("%s [Core] ❌ 解析配置 JSON 失败: %v", TAG, err)
		return -1
	}

	var ctx context.Context
	ctx, engineCancel = context.WithCancel(context.Background())
	engineCtx = ctx

	zlog.Infof("%s [Core] ==================== 启动代理引擎 (AutoSSH模式) ====================", TAG)

	srv, err := socks5.NewClassicServer(cfg.LocalAddr, "", "", "", 0, 60)
	if err != nil {
		zlog.Errorf("%s [SOCKS5] ❌ 创建 SOCKS5 服务器实例失败: %v", TAG, err)
		return -4
	}

	mu.Lock()
	socksServer = srv
	mu.Unlock()

	handler := &SshProxyHandler{
		UdpgwAddr: cfg.UdpgwAddr, // 完全由配置决定，为空则禁用 UDPGW
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
			User:            cfg.User,
			Auth:            sshAuthMethod,
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
				if cfg.VerifyFingerprint {
					if fpMD5 == cfg.ServerFingerprint || fpSHA256 == cfg.ServerFingerprint {
						return fmt.Errorf("host key [%s,%s] mismatch: %s", fpMD5, fpSHA256, cfg.ServerFingerprint)
					}
				}
				return nil
			},
			Timeout:         15 * time.Second,
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
			conn, err := dialTunnel(cfg)
			if err != nil {
				zlog.Errorf("%s [AutoSSH] ❌ 隧道建立失败: %v", TAG, err)
				time.Sleep(3 * time.Second) 
				continue
			}

			zlog.Infof("%s [AutoSSH] 正在进行 SSH 安全认证...", TAG)
			scc, chans, reqs, err := ssh.NewClientConn(conn, cfg.SshAddr, sshConfig)
			if err != nil {
				conn.Close()
				zlog.Errorf("%s [AutoSSH] ❌ SSH 握手失败: %v", TAG, err)
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
			zlog.Infof("%s [AutoSSH] ✅ SSH 隧道建立成功，已接管全局流量！", TAG)

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