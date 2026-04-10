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
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/ssh"
)

const TAG = "[MySsh]"

type ProxyConfig struct {
	LocalAddr   string `json:"local_addr"`
	SshAddr     string `json:"ssh_addr"`
	User        string `json:"user"`
	Pass        string `json:"pass"`
	TunnelType  string `json:"tunnel_type"`
	ProxyAddr   string `json:"proxy_addr"`
	CustomHost  string `json:"custom_host"`
	HttpPayload string `json:"http_payload"`
	CustomPath  string `json:"custom_path"`
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
	
	// 🌟 生命周期与守护进程管理
	engineCtx    context.Context
	engineCancel context.CancelFunc

	// 🌟 连接池与会话追踪管理
	udpNatMap    sync.Map
	tcpConnMap   sync.Map
	bufferPool   = sync.Pool{
		New: func() interface{} {
			return make([]byte, 65535)
		},
	}
	
	wg sync.WaitGroup
	zlog *zap.SugaredLogger = zap.NewNop().Sugar()
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

func InitLogger(logPath string, logLevelStr string) int {
	var level zapcore.Level
	
	switch strings.ToUpper(logLevelStr) {
	case "DEBUG":
		level = zapcore.DebugLevel
	case "INFO":
		level = zapcore.InfoLevel
	case "WARN":
		level = zapcore.WarnLevel
	case "ERROR":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel 
	}

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	if err != nil {
		return -1
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder   
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder 

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.AddSync(file),
		level, 
	)

	logger := zap.New(core)
	zlog = logger.Sugar()

	zlog.Infof("%s [Logger] 日志系统初始化完成，写入路径: %s，当前级别: %s", TAG, logPath, level.String())
	return 0
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

type SshProxyHandler struct{}

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

		// 🌟 获取 SSH 客户端，如果正在重连则直接返回错误，促使客户端重试
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
			_, err := io.Copy(remote, c)
			errc <- err
		}()
		go func() {
			_, err := io.Copy(c, remote)
			errc <- err
		}()
		
		<-errc
		remote.Close()
		<-errc
		
		return nil
	}

	rep := socks5.NewReply(socks5.RepCommandNotSupported, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
	_, _ = rep.WriteTo(c)
	return fmt.Errorf("unsupported command: %v", r.Cmd)
}

func (h *SshProxyHandler) UDPHandle(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	dstPort := binary.BigEndian.Uint16(d.DstPort)

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

	if !isDirect {
		zlog.Warnf("%s [SOCKS5-UDP] ⚠️ 拦截并丢弃代理 UDP 数据包 -> %s:%d (SSH不支持UDP)", TAG, targetHost, dstPort)
		return nil
	}

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
			
			// 🌟 使用对象池优化缓冲区分配
			buf := bufferPool.Get().([]byte)
			defer bufferPool.Put(buf)
			
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

// ----- 核心引擎调度 -----

func WgWait() {
	zlog.Infof("%s [Core] 正在等待所有后台任务彻底退出...", TAG)
	wg.Wait()
	zlog.Infof("%s [Core] ✅ 所有后台任务已安全清理完毕，程序可安全退出", TAG)
}

// 🌟 关闭失效的代理连接
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

// 🌟 SSH 心跳保活机制
func maintainKeepAlive(ctx context.Context, client *ssh.Client) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 发送 SSH 标准保活探测包
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				zlog.Warnf("%s [AutoSSH] ⚠️ 心跳发送失败: %v (准备断开重建)", TAG, err)
				client.Close() // 强制关闭死连接，触发 Wait() 返回
				return
			}
		}
	}
}

// StartSshTProxy2 启动代理引擎（带智能自动重连守护进程）
func StartSshTProxy2(configJson string) int {
	StopSshTProxy()

	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(configJson), &cfg); err != nil {
		zlog.Errorf("%s [Core] ❌ 解析配置 JSON 失败: %v", TAG, err)
		return -1
	}

	// 初始化引擎生命周期 Context
	var ctx context.Context
	ctx, engineCancel = context.WithCancel(context.Background())
	engineCtx = ctx

	zlog.Infof("%s [Core] ==================== 启动代理引擎 (AutoSSH模式) ====================", TAG)

	// 1. 启动 SOCKS5 本地监听 (永远在线，独立于 SSH 生命周期)
	srv, err := socks5.NewClassicServer(cfg.LocalAddr, "", "", "", 0, 60)
	if err != nil {
		zlog.Errorf("%s [SOCKS5] ❌ 创建 SOCKS5 服务器实例失败: %v", TAG, err)
		return -4
	}

	mu.Lock()
	socksServer = srv
	mu.Unlock()

	handler := &SshProxyHandler{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		zlog.Infof("%s [SOCKS5] 🚀 SOCKS5 代理服务已启动: %s", TAG, cfg.LocalAddr)
		if err := srv.ListenAndServe(handler); err != nil && !strings.Contains(err.Error(), "closed network connection") {
			zlog.Errorf("%s [SOCKS5] ❌ 服务异常退出: %v", TAG, err)
		}
		zlog.Infof("%s [SOCKS5] 🛑 SOCKS5 服务已完全停止", TAG)
	}()

	// 2. 启动 AutoSSH 后台守护协程
	wg.Add(1)
	go func() {
		defer wg.Done()
		
		sshConfig := &ssh.ClientConfig{
			User:            cfg.User,
			Auth:            []ssh.AuthMethod{ssh.Password(cfg.Pass)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         15 * time.Second,
		}

		for {
			// 检查引擎是否已被用户要求停止
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
				time.Sleep(3 * time.Second) // 失败退避
				continue
			}

			zlog.Infof("%s [AutoSSH] 正在进行 SSH 安全认证...", TAG)
			scc, chans, reqs, err := ssh.NewClientConn(conn, cfg.SshAddr, sshConfig)
			if err != nil {
				conn.Close()
				zlog.Errorf("%s [AutoSSH] ❌ SSH 握手失败: %v", TAG, err)
				time.Sleep(3 * time.Second) // 失败退避
				continue
			}

			client := ssh.NewClient(scc, chans, reqs)

			// 连接成功，挂载到全局
			mu.Lock()
			sshClient = client
			mu.Unlock()
			zlog.Infof("%s [AutoSSH] ✅ SSH 隧道建立成功，已接管全局流量！", TAG)

			// 启动心跳保活协程
			go maintainKeepAlive(engineCtx, client)

			// 阻塞等待连接断开
			err = client.Wait()
			zlog.Warnf("%s [AutoSSH] ⚠️ 隧道已断开 (%v)，准备自动重连...", TAG, err)

			// 连接断开了，清理现场
			mu.Lock()
			sshClient = nil
			mu.Unlock()

			// 强制切断所有卡在旧连接上的本地应用，促使它们立即重试
			killActiveProxyConnections()

			// 防抖退避
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
	// 发送全局停止信号，让 AutoSSH 协程和 KeepAlive 协程安全退出
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

	zlog.Infof("%s [Core] 代理引擎停止指令发送完成", TAG)
}