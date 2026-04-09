package myssh

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"context"
	"runtime"

	"nhooyr.io/websocket"
	"github.com/miekg/dns"
	"github.com/txthinking/socks5"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/ssh"
	utls "github.com/refraction-networking/utls"
)

const TAG = "[GoMySsh]"

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
	
	// 🌟 连接池管理 - 使用对象池优化缓冲区分配
	udpNatMap    sync.Map
	tcpConnMap   sync.Map
	bufferPool   = sync.Pool{
		New: func() interface{} {
			return make([]byte, 65535)
		},
	}
	
	// 🌟 生命周期与日志管理
	wg sync.WaitGroup
	zlog *zap.SugaredLogger = zap.NewNop().Sugar()
)

func init() {
    // 获取当前设备的逻辑 CPU 核心数
    numCPU := runtime.NumCPU()
    // 显式设置最大可用 P（Processor）数量
    runtime.GOMAXPROCS(numCPU) 
}

// InitLogger 初始化日志并将其重定向到指定文件
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
	if len(cfg.DirectSiteTags) == 0 {
		cfg.DirectSiteTags = []string{"cn"}
	}
	if len(cfg.DirectIPTags) == 0 {
		cfg.DirectIPTags = []string{"cn"}
	}

	zlog.Infof("%s [Config] ✅ 已应用全局配置: LocalDNS=[%s], RemoteDNS=[%s], GeoSite=[%s], GeoIP=[%s]", TAG, cfg.LocalDnsServer, cfg.RemoteDnsServer, cfg.GeoSiteFilePath, cfg.GeoIPFilePath)

	globalRouter = newGeoRouter()

	if _, err := os.Stat(cfg.GeoSiteFilePath); err == nil {
		zlog.Infof("%s [Config] 正在加载 GeoSite 规则... Tags: %v", TAG, cfg.DirectSiteTags)
		if err := globalRouter.LoadGeoSite(cfg.GeoSiteFilePath, cfg.DirectSiteTags); err != nil {
			zlog.Errorf("%s [Config] ❌ 加载 GeoSite 失败: %v", TAG, err)
		} else {
			zlog.Infof("%s [Config] ✅ GeoSite 加载成功", TAG)
		}
	} else if os.IsNotExist(err) {
		zlog.Warnf("%s [Config] ⚠️ 未找到 GeoSite 文件 (%s)，将跳过加载【域名直连分流】规则", TAG, cfg.GeoSiteFilePath)
	}

	if _, err := os.Stat(cfg.GeoIPFilePath); err == nil {
		zlog.Infof("%s [Config] 正在加载 GeoIP 规则... Tags: %v", TAG, cfg.DirectIPTags)
		if err := globalRouter.LoadGeoIP(cfg.GeoIPFilePath, cfg.DirectIPTags); err != nil {
			zlog.Errorf("%s [Config] ❌ 加载 GeoIP 失败: %v", TAG, err)
		} else {
			zlog.Infof("%s [Config] ✅ GeoIP 加载成功", TAG)
		}
	} else if os.IsNotExist(err) {
		zlog.Warnf("%s [Config] ⚠️ 未找到 GeoIP 文件 (%s)，将跳过加载【IP直连分流】规则", TAG, cfg.GeoIPFilePath)
	}

	return 0
}

func dialTunnel(cfg ProxyConfig) (net.Conn, error) {
	target := cfg.ProxyAddr
	if strings.ToLower(cfg.TunnelType) == "base" || cfg.TunnelType == "" {
		target = cfg.SshAddr
	}

	zlog.Infof("%s [Tunnel] 1. 开始建立底层连接，目标地址: %s, 模式: %s", TAG, target, cfg.TunnelType)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	baseConn, err := dialer.Dial("tcp", target)
	if err != nil {
		zlog.Errorf("%s [Tunnel] ❌ 底层 TCP 连接失败: %v", TAG, err)
		return nil, err
	}
	zlog.Infof("%s [Tunnel] ✅ 底层 TCP 连接建立成功", TAG)

	switch strings.ToLower(cfg.TunnelType) {
	case "tls":
		zlog.Infof("%s [Tunnel] 2. 准备进行 TLS (utls SNI Proxy) 握手, 伪装 Host: %s", TAG, cfg.CustomHost)
		
		utlsConfig := &utls.Config{
			ServerName:         cfg.CustomHost,
			InsecureSkipVerify: true,
		}

		// 替换标准 tls 为 utls，这里使用 HelloChrome_Auto 自动伪装最新版 Chrome 浏览器的 TLS 指纹
		tlsConn := utls.UClient(baseConn, utlsConfig, utls.HelloChrome_Auto)
		if err := tlsConn.Handshake(); err != nil {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ TLS 握手失败: %v", TAG, err)
			return nil, err
		}
		zlog.Infof("%s [Tunnel] ✅ TLS (utls) 握手成功", TAG)
		return tlsConn, nil

	case "ws", "wss":
		scheme := "ws"
		isWSS := false
		if strings.ToLower(cfg.TunnelType) == "wss" {
			scheme = "wss"
			isWSS = true
		}
		zlog.Infof("%s [Tunnel] 2. 准备进行 %s 握手, 伪装 Host: %s", TAG, strings.ToUpper(scheme), cfg.CustomHost)
		
		if cfg.CustomPath == "" {
			cfg.CustomPath = "/"
		}

		u := url.URL{Scheme: scheme, Host: cfg.ProxyAddr, Path: cfg.CustomPath}

		// 1. 构造常见的真实浏览器 Headers，消除纯机器/协议特征
		fakeHeaders := http.Header{
			"Host":                     []string{cfg.CustomHost},
			"User-Agent":               []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"},
			"Accept-Language":          []string{"zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7"},
			"Accept-Encoding":          []string{"gzip, deflate, br"},
			"Cache-Control":            []string{"no-cache"},
			"Pragma":                   []string{"no-cache"},
			"Sec-WebSocket-Extensions": []string{"permessage-deflate; client_max_window_bits"},
			"Sec-Fetch-Dest":           []string{"websocket"},
			"Sec-Fetch-Mode":           []string{"websocket"},
			"Sec-Fetch-Site":           []string{"same-origin"},
		}

		// 2. 自定义底层的 Transport 以支持 uTLS 和强行注入 baseConn
		transport := &http.Transport{
			// 强制关闭 HTTP/2 尝试。
			// 原因：utls.HelloChrome_Auto 的 ALPN 默认包含 h2。如果服务端协商通过了 h2，
			// 标准库 HTTP/1.1 的 Upgrade 机制会报错导致握手失败，因此必须在传输层禁用 h2。
			ForceAttemptHTTP2: false, 
		}

		if isWSS {
			// WSS 模式：接管 TLS 拨号过程，注入 uTLS 消除指纹
			transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				utlsConfig := &utls.Config{
					ServerName:         cfg.CustomHost,
					InsecureSkipVerify: true,
				}
				uConn := utls.UClient(baseConn, utlsConfig, utls.HelloChrome_Auto)
				if err := uConn.HandshakeContext(ctx); err != nil {
					return nil, err
				}
				return uConn, nil
			}
		} else {
			// WS 模式：直接使用明文 baseConn
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return baseConn, nil
			}
		}

		// 3. 设置 Dialer
		opts := &websocket.DialOptions{
			HTTPClient: &http.Client{
				Transport: transport,
			},
			HTTPHeader:   fakeHeaders,
			// 兼容 Websockify 强制要求的子协议
			Subprotocols: []string{"binary"},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// 4. 发起握手
		wsConn, resp, err := websocket.Dial(ctx, u.String(), opts)
		if err != nil {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ WebSocket 握手失败: %v", TAG, err)
			return nil, err
		}

		zlog.Infof("%s [Tunnel] ✅ WebSocket 握手成功, 协商协议: %s", TAG, resp.Header.Get("Sec-WebSocket-Protocol"))

		// 5. 神器：直接将 WebSocket 转换为标准的 net.Conn 字节流
		stream := websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary)
		
		return stream, nil
	case "http":
		zlog.Infof("%s [Tunnel] 2. 准备发送 HTTP CONNECT 代理请求, 目标 SSH: %s", TAG, cfg.SshAddr)
		
		payload := cfg.HttpPayload
		if payload == "" {
			payload = "CONNECT [host_and_port] HTTP/1.1[crlf]Host: [host][crlf][crlf]"
		}

		payload = strings.ReplaceAll(payload, "[host_and_port]", cfg.SshAddr)
		payload = strings.ReplaceAll(payload, "[host]", cfg.CustomHost)
		payload = strings.ReplaceAll(payload, "[crlf]", "\r\n")

		zlog.Infof("%s [Tunnel] 发送的 HTTP Payload:\n%s", TAG, payload)
		_, err := baseConn.Write([]byte(payload))
		if err != nil {
			baseConn.Close()
			return nil, err
		}

		br := bufio.NewReader(baseConn)
		line, _ := br.ReadString('\n')
		if !strings.Contains(line, "200") {
			baseConn.Close()
			zlog.Errorf("%s [Tunnel] ❌ HTTP 代理拒绝连接: %s", TAG, line)
			return nil, fmt.Errorf("HTTP Proxy Refused: %s", line)
		}
		
		for {
			l, _ := br.ReadString('\n')
			if l == "\r\n" || l == "" {
				break
			}
		}
		zlog.Infof("%s [Tunnel] ✅ HTTP CONNECT 代理建立成功", TAG)
		return baseConn, nil
	default:
		return baseConn, nil
	}
}

type SshProxyHandler struct{}

func (h *SshProxyHandler) TCPHandle(s *socks5.Server, c *net.TCPConn, r *socks5.Request) error {
	if r.Cmd == socks5.CmdUDP {
		zlog.Infof("%s [SOCKS5-TCP] 🟢 接收到 UDP ASSOCIATE 握手请求 (客户端准备发送 UDP)", TAG)
		
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
		zlog.Infof("%s [SOCKS5-TCP] 🔴 UDP ASSOCIATE 握手连接已释放", TAG)
		return nil
	}

	if r.Cmd == socks5.CmdConnect {
		// 🌟 1. 追踪 TCP 会话生命周期
		wg.Add(1)
		defer wg.Done()

		// 🌟 2. 登记当前客户端连接，以便在停止时能强行打断 io.Copy
		connKey := c.RemoteAddr().String() + "->" + r.Address()
		tcpConnMap.Store(connKey, c)
		defer tcpConnMap.Delete(connKey)

		mu.Lock()
		client := sshClient
		mu.Unlock()

		if client == nil {
			return fmt.Errorf("ssh client disconnected")
		}

		target := r.Address()
		zlog.Infof("%s [SOCKS5-TCP] 客户端请求 TCP 连接 -> 目标: %s", TAG, target)

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
			zlog.Infof("%s [ROUTER] 🟢 命中直连规则，使用锁定地址本地拨号 -> %s", TAG, dialTarget)
			remote, dialErr = net.DialTimeout("tcp", dialTarget, 5*time.Second)
			if dialErr != nil {
				zlog.Errorf("%s [Local-Dial] ❌ 本地拨号失败 (%s): %v", TAG, dialTarget, dialErr)
			}
		} else {
			zlog.Infof("%s [ROUTER] 🛡️ 命中代理规则，交由远端 SSH 解析并拨号 -> %s", TAG, target)
			remote, dialErr = client.Dial("tcp", target)
			if dialErr != nil {
				zlog.Errorf("%s [SSH-Dial] ❌ 远端拨号失败 (%s): %v", TAG, target, dialErr)
			}
		}

		if dialErr != nil {
			rep := socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
			_, _ = rep.WriteTo(c)
			return dialErr
		}
		
		zlog.Infof("%s [SOCKS5-TCP] ✅ 拨号成功，开始双向数据转发", TAG)
		defer func() {
			remote.Close()
			zlog.Infof("%s [SOCKS5-TCP] 连接已断开，释放资源 -> 目标: %s", TAG, target)
		}()

		rep := socks5.NewReply(socks5.RepSuccess, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
		if _, err := rep.WriteTo(c); err != nil {
			zlog.Errorf("%s [SOCKS5-TCP] ❌ 回复客户端 SOCKS5 响应失败: %v", TAG, err)
			return err
		}

		// 🌟 优化版本：等待任意一个出错，立刻关闭连接
		errc := make(chan error, 2)
		go func() {
			_, err := io.Copy(remote, c)
			errc <- err
		}()
		go func() {
			_, err := io.Copy(c, remote)
			errc <- err
		}()
		
		// 等待任意一个出错
		<-errc
		// 主动关闭远程连接，触发另一个 io.Copy 退出
		remote.Close()
		// 等待第二个完成
		<-errc
		
		return nil
	}

	zlog.Warnf("%s [SOCKS5-TCP] ⚠️ 拦截到不支持的 SOCKS5 命令: 0x%02x", TAG, r.Cmd)
	rep := socks5.NewReply(socks5.RepCommandNotSupported, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
	_, _ = rep.WriteTo(c)
	return fmt.Errorf("unsupported command: %v", r.Cmd)
}

func (h *SshProxyHandler) UDPHandle(s *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	dstPort := binary.BigEndian.Uint16(d.DstPort)

	if dstPort == 53 {
		zlog.Infof("%s [SOCKS5-UDP] 🟢 拦截到 UDP 53 端口 (DNS) 请求，转交 SSH TCP 解析处理", TAG)
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

		// 🌟 使用对象池优化缓冲区分配
		wg.Add(1)
		go func(conn *net.UDPConn, key string, dstAtyp byte, dstAddr []byte, dstPortBytes []byte, clientAddr *net.UDPAddr) {
			defer wg.Done() 
			defer conn.Close()
			defer udpNatMap.Delete(key)
			
			// 从对象池获取缓冲区
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

func WgWait() {
	zlog.Infof("%s [Core] 正在等待所有后台任务彻底退出...", TAG)
	wg.Wait()
	zlog.Infof("%s [Core] ✅ 所有后台任务已安全清理完毕，程序可安全退出", TAG)
}

func StartSshTProxy2(configJson string) int {
	StopSshTProxy()

	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(configJson), &cfg); err != nil {
		zlog.Errorf("%s [Core] ❌ 解析配置 JSON 失败: %v", TAG, err)
		return -1
	}

	zlog.Infof("%s [Core] ==================== 启动代理引擎 ====================", TAG)

	var conn net.Conn
	var err error
	var scc ssh.Conn
	var chans <-chan ssh.NewChannel
	var reqs <-chan *ssh.Request

	// 核心优化 1：引入启动期的内部短重试机制（默认重试 3 次，避免 UI 和 TUN 网卡频繁闪烁）
	maxRetries := 3
	for i := 1; i <= maxRetries; i++ {
		if i > 1 {
			zlog.Infof("%s [Core] 🔄 等待 2 秒后尝试第 %d/%d 次重新拨号...", TAG, i, maxRetries)
			time.Sleep(2 * time.Second)
		}

		conn, err = dialTunnel(cfg)
		if err != nil {
			zlog.Errorf("%s [Core] ❌ 隧道建立失败: %v", TAG, err)
			if i == maxRetries {
				return -2
			}
			continue
		}

		sshConfig := &ssh.ClientConfig{
			User:            cfg.User,
			Auth:            []ssh.AuthMethod{ssh.Password(cfg.Pass)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         15 * time.Second,
		}

		zlog.Infof("%s [SSH] 3. 准备与远端建立 SSH 安全认证 (User: %s)", TAG, cfg.User)
		scc, chans, reqs, err = ssh.NewClientConn(conn, cfg.SshAddr, sshConfig)
		if err != nil {
			conn.Close()
			zlog.Errorf("%s [SSH] ❌ SSH 握手或认证失败: %v", TAG, err)
			if i == maxRetries {
				return -3
			}
			continue
		}
		
		// 走到这里说明连接成功，跳出重试循环
		break 
	}

	zlog.Infof("%s [SSH] ✅ SSH 隧道握手并认证成功！", TAG)

	mu.Lock()
	sshClient = ssh.NewClient(scc, chans, reqs)
	mu.Unlock()

	srv, err := socks5.NewClassicServer(cfg.LocalAddr, "", "", "", 0, 60)
	if err != nil {
		zlog.Errorf("%s [SOCKS5] ❌ 创建 SOCKS5 服务器实例失败: %v", TAG, err)
		return -4
	}

	mu.Lock()
	socksServer = srv
	mu.Unlock()

	handler := &SshProxyHandler{}

	// SOCKS5 监听协程
	wg.Add(1)
	go func() {
		defer wg.Done()
		zlog.Infof("%s [SOCKS5] 🚀 SOCKS5 本地代理服务已启动并监听于: %s", TAG, cfg.LocalAddr)
		if err := srv.ListenAndServe(handler); err != nil && !strings.Contains(err.Error(), "closed network connection") {
			zlog.Errorf("%s [SOCKS5] ❌ 服务异常退出: %v", TAG, err)
		}
		zlog.Infof("%s [SOCKS5] 🛑 SOCKS5 本地代理服务已完全停止", TAG)
	}()

	// 核心优化 2：运行期的 SSH 连接断开守护协程 (解决僵尸连接问题)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Wait() 方法会一直阻塞，直到由于任何原因（超时、服务端掐断、网络断开）导致 SSH 掉线
		_ = sshClient.Wait()
		zlog.Errorf("%s [SSH] ⚠️ 检测到 SSH 底层连接已断开，触发全局关闭...", TAG)
		
		// 主动调用销毁函数（这会关闭 socksServer，从而让 ListenAndServe 退出）
		// 最终 wg.Wait() 会解除阻塞，Kotlin 层的主循环就会接管并执行 UI 级的自动重连！
		StopSshTProxy()
	}()

	return 0
}

func StartSshTProxy(configJson string) int {
	StopSshTProxy()

	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(configJson), &cfg); err != nil {
		zlog.Errorf("%s [Core] ❌ 解析配置 JSON 失败: %v", TAG, err)
		return -1
	}

	zlog.Infof("%s [Core] ==================== 启动代理引擎 ====================", TAG)

	conn, err := dialTunnel(cfg)
	if err != nil {
		return -2
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            []ssh.AuthMethod{ssh.Password(cfg.Pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	zlog.Infof("%s [SSH] 3. 准备与远端建立 SSH 安全认证 (User: %s)", TAG, cfg.User)
	scc, chans, reqs, err := ssh.NewClientConn(conn, cfg.SshAddr, sshConfig)
	if err != nil {
		conn.Close()
		zlog.Errorf("%s [SSH] ❌ SSH 握手或认证失败: %v", TAG, err)
		return -3
	}
	zlog.Infof("%s [SSH] ✅ SSH 隧道握手并认证成功！", TAG)

	mu.Lock()
	sshClient = ssh.NewClient(scc, chans, reqs)
	mu.Unlock()

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
		zlog.Infof("%s [SOCKS5] 🚀 SOCKS5 本地代理服务已启动并监听于: %s", TAG, cfg.LocalAddr)
		if err := srv.ListenAndServe(handler); err != nil && !strings.Contains(err.Error(), "closed network connection") {
			zlog.Errorf("%s [SOCKS5] ❌ 服务异常退出: %v", TAG, err)
		}
		zlog.Infof("%s [SOCKS5] 🛑 SOCKS5 本地代理服务已完全停止", TAG)
	}()

	return 0
}

func StopSshTProxy() {
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

	tcpSessionCount := 0
	tcpConnMap.Range(func(key, value interface{}) bool {
		if conn, ok := value.(net.Conn); ok {
			conn.Close()
			tcpSessionCount++
		}
		tcpConnMap.Delete(key)
		return true
	})
	if tcpSessionCount > 0 {
		zlog.Infof("%s [Core] 已强制断开 %d 个活跃的 TCP 会话", TAG, tcpSessionCount)
	}

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