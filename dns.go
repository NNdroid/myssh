package myssh

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/singleflight"
)

type dnsCacheEntry struct {
	msg       *dns.Msg
	expiresAt time.Time
	cachedAt  time.Time
}

// pooledDnsConn 带有最后使用时间戳的连接包装器
type pooledDnsConn struct {
	conn     *dns.Conn
	lastUsed time.Time
}

const (
	MaxCacheSize          = 5000
	CacheCleanupThreshold = 6000
	DefaultMinTTL         = 60
	DefaultMaxTTL         = 3600
	CacheCleanupInterval  = 60 * time.Second
)

var (
	// 传统 TCP DNS 连接池
	dnsConnPool = make(chan pooledDnsConn, 10)
	
	// 高性能 DoH 连接池 (复用 HTTP/2 传输)
	dohMu            sync.Mutex
	directDoHClient  *http.Client
	proxiedDoHClient *http.Client
	lastSshClient    *ssh.Client

	// 缓存机制
	dnsCache   = make(map[string]dnsCacheEntry)
	dnsCacheMu sync.RWMutex

	// 并发防击穿
	dnsFlightGroup singleflight.Group
)

func init() {
	go func() {
		ticker := time.NewTicker(CacheCleanupInterval)
		for range ticker.C {
			cleanupExpiredDNSCache()
		}
	}()
}

// ==================== 缓存管理机制 ====================

func cleanupExpiredDNSCache() {
	dnsCacheMu.Lock()
	defer dnsCacheMu.Unlock()
	evictDNSCacheLocked()
}

// evictDNSCacheLocked 智能缓存清理与驱逐策略 ($O(1)$ 随机淘汰优化)
func evictDNSCacheLocked() {
	now := time.Now()
	deleted := 0

	for k, v := range dnsCache {
		if now.After(v.expiresAt) {
			delete(dnsCache, k)
			deleted++
		}
	}

	if len(dnsCache) >= CacheCleanupThreshold {
		toDelete := len(dnsCache) - MaxCacheSize
		for k := range dnsCache {
			if toDelete <= 0 {
				break
			}
			delete(dnsCache, k)
			toDelete--
			deleted++
		}
	}

	if deleted > 0 {
		zlog.Debugf("%s [Cache-GC] ♻️ 清理/驱逐了 %d 条 DNS 缓存，当前余量: %d", TAG, deleted, len(dnsCache))
	}
}

func calculateOptimalTTL(reply *dns.Msg) uint32 {
	minTTL := uint32(DefaultMaxTTL)
	for _, ans := range reply.Answer {
		ttl := ans.Header().Ttl
		if ttl > 0 && ttl < minTTL {
			minTTL = ttl
		}
	}
	if minTTL < uint32(DefaultMinTTL) {
		minTTL = uint32(DefaultMinTTL)
	} else if minTTL > uint32(DefaultMaxTTL) {
		minTTL = uint32(DefaultMaxTTL)
	}
	return minTTL
}

func copyAndAdjustTTL(entry dnsCacheEntry, newMsgId uint16) *dns.Msg {
	cachedReply := entry.msg.Copy()
	cachedReply.Id = newMsgId

	elapsed := uint32(time.Since(entry.cachedAt).Seconds())
	adjust := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if rr.Header().Ttl >= elapsed {
				rr.Header().Ttl -= elapsed
			} else {
				rr.Header().Ttl = 0
			}
		}
	}
	adjust(cachedReply.Answer)
	adjust(cachedReply.Ns)
	adjust(cachedReply.Extra)

	return cachedReply
}

// ==================== 传统 TCP 连接池 ====================

func getDnsConn(client *ssh.Client, addr string) (*dns.Conn, error) {
	for {
		select {
		case pc := <-dnsConnPool:
			// 🌟 核心机制：检查空闲保质期
			// 如果连接在池子里闲置超过 8 秒，极大概率已被对端 DNS 服务器主动回收。
			// 我们直接关闭这个死连接，并通过 continue 循环去拿下一个或新建。
			if time.Since(pc.lastUsed) > 8*time.Second {
				pc.conn.Close()
				continue
			}
			return pc.conn, nil
		default:
			// 池子空了，或者旧连接已被全部清理，发起全新的拨号
			netConn, err := client.Dial("tcp", addr)
			if err != nil {
				return nil, err
			}
			return &dns.Conn{Conn: netConn}, nil
		}
	}
}

func putDnsConn(conn *dns.Conn) {
	select {
	case dnsConnPool <- pooledDnsConn{conn: conn, lastUsed: time.Now()}:
		// 成功放回池子，并刷新时间戳
	default:
		// 池子已满，丢弃并关闭多余的连接
		conn.Close()
	}
}

// ==================== DoH 客户端工厂 (支持长连接与 HTTP/2) ====================

func getDoHClient(isDirect bool, currentSshClient *ssh.Client) *http.Client {
	dohMu.Lock()
	defer dohMu.Unlock()

	if isDirect {
		if directDoHClient == nil {
			directDoHClient = &http.Client{Timeout: 5 * time.Second}
		}
		return directDoHClient
	}

	// 当使用代理时，如果 SSH 隧道已重建，则刷新 HTTP Client 以清空坏死的 Transport
	if proxiedDoHClient == nil || currentSshClient != lastSshClient {
		lastSshClient = currentSshClient
		proxiedDoHClient = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					if currentSshClient == nil {
						return nil, fmt.Errorf("ssh client is nil")
					}
					// 强制走 SSH 的 TCP 隧道
					return currentSshClient.Dial("tcp", addr)
				},
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        10,
				IdleConnTimeout:     30 * time.Second,
				TLSHandshakeTimeout: 5 * time.Second,
			},
		}
	}
	return proxiedDoHClient
}

// ==================== 核心解析实现 ====================

// DoH 解析器 (RFC 8484)
func resolveDoH(req *dns.Msg, url string, isDirect bool, sshClient *ssh.Client) (*dns.Msg, error) {
	msgBytes, err := req.Pack()
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(msgBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	client := getDoHClient(isDirect, sshClient)
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, err
	}
	return reply, nil
}

// DoT 解析器
func resolveDoT(req *dns.Msg, addr string, dialer func(network, addr string) (net.Conn, error)) (*dns.Msg, error) {
	addr = strings.TrimPrefix(addr, "tls://")
	addr = strings.TrimPrefix(addr, "dot://")
	if !strings.Contains(addr, ":") {
		addr += ":853" // 默认 DoT 端口
	}

	var netConn net.Conn
	var err error
	if dialer != nil {
		netConn, err = dialer("tcp", addr)
	} else {
		netConn, err = net.DialTimeout("tcp", addr, 5*time.Second)
	}
	if err != nil {
		return nil, err
	}

	host, _, _ := net.SplitHostPort(addr)
	tlsConn := tls.Client(netConn, &tls.Config{ServerName: host})
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, err
	}

	dnsConn := &dns.Conn{Conn: tlsConn}
	defer dnsConn.Close()

	dnsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := dnsConn.WriteMsg(req); err != nil {
		return nil, err
	}
	return dnsConn.ReadMsg()
}

// 传统 TCP 解析器
func resolveTCP(req *dns.Msg, addr string, dialer func(network, addr string) (net.Conn, error)) (*dns.Msg, error) {
	addr = strings.TrimPrefix(addr, "tcp://")
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}

	var netConn net.Conn
	var err error
	if dialer != nil {
		netConn, err = dialer("tcp", addr)
	} else {
		netConn, err = net.DialTimeout("tcp", addr, 5*time.Second)
	}
	if err != nil {
		return nil, err
	}

	dnsConn := &dns.Conn{Conn: netConn}
	defer dnsConn.Close()

	dnsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := dnsConn.WriteMsg(req); err != nil {
		return nil, err
	}
	return dnsConn.ReadMsg()
}

// ==================== 主入口点 ====================

func handleSshTcpDns(requestMsg *dns.Msg) (*dns.Msg, error) {
	domainName := "unknown"
	qtypeStr := "unknown"
	var cacheKey string
	var cleanDomain string

	if len(requestMsg.Question) > 0 {
		q := requestMsg.Question[0]
		domainName = q.Name
		cleanDomain = strings.TrimSuffix(domainName, ".")
		qtypeStr = dns.TypeToString[q.Qtype]
		// ⚡ 优化：零分配字符串拼接
		cacheKey = domainName + "-" + strconv.Itoa(int(q.Qtype))
	}

	isDirect := false
	if globalRouter != nil {
		isDirect = globalRouter.MatchDomain(cleanDomain)
	}

	// 1. Fast Path - 读取缓存
	if cacheKey != "" {
		dnsCacheMu.RLock()
		entry, found := dnsCache[cacheKey]
		dnsCacheMu.RUnlock()

		if found {
			if time.Now().Before(entry.expiresAt) {
				cachedReply := copyAndAdjustTTL(entry, requestMsg.Id)
				printDnsResponse("本地缓存 (Cache)", "Memory", domainName, qtypeStr, cachedReply)
				return cachedReply, nil
			}
			dnsCacheMu.Lock()
			delete(dnsCache, cacheKey)
			dnsCacheMu.Unlock()
		}
	}

	// 2. SingleFlight 合并并发请求
	v, err, shared := dnsFlightGroup.Do(cacheKey, func() (interface{}, error) {
		dnsCacheMu.RLock()
		entry, found := dnsCache[cacheKey]
		dnsCacheMu.RUnlock()
		if found && time.Now().Before(entry.expiresAt) {
			return entry.msg, nil
		}

		serverUrl := globalConfig.RemoteDnsServer
		if isDirect {
			serverUrl = globalConfig.LocalDnsServer
			if serverUrl == "" {
				serverUrl = "223.5.5.5:53" // 直连默认 UDP
			}
		} else if serverUrl == "" {
			serverUrl = "8.8.8.8:53" // 代理默认 TCP
		}

		// 准备代理拨号器
		var dialer func(network, addr string) (net.Conn, error)
		var currentSshClient *ssh.Client

		if !isDirect {
			mu.Lock()
			currentSshClient = sshClient
			mu.Unlock()

			if currentSshClient == nil {
				return nil, fmt.Errorf("ssh client not ready")
			}
			dialer = func(network, addr string) (net.Conn, error) {
				return currentSshClient.Dial(network, addr)
			}
		}

		var reply *dns.Msg
		var finalErr error
		maxRetries := 3

		for attempt := 1; attempt <= maxRetries; attempt++ {
			if attempt > 1 {
				zlog.Warnf("%s [DNS] ⚠️ 第 %d 次重试解析: %s", TAG, attempt, domainName)
			}

			// 🌟 协议分发路由器
			if strings.HasPrefix(serverUrl, "https://") || strings.HasPrefix(serverUrl, "doh://") {
				targetUrl := strings.Replace(serverUrl, "doh://", "https://", 1)
				reply, finalErr = resolveDoH(requestMsg, targetUrl, isDirect, currentSshClient)
			} else if strings.HasPrefix(serverUrl, "tls://") || strings.HasPrefix(serverUrl, "dot://") {
				reply, finalErr = resolveDoT(requestMsg, serverUrl, dialer)
			} else if strings.HasPrefix(serverUrl, "tcp://") {
				reply, finalErr = resolveTCP(requestMsg, serverUrl, dialer)
			} else if strings.HasPrefix(serverUrl, "udp://") {
				addr := strings.TrimPrefix(serverUrl, "udp://")
				if !strings.Contains(addr, ":") { addr += ":53" }
				dnsClient := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
				reply, _, finalErr = dnsClient.Exchange(requestMsg, addr)
			} else {
				// 兼容老版本的无前缀配置
				if isDirect {
					dnsClient := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
					reply, _, finalErr = dnsClient.Exchange(requestMsg, serverUrl)
				} else {
					// 传统的复用池 TCP 解析
					tcpConn, getErr := getDnsConn(currentSshClient, serverUrl)
					if getErr == nil {
						tcpConn.SetDeadline(time.Now().Add(5 * time.Second))
						if finalErr = tcpConn.WriteMsg(requestMsg); finalErr == nil {
							reply, finalErr = tcpConn.ReadMsg()
						}
						tcpConn.SetDeadline(time.Time{})
						if finalErr == nil {
							putDnsConn(tcpConn)
						} else {
							tcpConn.Close()
						}
					} else {
						finalErr = getErr
					}
				}
			}

			if finalErr == nil && reply != nil {
				break
			}
			time.Sleep(300 * time.Millisecond) // 重试间隔防抖
		}

		if finalErr != nil || reply == nil {
			zlog.Errorf("%s [DNS] ❌ 解析失败 [%s] -> %s: %v", TAG, serverUrl, domainName, finalErr)
			return nil, finalErr
		}

		if reply.Rcode == dns.RcodeSuccess || reply.Rcode == dns.RcodeNameError {
			optimalTTL := calculateOptimalTTL(reply)
			now := time.Now()

			dnsCacheMu.Lock()
			if len(dnsCache) >= CacheCleanupThreshold {
				evictDNSCacheLocked()
			}
			dnsCache[cacheKey] = dnsCacheEntry{
				msg:       reply.Copy(),
				expiresAt: now.Add(time.Duration(optimalTTL) * time.Second),
				cachedAt:  now,
			}
			dnsCacheMu.Unlock()
		}

		return reply, nil
	})

	if err != nil {
		return nil, err
	}

	originalReply := v.(*dns.Msg)
	finalReply := originalReply.Copy()
	finalReply.Id = requestMsg.Id 

	// 判断信息源以输出日志
	var source string
	var serverStr string
	if shared {
		source = "并发队列 (SingleFlight)"
		serverStr = "Shared"
	} else if isDirect {
		source = "直连解析 (Local)"
		serverStr = globalConfig.LocalDnsServer
	} else {
		source = "远端代理 (Remote)"
		serverStr = globalConfig.RemoteDnsServer
	}

	printDnsResponse(source, serverStr, domainName, qtypeStr, finalReply)

	return finalReply, nil
}

// ==================== 辅助打印与获取接口 ====================

func printDnsResponse(source, server, domainName, qtypeStr string, reply *dns.Msg) {
	if reply == nil {
		return
	}
	rcodeStr := dns.RcodeToString[reply.MsgHdr.Rcode]
	zlog.Infof("%s [DNS] ✅ 解析成功 | 来源=[%s] | 节点=[%s] | 域名=[%s] | 类型=[%s] | 状态=[%s] | 记录数=[%d]",
		TAG, source, server, domainName, qtypeStr, rcodeStr, len(reply.Answer))

	for _, ans := range reply.Answer {
		switch record := ans.(type) {
		case *dns.A:
			zlog.Infof("%s [DNS] └─ [A记录] IP: %s (TTL: %d)", TAG, record.A.String(), record.Hdr.Ttl)
		case *dns.AAAA:
			zlog.Infof("%s [DNS] └─ [AAAA记录] IPv6: %s (TTL: %d)", TAG, record.AAAA.String(), record.Hdr.Ttl)
		case *dns.CNAME:
			zlog.Infof("%s [DNS] └─ [CNAME记录] 别名: %s (TTL: %d)", TAG, record.Target, record.Hdr.Ttl)
		default:
			zlog.Infof("%s [DNS] └─ [%s记录] %s (TTL: %d)", TAG, dns.TypeToString[ans.Header().Rrtype], ans.String(), ans.Header().Ttl)
		}
	}
}

func GetCachedIPs(domain string) []net.IP {
	fqdn := dns.Fqdn(domain)
	var ips []net.IP

	dnsCacheMu.RLock()
	defer dnsCacheMu.RUnlock()

	keyA := fqdn + "-" + strconv.Itoa(int(dns.TypeA))
	if entry, found := dnsCache[keyA]; found && time.Now().Before(entry.expiresAt) {
		for _, ans := range entry.msg.Answer {
			if record, ok := ans.(*dns.A); ok {
				ips = append(ips, record.A)
			}
		}
	}

	keyAAAA := fqdn + "-" + strconv.Itoa(int(dns.TypeAAAA))
	if entry, found := dnsCache[keyAAAA]; found && time.Now().Before(entry.expiresAt) {
		for _, ans := range entry.msg.Answer {
			if record, ok := ans.(*dns.AAAA); ok {
				ips = append(ips, record.AAAA)
			}
		}
	}

	return ips
}

// ==================== 本地 DNS 服务端 (Local DNS Server) ====================

var (
	localUdpServer *dns.Server
	localTcpServer *dns.Server
)

// localDnsHandler 负责接收本地 DNS 请求，并调用核心逻辑
func localDnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	// 调用你现有的核心解析入口
	reply, err := handleSshTcpDns(r)
	if err != nil || reply == nil {
		// 如果解析失败，返回标准 Server Failure 响应
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}

	// 将解析结果写回给客户端 (miekg/dns 会自动处理 TCP 的长度头或 UDP 包)
	w.WriteMsg(reply)
}

// StartLocalDNSServer 启动本地 DNS 服务器监听 UDP 和 TCP
// port: 想要监听的端口，例如 10553
func StartLocalDNSServer(port int) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// 使用独立的 ServeMux
	mux := dns.NewServeMux()
	mux.HandleFunc(".", localDnsHandler)

	udpConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("绑定 UDP 端口失败: %w", err) // 发生错误，立刻同步返回
	}

	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		udpConn.Close() // TCP 失败了，记得把前面成功的 UDP 端口释放掉
		return fmt.Errorf("绑定 TCP 端口失败: %w", err) // 发生错误，立刻同步返回
	}
	// ===================================================

	// 将我们成功绑定的连接交给 dns.Server
	localUdpServer = &dns.Server{PacketConn: udpConn, Net: "udp", Handler: mux}
	localTcpServer = &dns.Server{Listener: tcpListener, Net: "tcp", Handler: mux}

	// 启动 UDP 监听 (此时由于端口已经绑定成功，ActivateAndServe 极少会报错)
	go func() {
		zlog.Infof("%s [DNS-Server] 🚀 正在启动本地 UDP DNS 服务监听: %s", TAG, addr)
		if err := localUdpServer.ActivateAndServe(); err != nil {
			zlog.Errorf("%s [DNS-Server] ❌ UDP 服务异常退出: %v", TAG, err)
		}
	}()

	// 启动 TCP 监听
	go func() {
		zlog.Infof("%s [DNS-Server] 🚀 正在启动本地 TCP DNS 服务监听: %s", TAG, addr)
		if err := localTcpServer.ActivateAndServe(); err != nil {
			zlog.Errorf("%s [DNS-Server] ❌ TCP 服务异常退出: %v", TAG, err)
		}
	}()

	return nil // 只有双端端口都绑定成功，才会真正在这里返回 nil
}

// StopLocalDNSServer 优雅停止本地 DNS 服务器
func StopLocalDNSServer() {
	if localUdpServer != nil {
		if err := localUdpServer.Shutdown(); err != nil {
			zlog.Errorf("%s [DNS-Server] 停止 UDP 服务出错: %v", TAG, err)
		}
	}
	if localTcpServer != nil {
		if err := localTcpServer.Shutdown(); err != nil {
			zlog.Errorf("%s [DNS-Server] 停止 TCP 服务出错: %v", TAG, err)
		}
	}
	zlog.Infof("%s [DNS-Server] 🛑 本地 DNS 服务已安全停止", TAG)
}