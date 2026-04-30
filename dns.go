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

// ==================== 常量与类型定义 ====================

const (
	MaxCacheSize          = 5000
	CacheCleanupThreshold = 6000
	DefaultMinTTL         = 60
	DefaultMaxTTL         = 3600
	CacheCleanupInterval  = 60 * time.Second
)

type dnsCacheEntry struct {
	msg       *dns.Msg
	expiresAt time.Time
	cachedAt  time.Time
}

type pooledDnsConn struct {
	conn     *dns.Conn
	lastUsed time.Time
}

// LocalDnsServer 核心 DNS 管理对象
type LocalDnsServer struct {
	UdpgwAddr    string
	UdpgwVersion string

	// 运行实例
	udpServer *dns.Server
	tcpServer *dns.Server

	// 连接池与客户端组件
	tcpConnPools    sync.Map
	dotConnPools    sync.Map
	directUdpClient *dns.Client
	dohMu           sync.Mutex
	directDoH       *http.Client
	proxiedDoH      *http.Client
	lastSshClient   *ssh.Client

	// 缓存与并发控制
	cache        map[string]dnsCacheEntry
	cacheMu      sync.RWMutex
	singleflight *singleflight.Group
}

var (
	localDnsServer  *LocalDnsServer
	dotSessionCache = tls.NewLRUClientSessionCache(64)
)

// ==================== 构造与初始化 ====================

func NewLocalDnsServer(udpgwAddr string, udpgwVersion string) *LocalDnsServer {
	l := &LocalDnsServer{
		UdpgwAddr:       udpgwAddr,
		UdpgwVersion:    udpgwVersion,
		singleflight:    &singleflight.Group{},
		cache:           make(map[string]dnsCacheEntry),
	}
	go l.cacheCleanupLoop()
	localDnsServer = l
	return l
}

// getPool 动态获取或创建专属连接池
func (l *LocalDnsServer) getPool(poolsMap *sync.Map, poolKey string) chan pooledDnsConn {
	val, _ := poolsMap.LoadOrStore(poolKey, make(chan pooledDnsConn, 10))
	return val.(chan pooledDnsConn)
}

// dialTracked 统一处理直连/代理的拨号逻辑，并自动进行 WrapConn 流量追踪
func (l *LocalDnsServer) dialTracked(network, addr string, isDirect bool, sshClient *ssh.Client, prefix string) (net.Conn, error) {
	var rawConn net.Conn
	var err error

	if isDirect {
		// 🟢 直连模式：无论是 TCP 还是 UDP，都直接使用标准库 Dial
		rawConn, err = net.DialTimeout(network, addr, 5*time.Second)
	} else {
		if sshClient == nil {
			return nil, fmt.Errorf("ssh client disconnected")
		}

		// 🔵 代理模式：必须区分 TCP 和 UDP 协议
		if network == "udp" {
			// 代理 UDP 必须走 UDPGW 隧道
			if l.UdpgwAddr == "" {
				return nil, fmt.Errorf("proxy udp requires udpgw_addr to be configured")
			}
			
			if l.UdpgwVersion == "badvpn" {
				rawConn, err = DialBadvpnUdpgw(sshClient, l.UdpgwAddr, addr)
			} else {
				rawConn, err = DialTun2proxyUdpgw(sshClient, l.UdpgwAddr, addr)
			}
		} else {
			// 代理 TCP 走标准 SSH 隧道转发
			rawConn, err = sshClient.Dial(network, addr)
		}
	}

	if err != nil {
		return nil, err
	}

	sessionName := fmt.Sprintf("%s->%s", prefix, addr)
	return WrapConn(rawConn, sessionName), nil
}

func (l *LocalDnsServer) cacheCleanupLoop() {
	ticker := time.NewTicker(CacheCleanupInterval)
	for range ticker.C {
		l.cleanupExpiredCache()
	}
}

// ==================== 核心解析入口 (HandleDnsRequest) ====================

func (l *LocalDnsServer) HandleDnsRequest(requestMsg *dns.Msg) (*dns.Msg, error) {
	domainName := "unknown"
	qtypeStr := "unknown"
	var cacheKey string
	var cleanDomain string

	if len(requestMsg.Question) > 0 {
		q := requestMsg.Question[0]
		domainName = q.Name
		cleanDomain = strings.TrimSuffix(domainName, ".")
		qtypeStr = dns.TypeToString[q.Qtype]
		cacheKey = domainName + "-" + strconv.Itoa(int(q.Qtype))
	}

	isDirect := false
	if globalRouter != nil {
		isDirect = globalRouter.MatchDomain(cleanDomain)
	}

	// 1. 缓存快查
	if cacheKey != "" {
		l.cacheMu.RLock()
		entry, found := l.cache[cacheKey]
		l.cacheMu.RUnlock()

		if found {
			if time.Now().Before(entry.expiresAt) {
				cachedReply := l.copyAndAdjustTTL(entry, requestMsg.Id)
				l.printDnsResponse("本地缓存 (Cache)", "Memory", domainName, qtypeStr, cachedReply)
				return cachedReply, nil
			}
			l.cacheMu.Lock()
			delete(l.cache, cacheKey)
			l.cacheMu.Unlock()
		}
	}

	// 🌟 定义结果封装以解决 serverUrl 作用域问题
	type sfResult struct {
		reply     *dns.Msg
		serverUrl string
	}

	// 2. SingleFlight 请求合并
	v, err, shared := l.singleflight.Do(cacheKey, func() (interface{}, error) {
		l.cacheMu.RLock()
		if entry, found := l.cache[cacheKey]; found && time.Now().Before(entry.expiresAt) {
			l.cacheMu.RUnlock()
			return sfResult{reply: entry.msg, serverUrl: "Shared-Task"}, nil
		}
		l.cacheMu.RUnlock()

		serverUrl := globalConfig.RemoteDnsServer
		if isDirect {
			serverUrl = globalConfig.LocalDnsServer
			if serverUrl == "" {
				serverUrl = "223.5.5.5:53"
			}
		} else if serverUrl == "" {
			serverUrl = "8.8.8.8:53"
		}

		mu.Lock()
		curSshClient := sshClient
		mu.Unlock()

		var reply *dns.Msg
		var finalErr error

		for attempt := 1; attempt <= 3; attempt++ {
			if attempt > 1 {
				zlog.Warnf("%s [DNS] ⚠️ 第 %d 次重试解析: %s", TAG, attempt, domainName)
			}

			if strings.HasPrefix(serverUrl, "https://") || strings.HasPrefix(serverUrl, "doh://") {
				target := strings.Replace(serverUrl, "doh://", "https://", 1)
				reply, finalErr = l.resolveDoH(requestMsg, target, isDirect, curSshClient)
			} else if strings.HasPrefix(serverUrl, "tls://") || strings.HasPrefix(serverUrl, "dot://") {
				reply, finalErr = l.resolveDoT(requestMsg, serverUrl, isDirect, curSshClient, attempt > 1)
			} else if strings.HasPrefix(serverUrl, "tcp://") {
				reply, finalErr = l.resolveTCP(requestMsg, serverUrl, isDirect, curSshClient, attempt > 1)
			} else { // udp \ default
				reply, finalErr = l.resolveUDP(requestMsg, serverUrl, isDirect, curSshClient)
			}

			if finalErr == nil && reply != nil {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}

		if finalErr != nil || reply == nil {
			zlog.Errorf("%s [DNS] ❌ 解析失败 [%s] -> %s: %v", TAG, serverUrl, domainName, finalErr)
			return nil, finalErr
		}

		if reply.Rcode == dns.RcodeSuccess || reply.Rcode == dns.RcodeNameError {
			l.cacheMu.Lock()
			l.cache[cacheKey] = dnsCacheEntry{
				msg:       reply.Copy(),
				expiresAt: time.Now().Add(time.Duration(l.calculateOptimalTTL(reply)) * time.Second),
				cachedAt:  time.Now(),
			}
			l.cacheMu.Unlock()
		}

		return sfResult{reply: reply, serverUrl: serverUrl}, nil
	})

	if err != nil {
		return nil, err
	}

	result := v.(sfResult)
	finalReply := result.reply.Copy()
	finalReply.Id = requestMsg.Id

	source := "远端代理 (Remote)"
	if shared {
		source = "并发队列 (SingleFlight)"
	} else if isDirect {
		source = "直连解析 (Local)"
	}
	l.printDnsResponse(source, result.serverUrl, domainName, qtypeStr, finalReply)

	return finalReply, nil
}

// ==================== 协议解析器实现 (保留原生逻辑) ====================

// resolveUDP 解析 UDP 流量 (已重构接入 dialTracked)
func (l *LocalDnsServer) resolveUDP(req *dns.Msg, addr string, isDirect bool, sshClient *ssh.Client) (*dns.Msg, error) {
	addr = strings.TrimPrefix(addr, "udp://")
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}

	// 🌟 1. 一行代码搞定拨号、UDPGW 分流和流量追踪！
	trackedConn, err := l.dialTracked("udp", addr, isDirect, sshClient, "DNS-UDP")
	if err != nil {
		return nil, err
	}
	defer trackedConn.Close()

	trackedConn.SetDeadline(time.Now().Add(5 * time.Second))

	// 🌟 2. 直连模式：依然可以使用 miekg/dns 的便捷方法
	if isDirect {
		dnsConn := &dns.Conn{Conn: trackedConn}
		resp, _, err := l.directUdpClient.ExchangeWithConn(req, dnsConn)
		return resp, err
	}

	// 🌟 3. 代理模式 (UDPGW)：底层是 TCP 承载的 UDP 报文，不能用 ExchangeWithConn，必须手动收发
	reqBytes, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack dns request failed: %v", err)
	}

	if _, err := trackedConn.Write(reqBytes); err != nil {
		return nil, fmt.Errorf("write udp dns request failed: %v", err)
	}

	bufPtr := udpBufPool.Get().(*[]byte)
	buffer := (*bufPtr)[:cap(*bufPtr)]
	defer udpBufPool.Put(bufPtr)

	n, err := trackedConn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("read udp dns response failed: %v", err)
	}

	reply := new(dns.Msg)
	if err := reply.Unpack(buffer[:n]); err != nil {
		return nil, fmt.Errorf("unpack dns response failed: %v", err)
	}

	return reply, nil
}

func (l *LocalDnsServer) resolveTCP(req *dns.Msg, addr string, isDirect bool, sshClient *ssh.Client, forceNew bool) (*dns.Msg, error) {
	addr = strings.TrimPrefix(addr, "tcp://")
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}

	start := time.Now()
	// 🌟 接收 poolKey
	tcpConn, poolKey, err := l.getTcpConnFromPool(addr, isDirect, sshClient, forceNew)
	if err != nil {
		return nil, err
	}

	tcpConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tcpConn.WriteMsg(req); err != nil {
		tcpConn.Close()
		return nil, err
	}

	reply, err := tcpConn.ReadMsg()
	if err == nil {
		// 🌟 按 poolKey 精准归还
		l.putTcpConnToPool(tcpConn, poolKey)
		zlog.Debugf("%s [DNS-TCP] ✅ 解析完成 | 耗时: %dms", TAG, time.Since(start).Milliseconds())
	} else {
		tcpConn.Close()
	}

	return reply, err
}

func (l *LocalDnsServer) resolveDoH(req *dns.Msg, url string, isDirect bool, sshClient *ssh.Client) (*dns.Msg, error) {
	msgBytes, _ := req.Pack()
	httpReq, _ := http.NewRequest("POST", url, bytes.NewReader(msgBytes))
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	client := l.getDoHClient(isDirect, sshClient)
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH status: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	reply := new(dns.Msg)
	err = reply.Unpack(body)
	return reply, err
}

func (l *LocalDnsServer) resolveDoT(req *dns.Msg, addr string, isDirect bool, sshClient *ssh.Client, forceNew bool) (*dns.Msg, error) {
	addr = strings.TrimPrefix(addr, "tls://")
	addr = strings.TrimPrefix(addr, "dot://")
	if !strings.Contains(addr, ":") {
		addr += ":853"
	}

	start := time.Now()
	// 🌟 接收 poolKey
	dotConn, poolKey, err := l.getDoTConnFromPool(addr, isDirect, sshClient, forceNew)
	if err != nil {
		return nil, err
	}

	dotConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := dotConn.WriteMsg(req); err != nil {
		dotConn.Close()
		return nil, err
	}

	reply, err := dotConn.ReadMsg()
	if err == nil {
		// 🌟 按 poolKey 精准归还
		l.putDoTConnToPool(dotConn, poolKey)
		zlog.Debugf("%s [DNS-DoT] ✅ 解析完成 | 耗时: %dms", TAG, time.Since(start).Milliseconds())
	} else {
		dotConn.Close()
	}

	return reply, err
}

// ==================== 内部组件与辅助方法 ====================

func (l *LocalDnsServer) getDoHClient(isDirect bool, sshClient *ssh.Client) *http.Client {
	l.dohMu.Lock()
	defer l.dohMu.Unlock()
	
	// ==========================================
	// 1. 直连 DoH Client
	// ==========================================
	if isDirect {
		if l.directDoH == nil {
			l.directDoH = &http.Client{
				Timeout: 5 * time.Second,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return l.dialTracked(network, addr, true, nil, "DNS-DoH-Direct")
					},
					ForceAttemptHTTP2: true,
					MaxIdleConns:        100,
					MaxIdleConnsPerHost: 10,
					IdleConnTimeout:     30 * time.Second,
				},
			}
		}
		return l.directDoH
	}
	
	// ==========================================
	// 2. 代理 DoH Client
	// ==========================================
	if l.proxiedDoH == nil || sshClient != l.lastSshClient {
		l.lastSshClient = sshClient
		l.proxiedDoH = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return l.dialTracked(network, addr, false, sshClient, "DNS-DoH-Proxy")
				},
				ForceAttemptHTTP2: true,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
			},
		}
	}
	return l.proxiedDoH
}

// ==================== TCP 池管理 ====================

func (l *LocalDnsServer) getTcpConnFromPool(addr string, isDirect bool, client *ssh.Client, forceNew bool) (*dns.Conn, string, error) {
	poolKey := fmt.Sprintf("%v|%s", isDirect, addr) // 例如 "true|8.8.8.8:53"
	pool := l.getPool(&l.tcpConnPools, poolKey)

	if !forceNew {
		for {
			select {
			case pc := <-pool:
				if time.Since(pc.lastUsed) > 5*time.Second {
					pc.conn.Close()
					continue
				}
				return pc.conn, poolKey, nil
			default:
				goto DialNew
			}
		}
	}
DialNew:
	trackedConn, err := l.dialTracked("tcp", addr, isDirect, client, "DNS-TCP")
	if err != nil {
		return nil, "", err
	}
	return &dns.Conn{Conn: trackedConn}, poolKey, nil
}

func (l *LocalDnsServer) putTcpConnToPool(conn *dns.Conn, poolKey string) {
	pool := l.getPool(&l.tcpConnPools, poolKey)
	select {
	case pool <- pooledDnsConn{conn: conn, lastUsed: time.Now()}:
	default:
		conn.Close()
	}
}

// ==================== DoT 池管理 ====================

func (l *LocalDnsServer) getDoTConnFromPool(addr string, isDirect bool, client *ssh.Client, forceNew bool) (*dns.Conn, string, error) {
	poolKey := fmt.Sprintf("%v|%s", isDirect, addr) // 例如 "false|8.8.8.8:853"
	pool := l.getPool(&l.dotConnPools, poolKey)

	if !forceNew {
		for {
			select {
			case pc := <-pool:
				if time.Since(pc.lastUsed) > 5*time.Second {
					pc.conn.Close()
					continue
				}
				return pc.conn, poolKey, nil
			default:
				goto DialNew
			}
		}
	}
DialNew:
	trackedConn, err := l.dialTracked("tcp", addr, isDirect, client, "DNS-DoT")
	if err != nil {
		return nil, "", err
	}

	host, _, _ := net.SplitHostPort(addr)
	tlsConn := tls.Client(trackedConn, &tls.Config{
		ServerName:         host,
		ClientSessionCache: dotSessionCache,
	})
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, "", err
	}

	return &dns.Conn{Conn: tlsConn}, poolKey, nil
}

func (l *LocalDnsServer) putDoTConnToPool(conn *dns.Conn, poolKey string) {
	pool := l.getPool(&l.dotConnPools, poolKey)
	select {
	case pool <- pooledDnsConn{conn: conn, lastUsed: time.Now()}:
	default:
		conn.Close()
	}
}

func (l *LocalDnsServer) calculateOptimalTTL(reply *dns.Msg) uint32 {
	minTTL := uint32(DefaultMaxTTL)
	for _, ans := range reply.Answer {
		ttl := ans.Header().Ttl
		if ttl > 0 && ttl < minTTL {
			minTTL = ttl
		}
	}
	if minTTL < uint32(DefaultMinTTL) {
		return uint32(DefaultMinTTL)
	}
	if minTTL > uint32(DefaultMaxTTL) {
		return uint32(DefaultMaxTTL)
	}
	return minTTL
}

func (l *LocalDnsServer) copyAndAdjustTTL(entry dnsCacheEntry, newMsgId uint16) *dns.Msg {
	cachedReply := entry.msg.Copy()
	cachedReply.Id = newMsgId
	elapsed := uint32(time.Since(entry.cachedAt).Seconds())
	adjust := func(rrs []dns.RR) {
		for _, rr := range rrs {
			h := rr.Header()
			if h.Ttl >= elapsed {
				h.Ttl -= elapsed
			} else {
				h.Ttl = 0
			}
		}
	}
	adjust(cachedReply.Answer)
	adjust(cachedReply.Ns)
	adjust(cachedReply.Extra)
	return cachedReply
}

func (l *LocalDnsServer) cleanupExpiredCache() {
	l.cacheMu.Lock()
	defer l.cacheMu.Unlock()
	now := time.Now()
	deleted := 0
	for k, v := range l.cache {
		if now.After(v.expiresAt) {
			delete(l.cache, k)
			deleted++
		}
	}
	if len(l.cache) >= CacheCleanupThreshold {
		toDelete := len(l.cache) - MaxCacheSize
		for k := range l.cache {
			if toDelete <= 0 {
				break
			}
			delete(l.cache, k)
			toDelete--
			deleted++
		}
	}
	if deleted > 0 {
		zlog.Debugf("%s [Cache-GC] ♻️ 清理了 %d 条缓存，当前余量: %d", TAG, deleted, len(l.cache))
	}
}

// ==================== 服务控制 ====================

func (l *LocalDnsServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	reply, err := l.HandleDnsRequest(r)
	if err != nil {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}
	w.WriteMsg(reply)
}

func (l *LocalDnsServer) Start(addr string) error {
	l.udpServer = &dns.Server{Addr: addr, Net: "udp", Handler: l}
	l.tcpServer = &dns.Server{Addr: addr, Net: "tcp", Handler: l}
	go func() {
		if err := l.udpServer.ListenAndServe(); err != nil {
			zlog.Errorf("UDP DNS Fail: %v", err)
		}
	}()
	go func() {
		if err := l.tcpServer.ListenAndServe(); err != nil {
			zlog.Errorf("TCP DNS Fail: %v", err)
		}
	}()
	zlog.Infof("%s [DNS-Server] 🚀 本地 DNS 服务启动: %s", TAG, addr)
	return nil
}

func (l *LocalDnsServer) Stop() {
	if l.udpServer != nil {
		l.udpServer.Shutdown()
	}
	if l.tcpServer != nil {
		l.tcpServer.Shutdown()
	}
}

func (l *LocalDnsServer) printDnsResponse(source, server, domainName, qtypeStr string, reply *dns.Msg) {
	if reply == nil {
		return
	}
	rcodeStr := dns.RcodeToString[reply.MsgHdr.Rcode]
	zlog.Debugf("%s [DNS] ✅ 解析成功 | 来源=[%s] | 节点=[%s] | 域名=[%s] | 类型=[%s] | 状态=[%s] | 记录数=[%d]",
		TAG, source, server, domainName, qtypeStr, rcodeStr, len(reply.Answer))

	for _, ans := range reply.Answer {
		switch record := ans.(type) {
		case *dns.A:
			zlog.Debugf("%s [DNS] └─ [A记录] IP: %s (TTL: %d)", TAG, record.A.String(), record.Hdr.Ttl)
		case *dns.AAAA:
			zlog.Debugf("%s [DNS] └─ [AAAA记录] IPv6: %s (TTL: %d)", TAG, record.AAAA.String(), record.Hdr.Ttl)
		case *dns.CNAME:
			zlog.Debugf("%s [DNS] └─ [CNAME记录] 别名: %s (TTL: %d)", TAG, record.Target, record.Hdr.Ttl)
		default:
			// 兜底支持所有其他记录类型 (MX, TXT, NS, SRV, etc.)
			zlog.Debugf("%s [DNS] └─ [%s记录] %s (TTL: %d)",
				TAG, dns.TypeToString[ans.Header().Rrtype], ans.String(), ans.Header().Ttl)
		}
	}
}

// ==================== 全局适配接口 ====================

func GetCachedIPs(domain string) []net.IP {
	if localDnsServer == nil {
		return nil
	}
	fqdn := dns.Fqdn(domain)
	var ips []net.IP
	localDnsServer.cacheMu.RLock()
	defer localDnsServer.cacheMu.RUnlock()
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		key := fqdn + "-" + strconv.Itoa(int(qt))
		if entry, ok := localDnsServer.cache[key]; ok && time.Now().Before(entry.expiresAt) {
			for _, ans := range entry.msg.Answer {
				if a, ok := ans.(*dns.A); ok {
					ips = append(ips, a.A)
				}
				if aaaa, ok := ans.(*dns.AAAA); ok {
					ips = append(ips, aaaa.AAAA)
				}
			}
		}
	}
	return ips
}

func ResolveOne(host string, qType uint16) net.IP {
	if localDnsServer == nil {
		return nil
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), qType)
	reply, err := localDnsServer.HandleDnsRequest(msg)
	if err == nil && reply != nil && len(reply.Answer) > 0 {
		for _, ans := range reply.Answer {
			if qType == dns.TypeAAAA {
				if aaaa, ok := ans.(*dns.AAAA); ok {
					return aaaa.AAAA
				}
			} else {
				if a, ok := ans.(*dns.A); ok {
					return a.A
				}
			}
		}
	}
	return nil
}
