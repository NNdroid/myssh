package myssh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/singleflight"
)

// 本文件实现本地 DNS 服务器：请求入口（lookupDNS）、四类上游解析
// （UDP/TCP/DoT/DoH，各含直连与经隧道两种路径）、启停与对外查询 API。
// 缓存与连接池实现见 dns_cache.go。

// LocalDnsServer 是本地 DNS 分流服务器。
type LocalDnsServer struct {
	UdpgwAddr    string
	UdpgwVersion string

	udpServer *dns.Server
	tcpServer *dns.Server

	// 上游 client 连接池
	tcpConnPools    sync.Map
	dotConnPools    sync.Map
	directUdpClient *dns.Client
	dohMu           sync.Mutex
	directDoH       *http.Client
	proxiedDoH      *http.Client
	lastSshClient   *ssh.Client

	// 响应缓存
	cache        map[string]dnsCacheEntry
	cacheMu      sync.RWMutex
	singleflight *singleflight.Group

	closeChan chan struct{}
	closeOnce sync.Once
}

var (
	localDnsServer  atomic.Pointer[LocalDnsServer]
	dotSessionCache = utls.NewLRUClientSessionCache(64)
)

func NewLocalDnsServer(udpgwAddr string, udpgwVersion string) *LocalDnsServer {
	l := &LocalDnsServer{
		UdpgwAddr:       udpgwAddr,
		UdpgwVersion:    udpgwVersion,
		singleflight:    &singleflight.Group{},
		cache:           make(map[string]dnsCacheEntry),
		closeChan:       make(chan struct{}),
		directUdpClient: &dns.Client{Net: "udp", Timeout: 5 * time.Second},
	}
	go l.cacheCleanupLoop()
	localDnsServer.Store(l)
	return l
}

// getPool 取（或创建）一个 key 对应的上游连接池。
func (l *LocalDnsServer) getPool(poolsMap *sync.Map, poolKey string) *dnsConnPool {
	val, _ := poolsMap.LoadOrStore(poolKey, newDNSConnPool(10))
	return val.(*dnsConnPool)
}

// dialTracked 建 dial 上游连接（直连或经 SSH 隧道），并纳入流量统计。
func (l *LocalDnsServer) dialTracked(network, addr string, isDirect bool, sshClient *ssh.Client, prefix string) (net.Conn, error) {
	var rawConn net.Conn
	var err error

	if isDirect {
		// 🟢 直连模式：普通 TCP 或 UDP，直接 Dial
		rawConn, err = dialProtected(currentEngineCtx(), ProxyConfig{}, network, addr, 5*time.Second)
	} else {
		if sshClient == nil {
			return nil, fmt.Errorf("ssh client disconnected")
		}

		// 🔵 隧道模式：所有 TCP 或 UDP 走 SSH 通道
		if network == "udp" {
			// UDP 上游走 UDPGW tunnel
			if l.UdpgwAddr == "" {
				return nil, fmt.Errorf("proxy udp requires udpgw_addr to be configured")
			}

			if l.UdpgwVersion == "badvpn" {
				rawConn, err = DialBadvpnUdpgw(sshClient, l.UdpgwAddr, addr)
			} else {
				rawConn, err = DialTun2proxyUdpgw(sshClient, l.UdpgwAddr, addr)
			}
		} else {
			// 普通 TCP 走 SSH tunnel 通道
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
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.cleanupExpiredCache()
		case <-l.closeChan:
			zlog.Infof("%s [DNS-Server] 🛑 DNS cache cleanup daemon safely exited", TAG)
			return
		}
	}
}

// ==================== Request handling (lookupDNS / HandleDnsRequest) ====================

// lookupDNS is the core resolution entry point. On a cache hit with the packed
// wire form available it returns packed (with the request's transaction ID and
// decayed TTLs applied, ready to write to the wire); otherwise it returns a
// structured reply (ID already set). At least one of the two is non-nil.
func (l *LocalDnsServer) lookupDNS(requestMsg *dns.Msg) ([]byte, *dns.Msg, string, error) {
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
	if gr := globalRouter.Load(); gr != nil {
		isDirect = gr.MatchDomain(cleanDomain)
	}

	// Top-level cache hit.
	if cacheKey != "" {
		l.cacheMu.RLock()
		entry, found := l.cache[cacheKey]
		l.cacheMu.RUnlock()

		if found {
			if time.Now().Before(entry.expiresAt) {
				if buf, ok := l.patchPacked(entry, requestMsg.Id); ok {
					l.printDnsResponse(" (Cache)", "Memory", domainName, qtypeStr, nil)
					return buf, nil, "Memory", nil
				}
				if entry.msg != nil {
					cachedReply := l.copyAndAdjustTTL(entry, requestMsg.Id)
					l.printDnsResponse(" (Cache)", "Memory", domainName, qtypeStr, cachedReply)
					return nil, cachedReply, "Memory", nil
				}
			} else {
				l.cacheMu.Lock()
				delete(l.cache, cacheKey)
				l.cacheMu.Unlock()
			}
		}
	}

	type sfResult struct {
		packed    []byte
		reply     *dns.Msg
		serverUrl string
	}

	// SingleFlight merges concurrent lookups for the same question.
	v, err, shared := l.singleflight.Do(cacheKey, func() (interface{}, error) {
		if packed, msg := l.readCache(cacheKey, requestMsg.Id); packed != nil || msg != nil {
			return sfResult{packed: packed, reply: msg, serverUrl: "Local Cache"}, nil
		}

		serverUrl := globalConfig.Load().RemoteDnsServer
		if isDirect {
			serverUrl = globalConfig.Load().LocalDnsServer
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
			if Debug {
				zlog.Errorf("%s [DNS] ❌ Resolution failed [%s] -> %s: %v", TAG, serverUrl, domainName, finalErr)
			}
			return nil, finalErr
		}

		if reply.Rcode == dns.RcodeSuccess || reply.Rcode == dns.RcodeNameError {
			l.cacheMu.Lock()
			entry := dnsCacheEntry{
				expiresAt: time.Now().Add(time.Duration(l.calculateOptimalTTL(reply)) * time.Second),
				cachedAt:  time.Now(),
				ips:       extractAnswerIPs(reply),
			}
			// Prefer caching the packed wire form so hits skip Unpack/Pack entirely;
			// fall back to the structured copy when packing or scanning fails.
			if packedBytes, perr := reply.Pack(); perr == nil {
				if offs := scanWireTTLOffsets(packedBytes); offs != nil {
					entry.packed = packedBytes
					entry.ttlOffset = offs
				}
			}
			if entry.packed == nil {
				entry.msg = reply.Copy()
			}
			l.cache[cacheKey] = entry
			l.cacheMu.Unlock()
		}

		// Serve this request from the cache as well so the packed and fallback
		// paths behave identically (transaction ID + TTL decay semantics).
		packed, msg := l.readCache(cacheKey, requestMsg.Id)
		if packed == nil && msg == nil {
			// Extremely unlikely: the entry we just stored was evicted by the
			// cleanup loop before we could read it back.
			fallback := reply.Copy()
			fallback.Id = requestMsg.Id
			msg = fallback
		}
		return sfResult{packed: packed, reply: msg, serverUrl: serverUrl}, nil
	})

	if err != nil {
		return nil, nil, "", err
	}

	result := v.(sfResult)
	if result.packed == nil && result.reply == nil {
		return nil, nil, "", fmt.Errorf("dns lookup returned no result")
	}

	source := "Remote Proxy"
	if shared {
		source = "Concurrent Queue (SingleFlight)"
	} else if isDirect {
		source = "Direct Resolution (Local)"
	}
	l.printDnsResponse(source, result.serverUrl, domainName, qtypeStr, result.reply)

	return result.packed, result.reply, result.serverUrl, nil
}

// HandleDnsRequest keeps the original structured-message interface.
func (l *LocalDnsServer) HandleDnsRequest(requestMsg *dns.Msg) (*dns.Msg, error) {
	packed, reply, _, err := l.lookupDNS(requestMsg)
	if err != nil {
		return nil, err
	}
	if packed != nil {
		m := new(dns.Msg)
		if err := m.Unpack(packed); err != nil {
			return nil, err
		}
		return m, nil
	}
	return reply, nil
}

// HandleDNSRequestPacked is for callers that write to the wire directly (the
// SOCKS5 UDP hijack path): on a cache hit it returns ready-to-send message
// bytes without any Unpack/Pack round-trip.
func (l *LocalDnsServer) HandleDNSRequestPacked(requestMsg *dns.Msg) ([]byte, error) {
	packed, reply, _, err := l.lookupDNS(requestMsg)
	if err != nil {
		return nil, err
	}
	if packed != nil {
		return packed, nil
	}
	return reply.Pack()
}

// ==================== 上游解析（均经 dialTracked） ====================

// resolveUDP 走 UDP 上游解析（经 dialTracked）。
func (l *LocalDnsServer) resolveUDP(req *dns.Msg, addr string, isDirect bool, sshClient *ssh.Client) (*dns.Msg, error) {
	addr = strings.TrimPrefix(addr, "udp://")
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}

	// 直连、UDPGW 均可转发！
	trackedConn, err := l.dialTracked("udp", addr, isDirect, sshClient, "DNS-UDP")
	if err != nil {
		return nil, err
	}
	defer trackedConn.Close()

	trackedConn.SetDeadline(time.Now().Add(5 * time.Second))

	// 直连模式：走 miekg/dns 标准交换
	if isDirect {
		dnsConn := &dns.Conn{Conn: trackedConn}
		resp, _, err := l.directUdpClient.ExchangeWithConn(req, dnsConn)
		return resp, err
	}

	// 隧道模式（UDPGW）：TCP 载 UDP 载荷，不能用 ExchangeWithConn（会复用连接），手工一问一答
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
	// 取带 poolKey 的连接
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
		// 使用带 poolKey 的归还
		l.putTcpConnToPool(tcpConn, poolKey)
		zlog.Debugf("%s [DNS-TCP] ✅ Resolution completed | Latency: %dms", TAG, time.Since(start).Milliseconds())
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
	// 取带 poolKey 的连接
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
		// 使用带 poolKey 的归还
		l.putDoTConnToPool(dotConn, poolKey)
		zlog.Debugf("%s [DNS-DoT] ✅ Resolution completed | Latency: %dms", TAG, time.Since(start).Milliseconds())
	} else {
		dotConn.Close()
	}

	return reply, err
}

// ==================== DoH client 管理 ====================

func (l *LocalDnsServer) getDoHClient(isDirect bool, sshClient *ssh.Client) *http.Client {
	l.dohMu.Lock()
	defer l.dohMu.Unlock()

	// ==========================================
	// 直连 DoH Client
	// ==========================================
	if isDirect {
		if l.directDoH == nil {
			l.directDoH = &http.Client{
				Timeout: 5 * time.Second,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return l.dialTracked(network, addr, true, nil, "DNS-DoH-Direct")
					},
					ForceAttemptHTTP2:   true,
					MaxIdleConns:        100,
					MaxIdleConnsPerHost: 10,
					IdleConnTimeout:     30 * time.Second,
				},
			}
		}
		return l.directDoH
	}

	// ==========================================
	// 隧道 DoH Client（随 SSH client 更换重建）
	// ==========================================
	if l.proxiedDoH == nil || sshClient != l.lastSshClient {
		if l.proxiedDoH != nil {
			l.proxiedDoH.CloseIdleConnections() // 关闭旧 client 的空闲连接
		}
		l.lastSshClient = sshClient
		l.proxiedDoH = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return l.dialTracked(network, addr, false, sshClient, "DNS-DoH-Proxy")
				},
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
			},
		}
	}
	return l.proxiedDoH
}

// ==================== TCP 连接池 ====================

func (l *LocalDnsServer) getTcpConnFromPool(addr string, isDirect bool, client *ssh.Client, forceNew bool) (*dns.Conn, string, error) {
	poolKey := fmt.Sprintf("%v|%s", isDirect, addr) // 例如 "true|8.8.8.8:53"
	pool := l.getPool(&l.tcpConnPools, poolKey)

	if !forceNew {
		if pc, ok := l.tryGetPooledConn(pool); ok {
			return pc, poolKey, nil
		}
	}

	trackedConn, err := l.dialTracked("tcp", addr, isDirect, client, "DNS-TCP")
	if err != nil {
		return nil, "", err
	}
	return &dns.Conn{Conn: trackedConn}, poolKey, nil
}

func (l *LocalDnsServer) putTcpConnToPool(conn *dns.Conn, poolKey string) {
	pool := l.getPool(&l.tcpConnPools, poolKey)
	pool.put(pooledDnsConn{conn: conn})
}

// ==================== DoT 连接池 ====================

func (l *LocalDnsServer) getDoTConnFromPool(addr string, isDirect bool, client *ssh.Client, forceNew bool) (*dns.Conn, string, error) {
	poolKey := fmt.Sprintf("%v|%s", isDirect, addr) // 例如 "false|8.8.8.8:853"
	pool := l.getPool(&l.dotConnPools, poolKey)

	if !forceNew {
		if pc, ok := l.tryGetPooledConn(pool); ok {
			return pc, poolKey, nil
		}
	}

	trackedConn, err := l.dialTracked("tcp", addr, isDirect, client, "DNS-DoT")
	if err != nil {
		return nil, "", err
	}

	host, _, _ := net.SplitHostPort(addr)
	hsCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tlsConn, err := newChromeUConn(hsCtx, trackedConn, host, []string{"dot"}, dotSessionCache, true)
	if err != nil {
		return nil, "", err
	}

	return &dns.Conn{Conn: tlsConn}, poolKey, nil
}

func (l *LocalDnsServer) putDoTConnToPool(conn *dns.Conn, poolKey string) {
	pool := l.getPool(&l.dotConnPools, poolKey)
	pool.put(pooledDnsConn{conn: conn})
}

// ==================== 服务与对外查询 ====================

func (l *LocalDnsServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	packed, reply, _, err := l.lookupDNS(r)
	if err != nil {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}
	if packed != nil {
		// Pre-packed cache hit: write the wire bytes directly with zero
		// Unpack/Pack; miekg's response writer adds the TCP length prefix.
		w.Write(packed)
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
	zlog.Infof("%s [DNS-Server] 🚀 Local DNS service started: %s", TAG, addr)
	return nil
}

func (l *LocalDnsServer) Stop() {
	l.closeOnce.Do(func() {
		close(l.closeChan)
		if l.udpServer != nil {
			l.udpServer.Shutdown()
		}
		if l.tcpServer != nil {
			l.tcpServer.Shutdown()
		}
		l.tcpConnPools.Range(func(key, value interface{}) bool {
			value.(*dnsConnPool).closeAll()
			return true
		})
		l.dotConnPools.Range(func(key, value interface{}) bool {
			value.(*dnsConnPool).closeAll()
			return true
		})
	})
}

func (l *LocalDnsServer) printDnsResponse(source, server, domainName, qtypeStr string, reply *dns.Msg) {
	if reply == nil {
		return
	}
	rcodeStr := dns.RcodeToString[reply.MsgHdr.Rcode]
	zlog.Debugf("%s [DNS] ✅ Resolution successful | Source=[%s] | Server=[%s] | Domain=[%s] | Type=[%s] | Status=[%s] | Records=[%d]",
		TAG, source, server, domainName, qtypeStr, rcodeStr, len(reply.Answer))

	for _, ans := range reply.Answer {
		switch record := ans.(type) {
		case *dns.A:
			zlog.Debugf("%s [DNS] └─ [A record] IP: %s (TTL: %d)", TAG, record.A.String(), record.Hdr.Ttl)
		case *dns.AAAA:
			zlog.Debugf("%s [DNS] └─ [AAAA record] IPv6: %s (TTL: %d)", TAG, record.AAAA.String(), record.Hdr.Ttl)
		case *dns.CNAME:
			zlog.Debugf("%s [DNS] └─ [CNAME record] Alias: %s (TTL: %d)", TAG, record.Target, record.Hdr.Ttl)
		default:
			// 其余记录类型 (MX, TXT, NS, SRV, etc.)
			zlog.Debugf("%s [DNS] └─ [%s record] %s (TTL: %d)",
				TAG, dns.TypeToString[ans.Header().Rrtype], ans.String(), ans.Header().Ttl)
		}
	}
}

// GetCachedIPs 返回域名在缓存中的 A/AAAA 记录 IP（供路由热路径直读）。
func GetCachedIPs(domain string) []net.IP {
	lds := localDnsServer.Load()
	if lds == nil {
		return nil
	}
	fqdn := dns.Fqdn(domain)
	var ips []net.IP
	lds.cacheMu.RLock()
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		key := fqdn + "-" + strconv.Itoa(int(qt))
		if entry, ok := lds.cache[key]; ok && time.Now().Before(entry.expiresAt) {
			// 直读写入时预解析好的 ips 切片（不可变）。该函数位于 UDP
			// 数据面逐包热路径上，绝不能在这里 Unpack——旧实现每次命中
			// 都重新解包整条 DNS 消息且持有读锁，高吞吐下开销显著。
			ips = append(ips, entry.ips...)
		}
	}
	lds.cacheMu.RUnlock()
	return ips
}

// ResolveOne 同步解析域名并返回首个匹配类型的记录值。
func ResolveOne(host string, qType uint16) net.IP {
	lds := localDnsServer.Load()
	if lds == nil {
		return nil
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), qType)
	reply, err := lds.HandleDnsRequest(msg)
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
