package myssh

import (
	"bytes"
	"context"
	"encoding/binary"
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

// ====================  info  ====================

const (
	MaxCacheSize          = 5000
	CacheCleanupThreshold = 6000
	DefaultMinTTL         = 60
	DefaultMaxTTL         = 3600
	CacheCleanupInterval  = 60 * time.Second
)

type dnsCacheEntry struct {
	// msg 是回退缓存：wire 打包/TTL 偏移扫描失败时保留结构化消息。
	msg *dns.Msg
	// packed 是预打包响应：命中时写入事务 ID 并按 ttlOffset 衰减 TTL 后
	// 直接写 wire，完全绕开 Unpack/Pack。
	packed    []byte
	ttlOffset []int
	expiresAt time.Time
	cachedAt  time.Time
}

// scanWireTTLOffsets 遍历 DNS wire format，返回每个资源记录 4 字节 TTL 字段的
// 起始偏移。遇到无法安全解析的结构（保留标签类型等）返回 nil，调用方回退到
// msg 深拷贝路径。名称压缩指针只可能指向报文中更早的数据，因此线性扫描是安全的。
func scanWireTTLOffsets(msgBytes []byte) []int {
	if len(msgBytes) < 12 {
		return nil
	}
	var offsets []int
	pos := 12
	qd := int(binary.BigEndian.Uint16(msgBytes[4:6]))
	an := int(binary.BigEndian.Uint16(msgBytes[6:8]))
	ns := int(binary.BigEndian.Uint16(msgBytes[8:10]))
	ar := int(binary.BigEndian.Uint16(msgBytes[10:12]))

	skipName := func() bool {
		for {
			if pos >= len(msgBytes) {
				return false
			}
			l := int(msgBytes[pos])
			switch {
			case l == 0:
				pos++
				return true
			case l&0xC0 == 0xC0: // 压缩指针，名称到此结束
				pos += 2
				return true
			case l&0xC0 != 0: // 保留/未知的标签类型，保守放弃
				return false
			default:
				pos += 1 + l
			}
		}
	}

	for i := 0; i < qd; i++ {
		if !skipName() {
			return nil
		}
		pos += 4 // QTYPE + QCLASS
	}
	for i := 0; i < an+ns+ar; i++ {
		if !skipName() {
			return nil
		}
		if pos+10 > len(msgBytes) {
			return nil
		}
		offsets = append(offsets, pos+4) // TYPE(2) + CLASS(2) 之后是 TTL(4)
		rdlen := int(binary.BigEndian.Uint16(msgBytes[pos+8 : pos+10]))
		pos += 10 + rdlen
	}
	return offsets
}

// patchPacked 复制预打包响应并写入新的事务 ID、按已流逝时间衰减各 RR 的 TTL，
// 语义与 copyAndAdjustTTL 一致。
func (l *LocalDnsServer) patchPacked(entry dnsCacheEntry, id uint16) ([]byte, bool) {
	if len(entry.packed) == 0 || len(entry.ttlOffset) == 0 {
		return nil, false
	}
	buf := make([]byte, len(entry.packed))
	copy(buf, entry.packed)
	binary.BigEndian.PutUint16(buf[0:2], id)
	elapsed := uint32(time.Since(entry.cachedAt).Seconds())
	if elapsed > 0 {
		for _, off := range entry.ttlOffset {
			if off+4 > len(buf) {
				return nil, false
			}
			ttl := binary.BigEndian.Uint32(buf[off : off+4])
			if ttl > elapsed {
				ttl -= elapsed
			} else {
				ttl = 0
			}
			binary.BigEndian.PutUint32(buf[off:off+4], ttl)
		}
	}
	return buf, true
}

// readCache 读取缓存命中：优先返回打好补丁的预打包字节，否则回退到结构化
// 深拷贝。返回值二选一非 nil。
func (l *LocalDnsServer) readCache(cacheKey string, id uint16) ([]byte, *dns.Msg) {
	l.cacheMu.RLock()
	entry, found := l.cache[cacheKey]
	l.cacheMu.RUnlock()
	if !found || !time.Now().Before(entry.expiresAt) {
		return nil, nil
	}
	if buf, ok := l.patchPacked(entry, id); ok {
		return buf, nil
	}
	if entry.msg != nil {
		return nil, l.copyAndAdjustTTL(entry, id)
	}
	return nil, nil
}

type pooledDnsConn struct {
	conn     *dns.Conn
	lastUsed time.Time
}

// dnsConnPool 是互斥锁保护的可复用连接池。相比 channel：Stop 之后在途请求
// 仍可能把连接归还池中——向已关闭的 channel 发送会 panic（select default 挡不住
// 已关闭 channel 的发送），而这里 put 会安全地把连接关掉。
type dnsConnPool struct {
	mu     sync.Mutex
	closed bool
	items  []pooledDnsConn
	max    int
}

func newDNSConnPool(max int) *dnsConnPool {
	return &dnsConnPool{max: max}
}

func (p *dnsConnPool) get() (pooledDnsConn, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.items) == 0 {
		return pooledDnsConn{}, false
	}
	pc := p.items[len(p.items)-1]
	p.items = p.items[:len(p.items)-1]
	return pc, true
}

func (p *dnsConnPool) put(pc pooledDnsConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.items) >= p.max {
		_ = pc.conn.Close()
		return
	}
	pc.lastUsed = time.Now()
	p.items = append(p.items, pc)
}

func (p *dnsConnPool) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for _, pc := range p.items {
		_ = pc.conn.Close()
	}
	p.items = nil
}

// LocalDnsServer  info  DNS  info
type LocalDnsServer struct {
	UdpgwAddr    string
	UdpgwVersion string

	//  info
	udpServer *dns.Server
	tcpServer *dns.Server

	//  info client info
	tcpConnPools    sync.Map
	dotConnPools    sync.Map
	directUdpClient *dns.Client
	dohMu           sync.Mutex
	directDoH       *http.Client
	proxiedDoH      *http.Client
	lastSshClient   *ssh.Client

	//  info
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

// ====================  info  ====================

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

// getPool  info
func (l *LocalDnsServer) getPool(poolsMap *sync.Map, poolKey string) *dnsConnPool {
	val, _ := poolsMap.LoadOrStore(poolKey, newDNSConnPool(10))
	return val.(*dnsConnPool)
}

// dialTracked  info / info ， info  WrapConn  info
func (l *LocalDnsServer) dialTracked(network, addr string, isDirect bool, sshClient *ssh.Client, prefix string) (net.Conn, error) {
	var rawConn net.Conn
	var err error

	if isDirect {
		// 🟢  info mode： info  TCP  info  UDP， info  Dial
		rawConn, err = dialProtected(currentEngineCtx(), ProxyConfig{}, network, addr, 5*time.Second)
	} else {
		if sshClient == nil {
			return nil, fmt.Errorf("ssh client disconnected")
		}

		// 🔵  info mode： info  TCP  info  UDP  info
		if network == "udp" {
			//  info  UDP  info  UDPGW tunnel
			if l.UdpgwAddr == "" {
				return nil, fmt.Errorf("proxy udp requires udpgw_addr to be configured")
			}

			if l.UdpgwVersion == "badvpn" {
				rawConn, err = DialBadvpnUdpgw(sshClient, l.UdpgwAddr, addr)
			} else {
				rawConn, err = DialTun2proxyUdpgw(sshClient, l.UdpgwAddr, addr)
			}
		} else {
			//  info  TCP  info  SSH tunnel info
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
			if attempt > 1 {
				zlog.Warnf("%s [DNS] ⚠️ Retry parsing #%d: %s", TAG, attempt, domainName)
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

// ====================  info  ( info ) ====================

// resolveUDP  info  UDP  info  ( info  dialTracked)
func (l *LocalDnsServer) resolveUDP(req *dns.Msg, addr string, isDirect bool, sshClient *ssh.Client) (*dns.Msg, error) {
	addr = strings.TrimPrefix(addr, "udp://")
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}

	//  info 、UDPGW  info ！
	trackedConn, err := l.dialTracked("udp", addr, isDirect, sshClient, "DNS-UDP")
	if err != nil {
		return nil, err
	}
	defer trackedConn.Close()

	trackedConn.SetDeadline(time.Now().Add(5 * time.Second))

	//  info mode： info  miekg/dns  info
	if isDirect {
		dnsConn := &dns.Conn{Conn: trackedConn}
		resp, _, err := l.directUdpClient.ExchangeWithConn(req, dnsConn)
		return resp, err
	}

	//  info mode (UDPGW)： info  TCP  info  UDP  info ， info  ExchangeWithConn， info
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
	//  info  poolKey
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
		//  info  poolKey  info
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
	//  info  poolKey
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
		//  info  poolKey  info
		l.putDoTConnToPool(dotConn, poolKey)
		zlog.Debugf("%s [DNS-DoT] ✅ Resolution completed | Latency: %dms", TAG, time.Since(start).Milliseconds())
	} else {
		dotConn.Close()
	}

	return reply, err
}

// ====================  info  ====================

func (l *LocalDnsServer) getDoHClient(isDirect bool, sshClient *ssh.Client) *http.Client {
	l.dohMu.Lock()
	defer l.dohMu.Unlock()

	// ==========================================
	//  info  DoH Client
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
	//  info  DoH Client
	// ==========================================
	if l.proxiedDoH == nil || sshClient != l.lastSshClient {
		if l.proxiedDoH != nil {
			l.proxiedDoH.CloseIdleConnections() // closed info client info ， info
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

// ==================== TCP  info  ====================

// tryGetPooledConn  info 。
//
//	info successfully info  (conn, true)； info  (nil, false)（ info closed）。
func (l *LocalDnsServer) tryGetPooledConn(pool *dnsConnPool) (*dns.Conn, bool) {
	pc, ok := pool.get()
	if !ok {
		return nil, false
	}
	if time.Since(pc.lastUsed) > 5*time.Second {
		pc.conn.Close()
		return nil, false
	}
	return pc.conn, true
}

func (l *LocalDnsServer) getTcpConnFromPool(addr string, isDirect bool, client *ssh.Client, forceNew bool) (*dns.Conn, string, error) {
	poolKey := fmt.Sprintf("%v|%s", isDirect, addr) //  info  "true|8.8.8.8:53"
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

// ==================== DoT  info  ====================

func (l *LocalDnsServer) getDoTConnFromPool(addr string, isDirect bool, client *ssh.Client, forceNew bool) (*dns.Conn, string, error) {
	poolKey := fmt.Sprintf("%v|%s", isDirect, addr) //  info  "false|8.8.8.8:853"
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
		zlog.Debugf("%s [Cache-GC] ♻️ Cleaned up %d cache entries, remaining: %d", TAG, deleted, len(l.cache))
	}
}

// ====================  info  ====================

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
			//  info support info  (MX, TXT, NS, SRV, etc.)
			zlog.Debugf("%s [DNS] └─ [%s record] %s (TTL: %d)",
				TAG, dns.TypeToString[ans.Header().Rrtype], ans.String(), ans.Header().Ttl)
		}
	}
}

// ====================  info  ====================

func GetCachedIPs(domain string) []net.IP {
	lds := localDnsServer.Load()
	if lds == nil {
		return nil
	}
	fqdn := dns.Fqdn(domain)
	var ips []net.IP
	lds.cacheMu.RLock()
	defer lds.cacheMu.RUnlock()
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		key := fqdn + "-" + strconv.Itoa(int(qt))
		if entry, ok := lds.cache[key]; ok && time.Now().Before(entry.expiresAt) {
			// msg 只在回退路径上保留；packed 路径按需解包。该函数只在
			// 路由未命中/拨号路径上被低频调用，解包开销可忽略。
			msg := entry.msg
			if msg == nil && len(entry.packed) > 0 {
				msg = new(dns.Msg)
				if err := msg.Unpack(entry.packed); err != nil {
					continue
				}
			}
			if msg == nil {
				continue
			}
			for _, ans := range msg.Answer {
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
