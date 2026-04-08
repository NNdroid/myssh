// dns.go - 优化后版本
package myssh

import (
	"fmt"
	"net"
	"sort"
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

const (
	MaxCacheSize            = 5000
	CacheCleanupThreshold   = 6000
	DefaultMinTTL           = 60
	DefaultMaxTTL           = 3600
	CacheCleanupInterval    = 60 * time.Second
)

var (
	dnsConnPool = make(chan *dns.Conn, 10)
	dnsCache    = make(map[string]dnsCacheEntry)
	dnsCacheMu  sync.RWMutex
	
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

// cleanupExpiredDNSCache 清理过期的 DNS 缓存
func cleanupExpiredDNSCache() {
	dnsCacheMu.Lock()
	defer dnsCacheMu.Unlock()
	
	now := time.Now()
	deleted := 0
	for k, v := range dnsCache {
		if now.After(v.expiresAt) {
			delete(dnsCache, k)
			deleted++
		}
	}
	
	if deleted > 0 {
		zlog.Infof("%s [Cache-GC] ♻️ 主动清理了 %d 条过期的 DNS 缓存", TAG, deleted)
	}
}

func getDnsConn(client *ssh.Client) (*dns.Conn, error) {
	select {
	case conn := <-dnsConnPool:
		return conn, nil
	default:
		if globalConfig.RemoteDnsServer == "" {
			globalConfig.RemoteDnsServer = "8.8.8.8:53"
		}
		netConn, err := client.Dial("tcp", globalConfig.RemoteDnsServer)
		if err != nil {
			return nil, err
		}
		return &dns.Conn{Conn: netConn}, nil
	}
}

func putDnsConn(conn *dns.Conn) {
	select {
	case dnsConnPool <- conn:
	default:
		conn.Close()
	}
}

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

// calculateOptimalTTL 计算最优的缓存 TTL（尊重原始响应）
func calculateOptimalTTL(reply *dns.Msg) uint32 {
	minTTL := uint32(DefaultMaxTTL)
	
	for _, ans := range reply.Answer {
		ttl := ans.Header().Ttl
		if ttl > 0 && ttl < minTTL {
			minTTL = ttl
		}
	}
	
	// 对 TTL 进行约束
	if minTTL < uint32(DefaultMinTTL) {
		minTTL = uint32(DefaultMinTTL)
	} else if minTTL > uint32(DefaultMaxTTL) {
		minTTL = uint32(DefaultMaxTTL)
	}
	
	return minTTL
}

// evictDNSCache 智能缓存清理策略
func evictDNSCache() {
	now := time.Now()
	deleted := 0
	
	// 第一步：删除所有过期项
	for k, v := range dnsCache {
		if now.After(v.expiresAt) {
			delete(dnsCache, k)
			deleted++
		}
	}
	
	// 如果缓存仍然超限，删除最旧的 25%
	if len(dnsCache) >= CacheCleanupThreshold {
		orderedKeys := make([]string, 0, len(dnsCache))
		for k := range dnsCache {
			orderedKeys = append(orderedKeys, k)
		}
		
		// 按 cachedAt 排序
		sort.Slice(orderedKeys, func(i, j int) bool {
			return dnsCache[orderedKeys[i]].cachedAt.Before(
				dnsCache[orderedKeys[j]].cachedAt)
		})
		
		toDelete := len(orderedKeys) / 4
		for i := 0; i < toDelete && len(dnsCache) > MaxCacheSize; i++ {
			delete(dnsCache, orderedKeys[i])
			deleted++
		}
	}
	
	if deleted > 0 {
		zlog.Debugf("%s [Cache-Evict] 清理了 %d 条缓存项，当前缓存大小: %d", TAG, deleted, len(dnsCache))
	}
}

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
		cacheKey = fmt.Sprintf("%s-%d", domainName, q.Qtype)
	}

	isDirect := false
	if globalRouter != nil {
		isDirect = globalRouter.MatchDomain(cleanDomain)
	}

	// 一次检查缓存 (Fast Path)
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
			// 过期则删除
			dnsCacheMu.Lock()
			delete(dnsCache, cacheKey)
			dnsCacheMu.Unlock()
		}
	}

	// 将并发请求加入队列 (SingleFlight)
	v, err, shared := dnsFlightGroup.Do(cacheKey, func() (interface{}, error) {
		
		// 进入执行队列后，先做二次缓存检查
		dnsCacheMu.RLock()
		entry, found := dnsCache[cacheKey]
		dnsCacheMu.RUnlock()
		if found && time.Now().Before(entry.expiresAt) {
			return entry.msg, nil
		}

		var reply *dns.Msg
		var finalErr error
		maxRetries := 3

		// 自动重试 3 次逻辑
		for attempt := 1; attempt <= maxRetries; attempt++ {
			if attempt > 1 {
				zlog.Warnf("%s [DNS] ⚠️ 第 %d 次重试解析: %s", TAG, attempt, domainName)
			}

			if isDirect {
				// 直连解析 (UDP)
				if globalConfig.LocalDnsServer == "" {
					globalConfig.LocalDnsServer = "223.5.5.5:53"
				}
				dnsClient := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
				reply, _, finalErr = dnsClient.Exchange(requestMsg, globalConfig.LocalDnsServer)
			} else {
				// 远端 SSH 解析 (TCP)
				mu.Lock()
				client := sshClient
				mu.Unlock()

				if client == nil {
					finalErr = fmt.Errorf("ssh client not ready")
					time.Sleep(500 * time.Millisecond)
					continue
				}

				tcpConn, getErr := getDnsConn(client)
				if getErr != nil {
					finalErr = getErr
					time.Sleep(500 * time.Millisecond)
					continue
				}

				tcpConn.SetDeadline(time.Now().Add(5 * time.Second))
				if writeErr := tcpConn.WriteMsg(requestMsg); writeErr != nil {
					finalErr = writeErr
					tcpConn.Close()
					continue
				}

				reply, finalErr = tcpConn.ReadMsg()
				if finalErr != nil {
					tcpConn.Close()
					continue
				}

				tcpConn.SetDeadline(time.Time{})
				putDnsConn(tcpConn)
			}

			// 成功则跳出重试循环
			if finalErr == nil && reply != nil {
				break
			}
		}

		// 经过 3 次重试依然失败
		if finalErr != nil || reply == nil {
			zlog.Errorf("%s [DNS] ❌ 历经 %d 次尝试后彻底失败 (%s): %v", TAG, maxRetries, domainName, finalErr)
			return nil, finalErr
		}

		// 解析成功，写入缓存 - 使用智能 TTL 管理
		if reply.Rcode == dns.RcodeSuccess || reply.Rcode == dns.RcodeNameError {
			dnsCacheMu.Lock()
			
			// 检查缓存是否需要清理
			if len(dnsCache) >= CacheCleanupThreshold {
				evictDNSCache()
			}
			
			optimalTTL := calculateOptimalTTL(reply)
			now := time.Now()
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

	var source string
	var server string

	if shared {
		source = "并发队列 (SingleFlight)"
		server = "Shared"
	} else if isDirect {
		source = "直连解析 (Local UDP)"
		server = globalConfig.LocalDnsServer
		if server == "" { server = "223.5.5.5:53" }
	} else {
		source = "远端代理 (Remote TCP)"
		server = globalConfig.RemoteDnsServer
		if server == "" { server = "8.8.8.8:53" }
	}

	printDnsResponse(source, server, domainName, qtypeStr, finalReply)

	return finalReply, nil
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

func GetCachedIPs(domain string) []net.IP {
	fqdn := dns.Fqdn(domain)
	var ips []net.IP

	dnsCacheMu.RLock()
	defer dnsCacheMu.RUnlock()

	keyA := fmt.Sprintf("%s-%d", fqdn, dns.TypeA)
	if entry, found := dnsCache[keyA]; found && time.Now().Before(entry.expiresAt) {
		for _, ans := range entry.msg.Answer {
			if record, ok := ans.(*dns.A); ok {
				ips = append(ips, record.A)
			}
		}
	}

	keyAAAA := fmt.Sprintf("%s-%d", fqdn, dns.TypeAAAA)
	if entry, found := dnsCache[keyAAAA]; found && time.Now().Before(entry.expiresAt) {
		for _, ans := range entry.msg.Answer {
			if record, ok := ans.(*dns.AAAA); ok {
				ips = append(ips, record.AAAA)
			}
		}
	}

	return ips
}