package myssh

import (
	"fmt"
	"net"
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
	cachedAt  time.Time // 用于动态扣减 TTL
}

var (
	// dnsConnPool 作为复用池，最大保持 10 个空闲连接
	dnsConnPool = make(chan *dns.Conn, 10)
	dnsCache    = make(map[string]dnsCacheEntry)
	dnsCacheMu  sync.RWMutex

	// 🌟 单飞队列 (SingleFlight)，用于合并对同一个域名的并发查询，防止并发洪峰打穿代理
	dnsFlightGroup singleflight.Group
)

// init 函数会在包加载时自动运行，启动后台清理任务
func init() {
	go func() {
		// 每 60 秒主动清理一次已过期的缓存，释放内存
		ticker := time.NewTicker(60 * time.Second)
		for range ticker.C {
			dnsCacheMu.Lock()
			now := time.Now()
			deleted := 0
			for k, v := range dnsCache {
				if now.After(v.expiresAt) {
					delete(dnsCache, k)
					deleted++
				}
			}
			dnsCacheMu.Unlock()
			if deleted > 0 {
				zlog.Infof("%s [Cache-GC] ♻️ 主动清理了 %d 条过期的 DNS 缓存", TAG, deleted)
			}
		}
	}()
}

// getDnsConn 从池中获取或新建 SSH TCP 连接
func getDnsConn(client *ssh.Client) (*dns.Conn, error) {
	select {
	case conn := <-dnsConnPool:
		return conn, nil // 成功复用
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

// putDnsConn 将健康的连接放回池中复用
func putDnsConn(conn *dns.Conn) {
	select {
	case dnsConnPool <- conn:
	default:
		conn.Close()
	}
}

// printDnsResponse 辅助函数：统一且详细地打印 DNS 响应结果
func printDnsResponse(source, server, domainName, qtypeStr string, reply *dns.Msg) {
	if reply == nil {
		return
	}
	rcodeStr := dns.RcodeToString[reply.MsgHdr.Rcode]
	
	// 🌟 详细打印出：来源、查询节点、域名、类型、状态等
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

// handleSshTcpDns 处理 DNS 查询，带有重试机制和队列防并发保护
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

	// 提前判定路由规则，方便后续打印和查询
	isDirect := false
	if globalRouter != nil {
		isDirect = globalRouter.MatchDomain(cleanDomain)
	}

	// ==========================================
	// 1. 一次检查缓存 (Fast Path)
	// ==========================================
	if cacheKey != "" {
		dnsCacheMu.RLock()
		entry, found := dnsCache[cacheKey]
		dnsCacheMu.RUnlock()

		if found {
			if time.Now().Before(entry.expiresAt) {
				cachedReply := copyAndAdjustTTL(entry, requestMsg.Id)
				// 🌟 明确打印从缓存返回
				printDnsResponse("本地缓存 (Cache)", "Memory", domainName, qtypeStr, cachedReply)
				return cachedReply, nil
			}
			// 过期则删除
			dnsCacheMu.Lock()
			delete(dnsCache, cacheKey)
			dnsCacheMu.Unlock()
		}
	}

	// ==========================================
	// 2. 将并发请求加入队列 (SingleFlight)
	// ==========================================
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

		// 🌟 自动重试 3 次逻辑
		for attempt := 1; attempt <= maxRetries; attempt++ {
			if attempt > 1 {
				zlog.Warnf("%s [DNS] ⚠️ 第 %d 次重试解析: %s", TAG, attempt, domainName)
			}

			if isDirect {
				// 🌍 直连解析 (UDP)
				if globalConfig.LocalDnsServer == "" {
					globalConfig.LocalDnsServer = "223.5.5.5:53"
				}
				dnsClient := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
				reply, _, finalErr = dnsClient.Exchange(requestMsg, globalConfig.LocalDnsServer)
			} else {
				// 🛡️ 远端 SSH 解析 (TCP)
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

		// --- 3. 解析成功，写入缓存 ---
		if reply.Rcode == dns.RcodeSuccess || reply.Rcode == dns.RcodeNameError {
			dnsCacheMu.Lock()
			if len(dnsCache) >= 10000 {
				for k := range dnsCache {
					delete(dnsCache, k)
					break 
				}
			}
			now := time.Now()
			dnsCache[cacheKey] = dnsCacheEntry{
				msg:       reply.Copy(),
				expiresAt: now.Add(120 * time.Second),
				cachedAt:  now,
			}
			dnsCacheMu.Unlock()
		}

		return reply, nil
	})

	if err != nil {
		return nil, err
	}

	// ==========================================
	// 4. 处理最终返回结果并判定日志来源
	// ==========================================
	originalReply := v.(*dns.Msg)
	finalReply := originalReply.Copy()
	finalReply.Id = requestMsg.Id 

	// 判定来源与使用的服务器
	var source string
	var server string

	if shared {
		// 该请求是跟着别人一起排队的，直接拿到了别人的结果
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

	// 统一调用辅助函数进行打印
	printDnsResponse(source, server, domainName, qtypeStr, finalReply)

	return finalReply, nil
}

// copyAndAdjustTTL 辅助函数：深度拷贝缓存结果并动态扣减 TTL
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

// GetCachedIPs 尝试从安全的远端 DNS 缓存中提取域名的 A 或 AAAA 记录
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