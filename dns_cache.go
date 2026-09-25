package myssh

import (
	"encoding/binary"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// 本文件实现 LocalDnsServer 的缓存层与上游连接池：
//   - 预打包 wire 缓存（命中免 Unpack/Pack，仅补事务 ID、衰减 TTL）
//   - 结构化消息回退缓存
//   - TCP/DoT 复用连接池

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
	// ips 是写入时预解析好的 A/AAAA 记录切片（不可变，只读共享）。
	// 路由热路径 GetCachedIPs 被 UDP 数据面逐包调用，直读该切片即可，
	// 绝不能在读锁内重新 Unpack 整条 DNS 消息。
	ips       []net.IP
	expiresAt time.Time
	cachedAt  time.Time
}

// extractAnswerIPs 从 DNS 响应中提取 A/AAAA 记录值，供缓存条目预解析。
func extractAnswerIPs(msg *dns.Msg) []net.IP {
	var ips []net.IP
	for _, ans := range msg.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			ips = append(ips, rr.A)
		case *dns.AAAA:
			ips = append(ips, rr.AAAA)
		}
	}
	return ips
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

// tryGetPooledConn 从池中取一条仍新鲜的连接。
//
//	命中且未过期返回 (conn, true)；否则 (nil, false)（含连接已关闭）。
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
		// 超限时按过期时间最旧优先淘汰：随机淘汰会误删刚写入的热点域名。
		// 该路径低频（超过 6000 条才触发），排序开销可接受。
		type cacheCandidate struct {
			key       string
			expiresAt time.Time
		}
		candidates := make([]cacheCandidate, 0, len(l.cache))
		for k, v := range l.cache {
			candidates = append(candidates, cacheCandidate{key: k, expiresAt: v.expiresAt})
		}
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].expiresAt.Before(candidates[j].expiresAt)
		})
		toDelete := len(candidates) - MaxCacheSize
		for i := 0; i < toDelete; i++ {
			delete(l.cache, candidates[i].key)
			deleted++
		}
	}
	if deleted > 0 {
		zlog.Debugf("%s [Cache-GC] ♻️ Cleaned up %d cache entries, remaining: %d", TAG, deleted, len(l.cache))
	}
}
