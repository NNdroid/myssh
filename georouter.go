package myssh

import (
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/ahocorasick"
	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// 本文件实现 GeoRouter 的运行时判定：域名规则匹配（Full/RootDomain/
// Keyword-AC/Regex 四级）、IP 前缀 Trie 命中、两级缓存（域名判定 / 域名→IP）
// 以及 ShouldDirect 分流入口。规则文件解析见 geo_parse.go，下载见 geo_download.go。

type GeoRouter struct {
	queryCount    atomic.Int64 // 查询数
	cacheHitCount atomic.Int64 // 缓存命中数

	fullDomains map[string]struct{}
	subDomains  map[string]struct{}
	keywordList []string
	keywordAC   *ahocorasick.Matcher
	// cloudflare/ahocorasick 的 Match 内部用实例级 counter 做去重，并发调用
	// 会互踩计数（可能漏掉关键词命中导致误路由），必须串行化。
	keywordMu    sync.Mutex
	regexList    []*regexp.Regexp
	regexGrouped []*regexp.Regexp

	ipTrie            *ipTrie
	domainCache       sync.Map // L1 域名判定缓存（domainCacheEntry）
	routeIPCache      sync.Map // 域名→已解析 IP 缓存（routeResolved），带 TTL
	cacheCount        atomic.Int32
	routeIPCacheCount atomic.Int32

	// resolveGroup 对同一域名的并发 DNS 回退解析去重：UDP 数据面每个包
	// 都会走到 ShouldDirect，缓存冷启动窗口内的并发包必须共享一次解析，
	// 否则会形成 DNS 查询风暴。
	resolveGroup singleflight.Group
}

// routeCacheCleanThreshold 是 L1 缓存的后台清理触发阈值：每写入 N 条触发
// 一次只删过期项的清理（非全清，保留热点，无命中率抖动）。
const routeCacheCleanThreshold = 5000

// domainCacheTTL 是域名判定缓存的存活期。过期条目在读取时惰性失效并
// 重算，保证规则语义最终一致。
const domainCacheTTL = 10 * time.Minute

// domainCacheEntry 是 L1 域名判定的缓存值；带 expire 支持惰性过期。
type domainCacheEntry struct {
	matched bool
	expire  time.Time
}

func newGeoRouter() *GeoRouter {
	return &GeoRouter{
		fullDomains: make(map[string]struct{}),
		subDomains:  make(map[string]struct{}),
		keywordList: make([]string, 0),
		regexList:   make([]*regexp.Regexp, 0),
		ipTrie:      newIPTrie(),
	}
}

type RouteResult struct {
	IsDirect bool   `json:"is_direct"`
	DialHost string `json:"dial_host"`
}

// routeIPCacheTTL 域名解析 IP 缓存的存活期。GeoIP 分流依赖 DNS 解析结果，
//
//	域名（而非“直连域名”）命中 IP 直连的 TTL 不能太长，否则 DNS 变更后
//	SOCKS5 客户端会拿到过期解析。
const routeIPCacheTTL = 5 * time.Minute

// routeResolved 缓存已解析的 IP 列表。
type routeResolved struct {
	ips    []net.IP
	expire time.Time
}

// ShouldDirect 判断目标 host 是否直连。
//
//	先查 GeoSite 域名规则、再查 IP（或解析后）是否 GeoIP 命中，命中则 IsDirect=true，
//
// DialHost 返回实际拨号目标（优先 IP）；否则走代理。
func (r *GeoRouter) ShouldDirect(host string) RouteResult {
	if host == "" {
		return RouteResult{IsDirect: false, DialHost: ""}
	}

	// 使用 Go 1.18+ 的 netip 包解析，比 net.ParseIP 更严格
	if addr, err := netip.ParseAddr(host); err == nil {
		if r.MatchNetIP(addr) {
			zlog.Debugf("%s [Router] Direct IP access [%s] -> Hit GeoIP, routing direct", TAG, host)
			return RouteResult{IsDirect: true, DialHost: host}
		}
		zlog.Debugf("%s [Router] Direct IP access [%s] -> Missed GeoIP, routing proxy", TAG, host)
		return RouteResult{IsDirect: false, DialHost: host}
	}

	// 先查 GeoSite (域名规则) 是否直连
	if r.MatchDomain(host) {
		ips := GetCachedIPs(host)
		if len(ips) > 0 {
			zlog.Debugf("%s [Router] Domain [%s] hit GeoSite -> Using cached IP (%s) for direct routing", TAG, host, ips[0].String())
			return RouteResult{IsDirect: true, DialHost: ips[0].String()}
		}
		zlog.Debugf("%s [Router] Domain [%s] hit GeoSite -> No cached IP, keeping domain for direct routing", TAG, host)
		return RouteResult{IsDirect: true, DialHost: host}
	}

	// 再查 GeoIP (IP 规则)
	ips := GetCachedIPs(host)
	if len(ips) == 0 {
		// 未命中本地 DNS 缓存，查路由自带的解析结果缓存（缩短 SOCKS5 首包延迟）
		if cached, ok := r.routeIPCache.Load(host); ok {
			rc := cached.(routeResolved)
			if time.Now().Before(rc.expire) {
				ips = rc.ips
			} else {
				r.routeIPCache.Delete(host)
			}
		}
	}
	if len(ips) == 0 {
		// singleflight：UDP 数据面每个包都会进入这里，缓存冷启动窗口内
		// 同一域名的并发包只允许触发一次真实解析，其余共享结果——否则
		// 会形成 DNS 查询风暴（解析自带重试，最坏十几秒）。
		v, err, _ := r.resolveGroup.Do("resolve:"+host, func() (interface{}, error) {
			// 双检：等待解析期间其他调用者可能已经填好缓存。
			if cached, ok := r.routeIPCache.Load(host); ok {
				rc := cached.(routeResolved)
				if time.Now().Before(rc.expire) {
					return rc.ips, nil
				}
			}
			// A/AAAA 两族并行解析：串行查询会让代理路径上每个新连接的
			// 建连延迟接近翻倍（解析本身带重试，最坏可达十几秒）。
			var (
				ip4, ip6    net.IP
				resolveDone sync.WaitGroup
			)
			resolveDone.Add(2)
			go func() {
				defer resolveDone.Done()
				ip4 = ResolveOne(host, dns.TypeA)
			}()
			go func() {
				defer resolveDone.Done()
				ip6 = ResolveOne(host, dns.TypeAAAA)
			}()
			resolveDone.Wait()
			var resolved []net.IP
			if ip4 != nil {
				resolved = append(resolved, ip4)
			}
			if ip6 != nil {
				resolved = append(resolved, ip6)
			}
			// 写缓存（固定 TTL）；写后触发阈值清理
			r.routeIPCache.Store(host, routeResolved{ips: resolved, expire: time.Now().Add(routeIPCacheTTL)})

			// 计数越过阈值触发一次后台清理。这里必须无条件归零：旧实现
			// 用 CompareAndSwap(N, 0)，并发下计数跳过 N 后 CAS 永久失配，
			// 清理从此再也不会触发，缓存无界增长。
			if r.routeIPCacheCount.Add(1) >= routeCacheCleanThreshold {
				r.routeIPCacheCount.Store(0)
				go r.cleanExpiredRouteIPCache()
			}
			return resolved, nil
		})
		if err == nil {
			if got, ok := v.([]net.IP); ok {
				ips = got
			}
		}
	}

	for _, resolvedIP := range ips {
		if r.MatchIP(resolvedIP) {
			zlog.Debugf("%s [Router] Domain [%s] resolved IP (%s) hit GeoIP -> routing direct", TAG, host, resolvedIP.String())
			return RouteResult{IsDirect: true, DialHost: resolvedIP.String()}
		}
	}

	// 默认走代理 (兜底)
	zlog.Debugf("%s [Router] Domain [%s] missed all direct rules -> routing proxy", TAG, host)
	return RouteResult{IsDirect: false, DialHost: host}
}

// MatchDomain 匹配域名 - 先查缓存
func (r *GeoRouter) MatchDomain(domain string) bool {
	domain = strings.ToLower(domain)

	// 先查 L1 缓存 (O(1) 命中)
	// 对高频 App / 系统域名，命中率高。
	if val, ok := r.domainCache.Load(domain); ok {
		entry := val.(domainCacheEntry)
		if time.Now().Before(entry.expire) {
			r.cacheHitCount.Add(1)
			r.queryCount.Add(1)
			return entry.matched
		}
		// 过期条目惰性删除，下面重算并写回。
		r.domainCache.Delete(domain)
	}

	r.queryCount.Add(1)
	matched := r.doMatchDomain(domain)

	r.domainCache.Store(domain, domainCacheEntry{matched: matched, expire: time.Now().Add(domainCacheTTL)})

	// 计数越过阈值触发一次后台清理。必须无条件归零：旧实现用
	// CompareAndSwap(N, 0)，并发下计数跳过 N 后 CAS 永久失配，清理从此
	// 再也不触发，缓存无界增长。清理只删过期项，不做全清——全清会把
	// 热点域名一并清掉，造成周期性的命中率归零与 AC/正则匹配尖刺。
	if r.cacheCount.Add(1) >= routeCacheCleanThreshold {
		r.cacheCount.Store(0)
		go r.cleanExpiredDomainCache()
	}

	return matched
}

// cleanExpiredDomainCache 删除 domainCache 中已过期的条目。
func (r *GeoRouter) cleanExpiredDomainCache() {
	now := time.Now()
	r.domainCache.Range(func(key, value interface{}) bool {
		if e, ok := value.(domainCacheEntry); ok && now.After(e.expire) {
			r.domainCache.Delete(key)
		}
		return true
	})
}

// cleanExpiredRouteIPCache 删除 routeIPCache 中已过期的条目。
func (r *GeoRouter) cleanExpiredRouteIPCache() {
	now := time.Now()
	r.routeIPCache.Range(func(key, value interface{}) bool {
		if rc, ok := value.(routeResolved); ok && now.After(rc.expire) {
			r.routeIPCache.Delete(key)
		}
		return true
	})
}

// ResetCacheAndStats 重置 L1 各级缓存与统计
func (r *GeoRouter) ResetCacheAndStats() {
	r.domainCache.Range(func(key, value interface{}) bool {
		r.domainCache.Delete(key)
		return true
	})
	r.routeIPCache.Range(func(key, value interface{}) bool {
		r.routeIPCache.Delete(key)
		return true
	})
	r.cacheCount.Store(0)
	r.routeIPCacheCount.Store(0)
	r.queryCount.Store(0)
	r.cacheHitCount.Store(0)
	zlog.Infof("%s [Router] ♻️ Route cache and query stats manually reset", TAG)
}

// getStats 返回查询统计：(查询数, 命中数)，供 gomobile 导出
func (r *GeoRouter) getStats() (int64, int64) {
	return r.queryCount.Load(), r.cacheHitCount.Load()
}

func (r *GeoRouter) doMatchDomain(domain string) bool {

	// Full 精确匹配
	if _, ok := r.fullDomains[domain]; ok {
		return true
	}

	// Domain 后缀匹配 (逐级上溯：a.b.c -> b.c -> c)
	sub := domain
	for {
		if _, ok := r.subDomains[sub]; ok {
			return true
		}
		idx := strings.IndexByte(sub, '.')
		if idx < 0 {
			break
		}
		sub = sub[idx+1:]
	}

	// Keyword 关键词匹配 (借助 AC 自动机 O(1) 匹配)
	if r.keywordAC != nil {
		// Match 非 concurrent-safe（内部 counter 去重），命中数可能为 0 条
		// 串行调用以规避 Match 的非并发安全实现；只发生在 L1 缓存未命中时。
		r.keywordMu.Lock()
		hits := r.keywordAC.Match([]byte(domain))
		r.keywordMu.Unlock()
		if len(hits) > 0 {
			return true
		}
	} else {
		// 降级线性扫描
		for _, kw := range r.keywordList {
			if strings.Contains(domain, kw) {
				return true
			}
		}
	}

	// 正则匹配 (分组后)
	if len(r.regexGrouped) > 0 {
		for _, re := range r.regexGrouped {
			if re.MatchString(domain) {
				return true
			}
		}
	} else {
		// 未分组时逐条匹配 (combine 失败兜底)
		for _, re := range r.regexList {
			if re.MatchString(domain) {
				return true
			}
		}
	}

	return false
}

func (r *GeoRouter) MatchIP(ip net.IP) bool {
	return r.ipTrie.Contains(ip)
}

// MatchNetIP 匹配 netip.Addr 类型的 IP
func (r *GeoRouter) MatchNetIP(addr netip.Addr) bool {
	if addr.Is4() {
		// addr.As4() 返回 [4]byte，[:] 转切片，避免额外分配
		a4 := addr.As4()
		return r.ipTrie.ContainsBytes(a4[:], true)
	}
	a16 := addr.As16()
	return r.ipTrie.ContainsBytes(a16[:], false)
}
