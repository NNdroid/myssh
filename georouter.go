package myssh

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/ahocorasick"
	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
	"google.golang.org/protobuf/encoding/protowire"
)

const (
	GEOIP_URL   = "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"
	GEOSITE_URL = "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"
)

// shouldDownload reports whether filePath needs to be (re)downloaded: it is
// missing, older than 24 hours, or structurally unusable.
//
// The age check alone is not enough. A truncated download lands with a fresh
// mtime, so it would otherwise sit on disk for a full refresh cycle and keep
// breaking every LoadGeoSite/LoadGeoIP in between.
func shouldDownload(filePath string) bool {
	info, err := os.Stat(filePath)
	if err != nil {
		return true // File does not exist or cannot be accessed
	}
	if time.Since(info.ModTime()) > 24*time.Hour {
		return true
	}
	if info.Size() == 0 {
		return true
	}
	// Reuse the tag scanner as a structural check: a file whose top-level wire
	// stream stops early is truncated or not a rule file at all, either way it
	// is unusable.
	if _, truncated, err := extractGeoFileTags(filePath); err != nil || truncated {
		return true
	}
	return false
}

// DownloadRuleFiles downloads geoip.dat and geosite.dat to the specified directory.
//
// The two files are refreshed independently: a failure on one must not strand
// the other on a stale copy, and both failures are reported.
func DownloadRuleFiles(destDir string) error {
	// Check and create the destination directory (MkdirAll returns nil if it already exists).
	// 0755 permissions: owner has read, write, execute; others have read, execute.
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	var errs []error
	for _, f := range []struct {
		name string
		url  string
	}{
		{name: "geoip.dat", url: GEOIP_URL},
		{name: "geosite.dat", url: GEOSITE_URL},
	} {
		path := filepath.Join(destDir, f.name)
		if !shouldDownload(path) {
			zlog.Debugf("%s is up to date, skipping download.", f.name)
			continue
		}

		zlog.Debugf("Downloading %s...", f.name)
		if err := downloadFile(f.url, path); err != nil {
			zlog.Warnf("%s download failed, previous copy kept: %v", f.name, err)
			errs = append(errs, fmt.Errorf("failed to download %s: %w", f.name, err))
			continue
		}
		zlog.Debugf("%s downloaded and updated successfully!", f.name)
	}

	return errors.Join(errs...)
}

// downloadFile contains the core download logic: download to a temporary file first,
// then overwrite the original file upon success.
//
// The bytes are validated before the rename. jsdelivr (or any middlebox in front
// of it) can answer HTTP 200 and simply stop sending before the file is
// complete, and io.Copy reports that as success. Left unchecked, a truncated
// rule file lands on disk and LoadGeoIP later fails with the misleading
// "no specified tags found" — the reported failure mode was intermittent
// because it depended on how far the transfer got cut off.
func downloadFile(url string, destPath string) error {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP GET request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check the HTTP status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("request failed with status code: %d", resp.StatusCode)
	}

	// Define the temporary file path
	tempPath := destPath + ".tmp"
	zlog.Debugf("Creating temporary file: %s", tempPath)

	// Create the temporary file
	out, err := os.Create(tempPath)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}

	// Use io.Copy to write the response stream to the file.
	// This avoids loading the entire file into memory.
	written, err := io.Copy(out, resp.Body)

	// Flush to stable storage. Best effort: the rename is what makes the new
	// file atomic for readers, the sync only guards against power loss.
	if serr := out.Sync(); serr != nil {
		zlog.Warnf("Failed to flush temporary file %s: %v", tempPath, serr)
	}

	// Ensure the file handle is closed regardless of whether writing succeeded.
	// Note: We cannot rely solely on 'defer out.Close()' here. On Windows,
	// os.Rename will fail if the file handle is still open.
	closeErr := out.Close()

	if err != nil {
		// If an error occurred during writing, remove the incomplete temporary file
		os.Remove(tempPath)
		return fmt.Errorf("failed to write data to temporary file: %w", err)
	}

	// Catch potential I/O flush errors during close
	if closeErr != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to close temporary file safely: %w", closeErr)
	}

	// Short body: the server promised more bytes than it delivered.
	if resp.ContentLength > 0 && written != resp.ContentLength {
		os.Remove(tempPath)
		return fmt.Errorf("received %d of %d bytes from %s; previous copy kept", written, resp.ContentLength, url)
	}

	// Structural check: the top-level wire stream must run to EOF and carry at
	// least one tagged entry. This also rejects a CDN error page served as 200.
	tags, truncated, verr := extractGeoFileTags(tempPath)
	if verr != nil {
		os.Remove(tempPath)
		return fmt.Errorf("downloaded file is not a readable rule file: %w", verr)
	}
	if truncated {
		os.Remove(tempPath)
		return fmt.Errorf("downloaded file is truncated (%d bytes, %d entries before EOF); previous copy kept", written, len(tags))
	}
	if len(tags) == 0 {
		os.Remove(tempPath)
		return fmt.Errorf("downloaded file contains no rule entries; previous copy kept")
	}

	// Download is complete and successful. Rename the temporary file to the target file.
	// This operation automatically overwrites any existing file with the same name.
	zlog.Debugf("Renaming temporary file to target path: %s", destPath)
	if err := os.Rename(tempPath, destPath); err != nil {
		// Clean up the temp file if the rename operation fails
		os.Remove(tempPath)
		return fmt.Errorf("failed to rename temporary file: %w", err)
	}

	return nil
}

type GeoRouter struct {
	queryCount    atomic.Int64 //  info
	cacheHitCount atomic.Int64 //  info

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

func (r *GeoRouter) LoadGeoSite(filepath string, targetTags []string) error {
	f, err := os.Open(filepath)
	if err != nil {
		return err
	}

	defer f.Close() //  info closed， info

	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("failed to read geosite.dat: %w", err)
	}

	tagMap := make(map[string]bool)
	for _, t := range targetTags {
		tagMap[strings.ToLower(t)] = true
	}

	foundCount := 0
	keywordMap := make(map[string]struct{}) //  info  Keyword  info ， info  AC  info

	//  info  protowire  info bytes info
	b := data
	// truncated marks that the top-level wire stream did not reach EOF — the
	// only observable signal of a truncated rule file. Without it a file that
	// was only half written degrades into an empty rule set.
	var truncated bool
	for len(b) > 0 {
		num, typ, length := protowire.ConsumeTag(b)
		if length < 0 {
			truncated = true
			break
		}
		b = b[length:]

		if num == 1 && typ == protowire.BytesType { // GeoSiteList.entry
			entryBytes, n := protowire.ConsumeBytes(b)
			if n < 0 {
				truncated = true
				break
			}
			b = b[n:]

			var countryCode string
			var domains [][]byte
			eb := entryBytes
			for len(eb) > 0 {
				enum, etyp, elen := protowire.ConsumeTag(eb)
				if elen < 0 {
					break
				}
				eb = eb[elen:]

				if enum == 1 && etyp == protowire.BytesType { // GeoSite.country_code
					v, en := protowire.ConsumeBytes(eb)
					if en < 0 {
						break
					}
					countryCode = string(v)
					eb = eb[en:]
				} else if enum == 2 && etyp == protowire.BytesType { // GeoSite.domain
					v, en := protowire.ConsumeBytes(eb)
					if en < 0 {
						break
					}
					domains = append(domains, v)
					eb = eb[en:]
				} else {
					en := protowire.ConsumeFieldValue(enum, etyp, eb)
					if en < 0 {
						break
					}
					eb = eb[en:]
				}
			}

			if tagMap[strings.ToLower(countryCode)] {
				foundCount++
				for _, domBytes := range domains {
					var dType int
					var dValue string
					db := domBytes
					for len(db) > 0 {
						dnum, dtyp, dlen := protowire.ConsumeTag(db)
						if dlen < 0 {
							break
						}
						db = db[dlen:]

						if dnum == 1 && dtyp == protowire.VarintType { // Domain.type
							v, dn := protowire.ConsumeVarint(db)
							if dn < 0 {
								break
							}
							dType = int(v)
							db = db[dn:]
						} else if dnum == 2 && dtyp == protowire.BytesType { // Domain.value
							v, dn := protowire.ConsumeBytes(db)
							if dn < 0 {
								break
							}
							dValue = string(v)
							db = db[dn:]
						} else {
							dn := protowire.ConsumeFieldValue(dnum, dtyp, db)
							if dn < 0 {
								break
							}
							db = db[dn:]
						}
					}

					val := strings.ToLower(dValue)
					switch dType {
					case 0: // Plain
						if _, exists := keywordMap[val]; !exists {
							keywordMap[val] = struct{}{}
							r.keywordList = append(r.keywordList, val)
						}
					case 1: // Regex
						if re, err := regexp.Compile(val); err == nil {
							r.regexList = append(r.regexList, re)
						}
					case 2: // RootDomain
						r.subDomains[val] = struct{}{}
					case 3: // Full
						r.fullDomains[val] = struct{}{}
					}
				}
			}
		} else {
			n := protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				truncated = true
				break
			}
			b = b[n:]
		}
	}

	if truncated {
		zlog.Warnf("%s [Router] ⚠️ geosite.dat is truncated: wire parse stopped after %d of %d bytes (%d matching tag(s) read), so routing is partial — re-download the rule file", TAG, len(data)-len(b), len(data), foundCount)
	}

	if foundCount == 0 && len(targetTags) > 0 {
		if truncated {
			return fmt.Errorf("geosite.dat is truncated (wire parse stopped after %d of %d bytes), so no specified tags could be read: %v", len(data)-len(b), len(data), targetTags)
		}
		return fmt.Errorf("no specified tags found in geosite: %v", targetTags)
	}

	//  info
	r.combineRegexPatterns()

	//  info  Keyword  info  AC  info ， info  O(N)  info
	if len(r.keywordList) > 0 {
		r.keywordAC = ahocorasick.NewStringMatcher(r.keywordList)
	}

	// cleanup：解除大块字节引用，交由 GC 自然回收。
	// 注意：不要在这里调用 debug.FreeOSMemory()——它强制 STW 并向 OS 归还
	// 内存，在 Android 上会造成可见的掉帧，收益却只是推迟下一次分配。
	data = nil
	keywordMap = nil

	zlog.Debugf("%s [Router] GeoSite parsing completed, matched %d rule clusters", TAG, foundCount)
	return nil
}

// combineRegexPatterns  info ， info
func (r *GeoRouter) combineRegexPatterns() {
	if len(r.regexList) == 0 {
		return
	}

	const chunkSize = 100 //  info  100  info ， info  DFA  info
	r.regexGrouped = make([]*regexp.Regexp, 0)

	for i := 0; i < len(r.regexList); i += chunkSize {
		end := i + chunkSize
		if end > len(r.regexList) {
			end = len(r.regexList)
		}

		patterns := make([]string, 0, end-i)
		for _, re := range r.regexList[i:end] {
			patterns = append(patterns, "("+re.String()+")")
		}
		combined := strings.Join(patterns, "|")

		if regex, err := regexp.Compile(combined); err == nil {
			r.regexGrouped = append(r.regexGrouped, regex)
		} else {
			//  info ： info failed， info
			zlog.Warnf("%s [Router] Regex chunk merge exception, degraded to loose storage: %v", TAG, err)
			r.regexGrouped = append(r.regexGrouped, r.regexList[i:end]...)
		}
	}
	zlog.Debugf("%s [Router] %d regular expressions optimized into %d matching groups", TAG, len(r.regexList), len(r.regexGrouped))
}

func (r *GeoRouter) LoadGeoIP(filepath string, targetTags []string) error {
	f, err := os.Open(filepath)
	if err != nil {
		return err
	}

	defer f.Close() //  info closed， info

	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("failed to read geoip.dat: %w", err)
	}

	tagMap := make(map[string]bool)
	for _, t := range targetTags {
		tagMap[strings.ToUpper(t)] = true
	}

	foundCount := 0
	ipInsertCount := 0

	//  info  protowire  info  GeoIP
	b := data
	// truncated marks that the top-level wire stream did not reach EOF — the
	// only observable signal of a truncated rule file. Without it a file that
	// was only half written degrades into an empty rule set.
	var truncated bool
	for len(b) > 0 {
		num, typ, length := protowire.ConsumeTag(b)
		if length < 0 {
			truncated = true
			break
		}
		b = b[length:]

		if num == 1 && typ == protowire.BytesType { // GeoIPList.entry
			entryBytes, n := protowire.ConsumeBytes(b)
			if n < 0 {
				truncated = true
				break
			}
			b = b[n:]

			var countryCode string
			var cidrs [][]byte

			eb := entryBytes
			for len(eb) > 0 {
				enum, etyp, elen := protowire.ConsumeTag(eb)
				if elen < 0 {
					break
				}
				eb = eb[elen:]

				if enum == 1 && etyp == protowire.BytesType { // GeoIP.country_code
					v, en := protowire.ConsumeBytes(eb)
					if en < 0 {
						break
					}
					countryCode = string(v)
					eb = eb[en:]
				} else if enum == 2 && etyp == protowire.BytesType { // GeoIP.cidr
					v, en := protowire.ConsumeBytes(eb)
					if en < 0 {
						break
					}
					cidrs = append(cidrs, v)
					eb = eb[en:]
				} else {
					en := protowire.ConsumeFieldValue(enum, etyp, eb)
					if en < 0 {
						break
					}
					eb = eb[en:]
				}
			}

			if tagMap[strings.ToUpper(countryCode)] {
				foundCount++
				for _, cidrBytes := range cidrs {
					var ip []byte
					var prefix uint32

					cb := cidrBytes
					for len(cb) > 0 {
						cnum, ctyp, clen := protowire.ConsumeTag(cb)
						if clen < 0 {
							break
						}
						cb = cb[clen:]

						if cnum == 1 && ctyp == protowire.BytesType { // CIDR.ip
							v, cn := protowire.ConsumeBytes(cb)
							if cn < 0 {
								break
							}
							ip = v
							cb = cb[cn:]
						} else if cnum == 2 && ctyp == protowire.VarintType { // CIDR.prefix
							v, cn := protowire.ConsumeVarint(cb)
							if cn < 0 {
								break
							}
							prefix = uint32(v)
							cb = cb[cn:]
						} else {
							cn := protowire.ConsumeFieldValue(cnum, ctyp, cb)
							if cn < 0 {
								break
							}
							cb = cb[cn:]
						}
					}

					if len(ip) == 4 || len(ip) == 16 {
						r.ipTrie.Insert(ip, int(prefix))
						ipInsertCount++
					}
				}
			}
		} else {
			n := protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				truncated = true
				break
			}
			b = b[n:]
		}
	}

	if truncated {
		zlog.Warnf("%s [Router] ⚠️ geoip.dat is truncated: wire parse stopped after %d of %d bytes (%d matching tag(s) read), so routing is partial — re-download the rule file", TAG, len(data)-len(b), len(data), foundCount)
	}

	if foundCount == 0 && len(targetTags) > 0 {
		if truncated {
			return fmt.Errorf("geoip.dat is truncated (wire parse stopped after %d of %d bytes), so no specified tags could be read: %v", len(data)-len(b), len(data), targetTags)
		}
		return fmt.Errorf("no specified tags found in geoip: %v", targetTags)
	}

	// cleanup：解除大块字节引用，交由 GC 自然回收（理由同 LoadGeoSite）。
	data = nil

	zlog.Debugf("%s [Router] GeoIP parsing completed, loaded %d CIDR subnets into Radix tree", TAG, ipInsertCount)
	return nil
}

type RouteResult struct {
	IsDirect bool   `json:"is_direct"`
	DialHost string `json:"dial_host"`
}

// routeIPCacheTTL  info 。 info  GeoIP  info  DNS  info ，
//
//	info （ info “ info ” info ） info  TTL  info ， info  SOCKS5  info 。
const routeIPCacheTTL = 5 * time.Minute

// routeResolved  info  IP  info 。
type routeResolved struct {
	ips    []net.IP
	expire time.Time
}

// ShouldDirect  info target host  info 。
//
//	info  GeoSite  info 、 info  IP  info  GeoIP  info  IsDirect=true，
//
// DialHost  info （ info  IP）； info 。
func (r *GeoRouter) ShouldDirect(host string) RouteResult {
	if host == "" {
		return RouteResult{IsDirect: false, DialHost: ""}
	}

	//  info  Go 1.18+  info  netip  info ， info  net.ParseIP
	if addr, err := netip.ParseAddr(host); err == nil {
		if r.MatchNetIP(addr) {
			zlog.Debugf("%s [Router] Direct IP access [%s] -> Hit GeoIP, routing direct", TAG, host)
			return RouteResult{IsDirect: true, DialHost: host}
		}
		zlog.Debugf("%s [Router] Direct IP access [%s] -> Missed GeoIP, routing proxy", TAG, host)
		return RouteResult{IsDirect: false, DialHost: host}
	}

	//  info  GeoSite ( info )  info
	if r.MatchDomain(host) {
		ips := GetCachedIPs(host)
		if len(ips) > 0 {
			zlog.Debugf("%s [Router] Domain [%s] hit GeoSite -> Using cached IP (%s) for direct routing", TAG, host, ips[0].String())
			return RouteResult{IsDirect: true, DialHost: ips[0].String()}
		}
		zlog.Debugf("%s [Router] Domain [%s] hit GeoSite -> No cached IP, keeping domain for direct routing", TAG, host)
		return RouteResult{IsDirect: true, DialHost: host}
	}

	//  info  GeoIP (IP  info )
	ips := GetCachedIPs(host)
	if len(ips) == 0 {
		//  info ， info  DNS  info （ info  SOCKS5  info ）
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
			//  info （ info  TTL）； info ， info
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

	//  info  ( info )
	zlog.Debugf("%s [Router] Domain [%s] missed all direct rules -> routing proxy", TAG, host)
	return RouteResult{IsDirect: false, DialHost: host}
}

// MatchDomain  info  -  info
func (r *GeoRouter) MatchDomain(domain string) bool {
	domain = strings.ToLower(domain)

	//  info  L1  info  (O(1)  info )
	//  info  App /  info ， info ， info 。
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

// ResetCacheAndStats  info  L1  info
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

// getStats  info ：( info ,  info )， info  gomobile  info
func (r *GeoRouter) getStats() (int64, int64) {
	return r.queryCount.Load(), r.cacheHitCount.Load()
}

func (r *GeoRouter) doMatchDomain(domain string) bool {

	// Full  info
	if _, ok := r.fullDomains[domain]; ok {
		return true
	}

	// Domain  info  ( info ： info )
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

	// Keyword  info  ( info  AC  info  O(1)  info )
	if r.keywordAC != nil {
		// Match  info mode info ， info  0  info
		// 串行调用以规避 Match 的非并发安全实现；只发生在 L1 缓存未命中时。
		r.keywordMu.Lock()
		hits := r.keywordAC.Match([]byte(domain))
		r.keywordMu.Unlock()
		if len(hits) > 0 {
			return true
		}
	} else {
		//  info
		for _, kw := range r.keywordList {
			if strings.Contains(domain, kw) {
				return true
			}
		}
	}

	//  info  ( info )
	if len(r.regexGrouped) > 0 {
		for _, re := range r.regexGrouped {
			if re.MatchString(domain) {
				return true
			}
		}
	} else {
		//  info  ( info  combine  info )
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

// MatchNetIP  info  IP  info
func (r *GeoRouter) MatchNetIP(addr netip.Addr) bool {
	if addr.Is4() {
		// addr.As4()  info  [4]byte，[:]  info ， info
		a4 := addr.As4()
		return r.ipTrie.ContainsBytes(a4[:], true)
	}
	a16 := addr.As16()
	return r.ipTrie.ContainsBytes(a16[:], false)
}

// ==========================================
//  info  IP  info  (CIDR Trie)
// ==========================================

type ipTrieNode struct {
	left  *ipTrieNode // 0  info
	right *ipTrieNode // 1  info
	isEnd bool        //  info  CIDR  info
}

type ipTrie struct {
	v4Root *ipTrieNode
	v6Root *ipTrieNode
}

func newIPTrie() *ipTrie {
	return &ipTrie{
		v4Root: &ipTrieNode{},
		v6Root: &ipTrieNode{},
	}
}

func (t *ipTrie) Insert(ipBytes []byte, prefixLen int) {
	var node *ipTrieNode
	if len(ipBytes) == 4 {
		node = t.v4Root
	} else if len(ipBytes) == 16 {
		node = t.v6Root
	} else {
		return
	}

	for i := 0; i < prefixLen; i++ {
		bit := (ipBytes[i/8] >> (7 - (i % 8))) & 1
		if bit == 0 {
			if node.left == nil {
				node.left = &ipTrieNode{}
			}
			node = node.left
		} else {
			if node.right == nil {
				node.right = &ipTrieNode{}
			}
			node = node.right
		}
	}
	node.isEnd = true
}

func (t *ipTrie) Contains(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return t.ContainsBytes(ip4, true)
	}
	return t.ContainsBytes(ip.To16(), false)
}

// ContainsBytes  info 、 info
func (t *ipTrie) ContainsBytes(ipBytes []byte, isV4 bool) bool {
	var node *ipTrieNode
	if isV4 {
		node = t.v4Root
	} else {
		node = t.v6Root
	}

	for i := 0; i < len(ipBytes)*8; i++ {
		if node == nil {
			return false
		}
		if node.isEnd {
			return true //  info  ( info  10.0.0.0/8 successfully)
		}
		bit := (ipBytes[i/8] >> (7 - (i % 8))) & 1
		if bit == 0 {
			node = node.left
		} else {
			node = node.right
		}
	}
	return node != nil && node.isEnd
}
