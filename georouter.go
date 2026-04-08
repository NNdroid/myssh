package myssh

import (
	"fmt"
	"io/ioutil"
	"net"
	"regexp"
	"strings"

	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"github.com/yl2chen/cidranger"
	"google.golang.org/protobuf/proto"
)

// ---------------------------------------------------------
// GeoRouter 核心结构
// ---------------------------------------------------------

type GeoRouter struct {
	// 域名匹配器
	fullDomains   map[string]struct{} // 精确匹配 (Full)
	subDomains    map[string]struct{} // 后缀/子域名匹配 (Domain)
	keywordList   []string            // 关键字匹配 (Keyword)
	regexList     []*regexp.Regexp    // 正则匹配 (Regex)

	// IP CIDR 匹配器 (使用 cidranger 提供 O(1) 高效检索)
	ipRanger cidranger.Ranger
}

// newGeoRouter 创建一个新的空路由管理器
func newGeoRouter() *GeoRouter {
	return &GeoRouter{
		fullDomains: make(map[string]struct{}),
		subDomains:  make(map[string]struct{}),
		keywordList: make([]string, 0),
		regexList:   make([]*regexp.Regexp, 0),
		ipRanger:    cidranger.NewPCTrieRanger(),
	}
}

// ---------------------------------------------------------
// 加载数据解析器
// ---------------------------------------------------------

// LoadGeoSite 解析 geosite.dat 并加载指定 tags 数组的规则 (如 []string{"cn", "google"})
func (r *GeoRouter) LoadGeoSite(filepath string, targetTags []string) error {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("读取 geosite.dat 失败: %w", err)
	}

	var geoSiteList routercommon.GeoSiteList
	if err := proto.Unmarshal(data, &geoSiteList); err != nil {
		return fmt.Errorf("解析 protobuf 失败: %w", err)
	}

	// 建立一个 map 提升查找效率，并统一转为小写
	tagMap := make(map[string]bool)
	for _, t := range targetTags {
		tagMap[strings.ToLower(t)] = true
	}

	foundCount := 0

	for _, site := range geoSiteList.Entry {
		if tagMap[strings.ToLower(site.CountryCode)] {
			foundCount++
			for _, domain := range site.Domain {
				val := strings.ToLower(domain.Value)
				switch domain.Type {
				case routercommon.Domain_Plain:
					r.keywordList = append(r.keywordList, val)
				case routercommon.Domain_Regex:
					if re, err := regexp.Compile(val); err == nil {
						r.regexList = append(r.regexList, re)
					}
				case routercommon.Domain_RootDomain:
					r.subDomains[val] = struct{}{}
				case routercommon.Domain_Full:
					r.fullDomains[val] = struct{}{}
				}
			}
		}
	}

	if foundCount == 0 && len(targetTags) > 0 {
		return fmt.Errorf("未在 geosite 中找到任何指定的标签: %v", targetTags)
	}
	
	// 🌟 增加一条底层的 Debug 日志，记录实际加载了多少条规则簇
	zlog.Debugf("%s [Router] GeoSite 解析完毕，匹配到 %d 个规则簇", TAG, foundCount)
	return nil
}

// LoadGeoIP 解析 geoip.dat 并加载指定 tags 数组的 CIDR 规则
func (r *GeoRouter) LoadGeoIP(filepath string, targetTags []string) error {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("读取 geoip.dat 失败: %w", err)
	}

	var geoIPList routercommon.GeoIPList
	if err := proto.Unmarshal(data, &geoIPList); err != nil {
		return fmt.Errorf("解析 protobuf 失败: %w", err)
	}

	tagMap := make(map[string]bool)
	for _, t := range targetTags {
		tagMap[strings.ToUpper(t)] = true
	}

	foundCount := 0
	ipInsertCount := 0

	for _, ipGroup := range geoIPList.Entry {
		if tagMap[strings.ToUpper(ipGroup.CountryCode)] {
			foundCount++
			for _, cidr := range ipGroup.Cidr {
				ip := cidr.Ip
				prefix := cidr.Prefix

				var ipNet *net.IPNet
				if len(ip) == 4 { // IPv4
					ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(int(prefix), 32)}
				} else if len(ip) == 16 { // IPv6
					ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(int(prefix), 128)}
				} else {
					continue 
				}

				_ = r.ipRanger.Insert(cidranger.NewBasicRangerEntry(*ipNet))
				ipInsertCount++
			}
		}
	}

	if foundCount == 0 && len(targetTags) > 0 {
		return fmt.Errorf("未在 geoip 中找到任何指定的标签: %v", targetTags)
	}
	
	// 🌟 增加底层的 Debug 日志
	zlog.Debugf("%s [Router] GeoIP 解析完毕，共将 %d 条 CIDR 网段载入 Radix 树", TAG, ipInsertCount)
	return nil
}

// ---------------------------------------------------------
// 高效分流匹配逻辑
// ---------------------------------------------------------

type RouteResult struct {
	IsDirect bool   `json:"is_direct"`
	DialHost string `json:"dial_host"`
}

// ShouldDirect 综合判断请求的 host 是否应该走直连，并返回路由决策对象
func (r *GeoRouter) ShouldDirect(host string) RouteResult {
	if host == "" {
		return RouteResult{IsDirect: false, DialHost: ""}
	}

	ip := net.ParseIP(host)
	if ip != nil {
		// 原生就是 IP，直接匹配并返回它自己
		if r.MatchIP(ip) {
			zlog.Debugf("%s [Router] 直接 IP 访问 [%s] -> 命中 GeoIP，走直连", TAG, host)
			return RouteResult{IsDirect: true, DialHost: host}
		}
		zlog.Debugf("%s [Router] 直接 IP 访问 [%s] -> 未命中 GeoIP，走代理", TAG, host)
		return RouteResult{IsDirect: false, DialHost: host}
	}

	// ==========================
	// 1. 走 GeoSite (域名规则) 匹配
	// ==========================
	if r.MatchDomain(host) {
		ips := GetCachedIPs(host)
		if len(ips) > 0 {
			zlog.Debugf("%s [Router] 域名 [%s] 命中 GeoSite -> 使用缓存 IP (%s) 走直连", TAG, host, ips[0].String())
			return RouteResult{IsDirect: true, DialHost: ips[0].String()}
		}
		zlog.Debugf("%s [Router] 域名 [%s] 命中 GeoSite -> 无缓存 IP，保留域名走直连", TAG, host)
		return RouteResult{IsDirect: true, DialHost: host}
	}

	// ==========================
	// 2. 查 GeoIP (IP 规则)
	// ==========================
	ips := GetCachedIPs(host)
	if len(ips) == 0 {
		localIPs, err := net.LookupIP(host)
		if err == nil {
			ips = localIPs
		}
	}

	for _, resolvedIP := range ips {
		if r.MatchIP(resolvedIP) {
			zlog.Debugf("%s [Router] 域名 [%s] 解析的 IP (%s) 命中 GeoIP -> 走直连", TAG, host, resolvedIP.String())
			return RouteResult{IsDirect: true, DialHost: resolvedIP.String()}
		}
	}

	// ==========================
	// 3. 走代理 (未命中直连规则)
	// ==========================
	zlog.Debugf("%s [Router] 域名 [%s] 未命中任何直连规则 -> 走代理", TAG, host)
	return RouteResult{IsDirect: false, DialHost: host}
}

// MatchDomain 检查域名是否命中规则 (包含精确匹配和后缀层级匹配)
func (r *GeoRouter) MatchDomain(domain string) bool {
	domain = strings.ToLower(domain)

	// 1. Full 检查
	if _, ok := r.fullDomains[domain]; ok {
		return true
	}

	// 2. Domain 检查
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts); i++ {
		sub := strings.Join(parts[i:], ".")
		if _, ok := r.subDomains[sub]; ok {
			return true
		}
	}

	// 3. Keyword 检查
	for _, kw := range r.keywordList {
		if strings.Contains(domain, kw) {
			return true
		}
	}

	// 4. Regex 检查
	for _, re := range r.regexList {
		if re.MatchString(domain) {
			return true
		}
	}

	return false
}

// MatchIP 使用 Radix Tree (基数树) 以 O(1) 时间复杂度检查 IP 是否在 CIDR 网段内
func (r *GeoRouter) MatchIP(ip net.IP) bool {
	contains, err := r.ipRanger.Contains(ip)
	if err != nil {
		return false
	}
	return contains
}