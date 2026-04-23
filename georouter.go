package myssh

import (
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"github.com/yl2chen/cidranger"
	"google.golang.org/protobuf/proto"
)

type GeoRouter struct {
	fullDomains   map[string]struct{}
	subDomains    map[string]struct{}
	keywordList   []string
	regexList     []*regexp.Regexp
	regexCombined *regexp.Regexp // 合并后的正则表达式

	ipRanger cidranger.Ranger
}

func newGeoRouter() *GeoRouter {
	return &GeoRouter{
		fullDomains: make(map[string]struct{}),
		subDomains:  make(map[string]struct{}),
		keywordList: make([]string, 0),
		regexList:   make([]*regexp.Regexp, 0),
		ipRanger:    cidranger.NewPCTrieRanger(),
	}
}

func (r *GeoRouter) LoadGeoSite(filepath string, targetTags []string) error {
	f, err := os.Open(filepath)
	if err != nil {
		return err
	}

	defer f.Close() // 确保句柄及时关闭，断开系统级的映射关系

	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("读取 geosite.dat 失败: %w", err)
	}

	var geoSiteList routercommon.GeoSiteList
	if err := proto.Unmarshal(data, &geoSiteList); err != nil {
		return fmt.Errorf("解析 protobuf 失败: %w", err)
	}

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

	// 合并正则表达式以提升性能
	r.combineRegexPatterns()

	// 清理动作
	data = nil                               // 释放原始字节流引用
	geoSiteList = routercommon.GeoSiteList{} // 释放解析后的临时大结构体引用

	// 强制触发 GC 并尝试将物理内存还给 Android 系统
	runtime.GC()
	debug.FreeOSMemory()

	zlog.Debugf("%s [Router] GeoSite 解析完毕，匹配到 %d 个规则簇", TAG, foundCount)
	return nil
}

// combineRegexPatterns 合并所有正则表达式为一个，提升匹配性能
func (r *GeoRouter) combineRegexPatterns() {
	if len(r.regexList) == 0 {
		return
	}

	patterns := make([]string, len(r.regexList))
	for i, re := range r.regexList {
		patterns[i] = "(" + re.String() + ")"
	}
	combined := strings.Join(patterns, "|")

	if regex, err := regexp.Compile(combined); err == nil {
		r.regexCombined = regex
		zlog.Debugf("%s [Router] 已合并 %d 个正则表达式为单一模式", TAG, len(r.regexList))
	}
}

func (r *GeoRouter) LoadGeoIP(filepath string, targetTags []string) error {
	f, err := os.Open(filepath)
	if err != nil {
		return err
	}

	defer f.Close() // 确保句柄及时关闭，断开系统级的映射关系

	data, err := io.ReadAll(f)
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

	// 清理动作
	data = nil                           // 释放原始字节流引用
	geoIPList = routercommon.GeoIPList{} // 释放解析后的临时大结构体引用

	// 强制触发 GC 并尝试将物理内存还给 Android 系统
	runtime.GC()
	debug.FreeOSMemory()

	zlog.Debugf("%s [Router] GeoIP 解析完毕，共将 %d 条 CIDR 网段载入 Radix 树", TAG, ipInsertCount)
	return nil
}

type RouteResult struct {
	IsDirect bool   `json:"is_direct"`
	DialHost string `json:"dial_host"`
}

func (r *GeoRouter) ShouldDirect(host string) RouteResult {
	if host == "" {
		return RouteResult{IsDirect: false, DialHost: ""}
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if r.MatchIP(ip) {
			if Debug {
				zlog.Debugf("%s [Router] 直接 IP 访问 [%s] -> 命中 GeoIP，走直连", TAG, host)
			}
			return RouteResult{IsDirect: true, DialHost: host}
		}
		if Debug {
			zlog.Debugf("%s [Router] 直接 IP 访问 [%s] -> 未命中 GeoIP，走代理", TAG, host)
		}
		return RouteResult{IsDirect: false, DialHost: host}
	}

	// 走 GeoSite (域名规则) 匹配
	if r.MatchDomain(host) {
		ips := GetCachedIPs(host)
		if len(ips) > 0 {
			if Debug {
				zlog.Debugf("%s [Router] 域名 [%s] 命中 GeoSite -> 使用缓存 IP (%s) 走直连", TAG, host, ips[0].String())
			}
			return RouteResult{IsDirect: true, DialHost: ips[0].String()}
		}
		if Debug {
			zlog.Debugf("%s [Router] 域名 [%s] 命中 GeoSite -> 无缓存 IP，保留域名走直连", TAG, host)
		}
		return RouteResult{IsDirect: true, DialHost: host}
	}

	// 查 GeoIP (IP 规则)
	ips := GetCachedIPs(host)
	if len(ips) == 0 {
		localIPs, err := net.LookupIP(host)
		if err == nil {
			ips = localIPs
		}
	}

	for _, resolvedIP := range ips {
		if r.MatchIP(resolvedIP) {
			if Debug {
				zlog.Debugf("%s [Router] 域名 [%s] 解析的 IP (%s) 命中 GeoIP -> 走直连", TAG, host, resolvedIP.String())
			}
			return RouteResult{IsDirect: true, DialHost: resolvedIP.String()}
		}
	}

	// 走代理 (未命中直连规则)
	if Debug {
		zlog.Debugf("%s [Router] 域名 [%s] 未命中任何直连规则 -> 走代理", TAG, host)
	}
	return RouteResult{IsDirect: false, DialHost: host}
}

// MatchDomain 检查域名是否命中规则 - 优化版本
func (r *GeoRouter) MatchDomain(domain string) bool {
	domain = strings.ToLower(domain)

	// Full 检查
	if _, ok := r.fullDomains[domain]; ok {
		return true
	}

	// Domain 检查
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts); i++ {
		sub := strings.Join(parts[i:], ".")
		if _, ok := r.subDomains[sub]; ok {
			return true
		}
	}

	// Keyword 检查 - 按长度倒序优化匹配速度
	for _, kw := range r.keywordList {
		if strings.Contains(domain, kw) {
			return true
		}
	}

	// 合并的正则表达式
	if r.regexCombined != nil && r.regexCombined.MatchString(domain) {
		return true
	}

	return false
}

func (r *GeoRouter) MatchIP(ip net.IP) bool {
	contains, err := r.ipRanger.Contains(ip)
	if err != nil {
		return false
	}
	return contains
}
