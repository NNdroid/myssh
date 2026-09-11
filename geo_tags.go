package myssh

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// ==========================================
// GeoSite / GeoIP tag 列表查询（Android API）
//
// 两个文件顶层结构相同：repeated entry（field 1），entry 的 field 1
// 是 tag（country_code / category）。扫描器只走顶层与 entry 的 field 1，
// 对 domains/cidrs 等大字段仅做长度跳过——全程零拷贝指针推进，不做任何
// protobuf 反射或字符串解析，这是纯 Go 下最快的读取方式。
//
// 性能特征：首次调用 ≈ 一次文件读取（几十 MB 文件约几十毫秒）；之后命中
// 缓存为 O(1)。缓存以 (size, mtime) 失效，规则文件更新（DownloadRuleFiles
// 每日刷新）后下一次调用自动重扫。
// ==========================================

type geoTagsCacheEntry struct {
	tags      []string
	size      int64
	modTime   time.Time
	truncated bool // 顶层 wire 解析未走到 EOF：文件可能不完整或含未知结构
}

var (
	geoTagsMu    sync.Mutex
	geoTagsCache = make(map[string]geoTagsCacheEntry) // key: 文件绝对路径
)

// GetGeoSiteTagsJSON 返回当前生效 geosite 文件中的全部 tag（去重、升序），
// JSON 数组字符串，例如 ["cn","geolocation-!cn","private"]。文件未配置或
// 读取失败时返回 "[]"。结果带缓存，适合每次进入选择界面时调用。
func GetGeoSiteTagsJSON() string {
	path := globalConfig.Load().GeoSiteFilePath
	if strings.TrimSpace(path) == "" {
		path = "geosite.dat"
	}
	return getGeoTagsJSON(path)
}

// GetGeoIPTagsJSON 返回当前生效 geoip 文件中的全部 tag（去重、升序），
// JSON 数组字符串，例如 ["cn","private","cloudflare"]。语义与缓存策略同上。
func GetGeoIPTagsJSON() string {
	path := globalConfig.Load().GeoIPFilePath
	if strings.TrimSpace(path) == "" {
		path = "geoip.dat"
	}
	return getGeoTagsJSON(path)
}

func getGeoTagsJSON(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}

	info, err := os.Stat(abs)
	if err != nil {
		zlog.Warnf("%s [GeoTags] ⚠️ Rule file not found (%s): %v", TAG, abs, err)
		return "[]"
	}

	geoTagsMu.Lock()
	if e, ok := geoTagsCache[abs]; ok && e.size == info.Size() && e.modTime.Equal(info.ModTime()) {
		tags := e.tags
		geoTagsMu.Unlock()
		return marshalGeoTags(tags)
	}
	geoTagsMu.Unlock()

	tags, truncated, err := extractGeoFileTags(abs)
	if err != nil {
		zlog.Warnf("%s [GeoTags] ⚠️ Failed to scan rule file (%s): %v", TAG, abs, err)
		return "[]"
	}
	if truncated {
		// 44 个 tag 却对应 17MB 文件这类现象的根因：解析没走到 EOF。
		zlog.Warnf("%s [GeoTags] ⚠️ Rule file scan ended before EOF (%s, %d bytes): file is likely truncated or malformed; tag list may be partial", TAG, abs, info.Size())
	}

	geoTagsMu.Lock()
	geoTagsCache[abs] = geoTagsCacheEntry{tags: tags, size: info.Size(), modTime: info.ModTime(), truncated: truncated}
	geoTagsMu.Unlock()

	return marshalGeoTags(tags)
}

// GetGeoFileInfoJSON 返回 GetGeoSiteTagsJSON/GetGeoIPTagsJSON 实际扫描的
// 诊断信息，用于在设备上核对"扫的是哪个文件、完不完整"：
//
//	{"site_path":"...","site_size":17305577,"site_truncated":false,"site_tags":260,
//	 "ip_path":"...","ip_size":17058810,"ip_truncated":false,"ip_tags":260}
//
// ip_truncated/site_truncated 为 true 时 tag 列表只是文件的部分内容——
// 通常是规则文件下载不完整（截断）或格式损坏，重新下载即可。
func GetGeoFileInfoJSON() string {
	sitePath := globalConfig.Load().GeoSiteFilePath
	if strings.TrimSpace(sitePath) == "" {
		sitePath = "geosite.dat"
	}
	ipPath := globalConfig.Load().GeoIPFilePath
	if strings.TrimSpace(ipPath) == "" {
		ipPath = "geoip.dat"
	}

	out := struct {
		SitePath      string `json:"site_path"`
		SiteSize      int64  `json:"site_size"`
		SiteTruncated bool   `json:"site_truncated"`
		SiteTags      int    `json:"site_tags"`
		IpPath        string `json:"ip_path"`
		IpSize        int64  `json:"ip_size"`
		IpTruncated   bool   `json:"ip_truncated"`
		IpTags        int    `json:"ip_tags"`
	}{SitePath: sitePath, IpPath: ipPath}

	siteInfo := scanGeoTagsForInfo(sitePath, &out.SiteTruncated, &out.SiteTags)
	out.SiteSize = siteInfo
	ipInfo := scanGeoTagsForInfo(ipPath, &out.IpTruncated, &out.IpTags)
	out.IpSize = ipInfo

	data, err := json.Marshal(out)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func scanGeoTagsForInfo(path string, truncated *bool, count *int) int64 {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	info, err := os.Stat(abs)
	if err != nil {
		*truncated = false
		*count = -1 // 文件不存在
		return -1
	}
	geoTagsMu.Lock()
	e, ok := geoTagsCache[abs]
	geoTagsMu.Unlock()
	if ok && e.size == info.Size() && e.modTime.Equal(info.ModTime()) {
		*truncated = e.truncated
		*count = len(e.tags)
		return info.Size()
	}
	tags, tr, err := extractGeoFileTags(abs)
	if err != nil {
		*truncated = false
		*count = -1
		return -1
	}
	geoTagsMu.Lock()
	geoTagsCache[abs] = geoTagsCacheEntry{tags: tags, size: info.Size(), modTime: info.ModTime(), truncated: tr}
	geoTagsMu.Unlock()
	*truncated = tr
	*count = len(tags)
	return info.Size()
}

// extractGeoFileTags 扫描规则文件顶层的全部 entry tag。wire 格式与
// LoadGeoSite/LoadGeoIP 的宽松解析风格一致：结构异常时停止并返回已收集
// 部分。truncated 为 true 表示解析没有走到文件末尾——文件很可能下载不完整
// （截断的最后一个 record）或包含未知结构，tag 列表只是其中一部分。
func extractGeoFileTags(path string) (tags []string, truncated bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}

	seen := make(map[string]struct{})
	b := data
	for len(b) > 0 {
		num, typ, length := protowire.ConsumeTag(b)
		if length < 0 {
			return collectGeoTags(seen), true, nil
		}
		b = b[length:]

		if num == 1 && typ == protowire.BytesType { // GeoSiteList/GeoIPList.entry
			entryBytes, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return collectGeoTags(seen), true, nil
			}
			b = b[n:]

			eb := entryBytes
			for len(eb) > 0 {
				enum, etyp, elen := protowire.ConsumeTag(eb)
				if elen < 0 {
					break // 仅放弃该 entry，不影响整体扫描
				}
				eb = eb[elen:]

				if enum == 1 && etyp == protowire.BytesType { // entry.country_code
					v, en := protowire.ConsumeBytes(eb)
					if en < 0 {
						break
					}
					eb = eb[en:]
					if tag := string(v); tag != "" {
						seen[tag] = struct{}{}
					}
				} else { // domains/cidrs 等：仅跳过长度，不下钻
					en := protowire.ConsumeFieldValue(enum, etyp, eb)
					if en < 0 {
						break
					}
					eb = eb[en:]
				}
			}
		} else {
			n := protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return collectGeoTags(seen), true, nil
			}
			b = b[n:]
		}
	}

	return collectGeoTags(seen), false, nil
}

func collectGeoTags(seen map[string]struct{}) []string {
	tags := make([]string, 0, len(seen))
	for t := range seen {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	return tags
}

func marshalGeoTags(tags []string) string {
	if len(tags) == 0 {
		return "[]"
	}
	data, err := json.Marshal(tags)
	if err != nil {
		return "[]"
	}
	return string(data)
}
