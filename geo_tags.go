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
	tags    []string
	size    int64
	modTime time.Time
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

	tags, err := extractGeoFileTags(abs)
	if err != nil {
		zlog.Warnf("%s [GeoTags] ⚠️ Failed to scan rule file (%s): %v", TAG, abs, err)
		return "[]"
	}

	geoTagsMu.Lock()
	geoTagsCache[abs] = geoTagsCacheEntry{tags: tags, size: info.Size(), modTime: info.ModTime()}
	geoTagsMu.Unlock()

	return marshalGeoTags(tags)
}

// extractGeoFileTags 扫描规则文件顶层的全部 entry tag。wire 格式与
// LoadGeoSite/LoadGeoIP 的宽松解析风格一致：结构异常时停止并返回已收集部分。
func extractGeoFileTags(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	b := data
	for len(b) > 0 {
		num, typ, length := protowire.ConsumeTag(b)
		if length < 0 {
			break
		}
		b = b[length:]

		if num == 1 && typ == protowire.BytesType { // GeoSiteList/GeoIPList.entry
			entryBytes, n := protowire.ConsumeBytes(b)
			if n < 0 {
				break
			}
			b = b[n:]

			eb := entryBytes
			for len(eb) > 0 {
				enum, etyp, elen := protowire.ConsumeTag(eb)
				if elen < 0 {
					break
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
				break
			}
			b = b[n:]
		}
	}

	tags := make([]string, 0, len(seen))
	for t := range seen {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	return tags, nil
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
