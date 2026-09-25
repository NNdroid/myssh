package myssh

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/cloudflare/ahocorasick"
	"google.golang.org/protobuf/encoding/protowire"
)

// 本文件实现 geosite.dat / geoip.dat 的零拷贝 protowire 解析：
// 只提取目标 tag 的条目，填充 GeoRouter 的域名/关键词/正则/IP 规则集。

func (r *GeoRouter) LoadGeoSite(filepath string, targetTags []string) error {
	f, err := os.Open(filepath)
	if err != nil {
		return err
	}

	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("failed to read geosite.dat: %w", err)
	}

	tagMap := make(map[string]bool)
	for _, t := range targetTags {
		tagMap[strings.ToLower(t)] = true
	}

	foundCount := 0
	keywordMap := make(map[string]struct{}) // Keyword 去重集合，交给 AC 匹配

	// 顶层 protowire 流式解析 bytes 字段
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

	// 合并正则
	r.combineRegexPatterns()

	// 构建 Keyword 的 AC 自动机，提升 O(N) 匹配
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

// combineRegexPatterns 把正则列表按块合并，减少 DFA 状态数
func (r *GeoRouter) combineRegexPatterns() {
	if len(r.regexList) == 0 {
		return
	}

	const chunkSize = 100 // 每组合并 100 条，限制 DFA 规模
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
			// 兜底：合并 failed，退回独立正则
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

	defer f.Close()

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

	// 顶层 protowire 流式解析 GeoIP
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
