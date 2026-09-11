package myssh

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ==========================================
// Magic 校验 API（Android / gomobile）
//
// udp_custom 与 icmp_custom 的记录魔数规则不同（udp 允许 4 字节原文，
// icmp 只接受 hex），但都支持 0x/0X 前缀的十六进制输入。本 API 把
// "这个值合不合法、最终是多少" 归一成一个 JSON 结果，宿主在保存节点前
// 即可调用校验并回显归一化值。
// ==========================================

type magicCheckResult struct {
	Valid      bool   `json:"valid"`
	Tunnel     string `json:"tunnel"`
	Input      string `json:"input"`
	Magic      uint32 `json:"magic"`
	Normalized string `json:"normalized"`
	UseDefault bool   `json:"use_default"` // 输入为空：SDK 将采用各自默认魔数
	Error      string `json:"error,omitempty"`
}

// CheckMagicJSON 校验 magic 值是否符合对应隧道协议的要求，JSON 返回：
//
//	{"valid":true,"tunnel":"udp_custom","input":"UDPC","magic":1430669379,
//	 "normalized":"0x55445043","use_default":false}
//
// tunnel 取 "udp_custom"（4 字节原文，如 "UDPC"，或 0x 前缀 hex）或
// "icmp_custom"（8 位 hex，或 0x 前缀 hex；刻意拒绝 ASCII 词——魔数明文
// 传输，可打印串会成为中间设备指纹）。空输入合法且 use_default=true。
// 其他 tunnel 值返回 valid=false。
func CheckMagicJSON(tunnel, magic string) string {
	res := magicCheckResult{Tunnel: strings.ToLower(strings.TrimSpace(tunnel)), Input: magic}

	var err error
	switch res.Tunnel {
	case "udp_custom":
		res.Magic, err = parseUDPCMagicSDK(magic)
	case "icmp_custom":
		res.Magic, err = parseICMPMagicSDK(magic)
	default:
		err = fmt.Errorf("unsupported tunnel %q (want udp_custom or icmp_custom)", tunnel)
	}

	if err != nil {
		res.Error = err.Error()
		data, merr := json.Marshal(res)
		if merr != nil {
			return `{"valid":false,"error":"marshal failed"}`
		}
		return string(data)
	}

	res.Valid = true
	// use_default 表示"用户留空、由 SDK 取默认魔数"，按输入判定而非结果值——
	// 显式输入恰好等于默认值（如 udp 的 "UDPC"）不应被标记。
	res.UseDefault = strings.TrimSpace(magic) == ""
	res.Normalized = fmt.Sprintf("0x%08X", res.Magic)
	data, merr := json.Marshal(res)
	if merr != nil {
		return `{"valid":false,"error":"marshal failed"}`
	}
	return string(data)
}
