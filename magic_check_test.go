package myssh

import (
	"encoding/json"
	"testing"
)

func TestParseUDPCMagicSDKHexPrefix(t *testing.T) {
	// 0x 前缀：与 4 字节原文 "UDPC" 等价
	got, err := parseUDPCMagicSDK("0x55445043")
	if err != nil || got != 0x55445043 {
		t.Fatalf("0x55445043: got=%08x err=%v", got, err)
	}
	// 大写 0X 前缀
	if got, err = parseUDPCMagicSDK("0X55445043"); err != nil || got != 0x55445043 {
		t.Fatalf("0X55445043: got=%08x err=%v", got, err)
	}
	// 短 hex：左补零
	if got, err = parseUDPCMagicSDK("0x1"); err != nil || got != 1 {
		t.Fatalf("0x1: got=%08x err=%v", got, err)
	}
	// 原有 4 字节原文行为不变
	if got, err = parseUDPCMagicSDK("UDPC"); err != nil || got != 0x55445043 {
		t.Fatalf("UDPC: got=%08x err=%v", got, err)
	}
	// 空值仍走默认（UDP 的默认是 UDPC_MAGIC_DEFAULT = 0x55445043）
	if got, err = parseUDPCMagicSDK(""); err != nil || got != 0x55445043 {
		t.Fatalf("empty: got=%08x err=%v", got, err)
	}
	// 非法：超长 hex、裸 0x、长度错误
	for _, bad := range []string{"0x123456789", "0x", "0X", "abc", "UDP"} {
		if _, err := parseUDPCMagicSDK(bad); err == nil {
			t.Errorf("value %q unexpectedly accepted", bad)
		}
	}
}

func TestParseICMPMagicSDKHexPrefix(t *testing.T) {
	got, err := parseICMPMagicSDK("0xd1a7c0de")
	if err != nil || got != 0xd1a7c0de {
		t.Fatalf("0xd1a7c0de: got=%08x err=%v", got, err)
	}
	// 裸 8 位 hex 行为不变
	if got, err = parseICMPMagicSDK("D1A7C0DE"); err != nil || got != 0xd1a7c0de {
		t.Fatalf("D1A7C0DE: got=%08x err=%v", got, err)
	}
	// ASCII 词仍然被拒（指纹防护不因 0x 支持而放松）
	for _, bad := range []string{"UDPC", "0x", "0X", "0x123456789", "zzzzzzzz"} {
		if _, err := parseICMPMagicSDK(bad); err == nil {
			t.Errorf("value %q unexpectedly accepted", bad)
		}
	}
	// 空值默认
	if got, err := parseICMPMagicSDK(""); err != nil || got != 0 {
		t.Fatalf("empty: got=%08x err=%v", got, err)
	}
}

func TestCheckMagicJSON(t *testing.T) {
	// udp：原文输入
	res := CheckMagicJSON("udp_custom", "UDPC")
	var m magicCheckResult
	if err := json.Unmarshal([]byte(res), &m); err != nil {
		t.Fatalf("unmarshal: %v (%s)", err, res)
	}
	if !m.Valid || m.Magic != 0x55445043 || m.Normalized != "0x55445043" || m.UseDefault {
		t.Fatalf("udp UDPC: %+v", m)
	}
	// udp：0x 输入等价
	res = CheckMagicJSON("udp_custom", "0x55445043")
	if err := json.Unmarshal([]byte(res), &m); err != nil || m.Magic != 0x55445043 {
		t.Fatalf("udp 0x: %s", res)
	}
	// icmp：0x 输入
	res = CheckMagicJSON("icmp_custom", "0xD1A7C0DE")
	if err := json.Unmarshal([]byte(res), &m); err != nil || !m.Valid || m.Magic != 0xd1a7c0de {
		t.Fatalf("icmp 0x: %s", res)
	}
	// icmp：ASCII 词被拒
	res = CheckMagicJSON("icmp_custom", "UDPC")
	if err := json.Unmarshal([]byte(res), &m); err != nil || m.Valid || m.Error == "" {
		t.Fatalf("icmp ascii should fail: %s", res)
	}
	// 空值：use_default=true
	res = CheckMagicJSON("icmp_custom", "")
	if err := json.Unmarshal([]byte(res), &m); err != nil || !m.Valid || !m.UseDefault || m.Normalized != "0x00000000" {
		t.Fatalf("empty default: %s", res)
	}
	// 不支持的隧道类型
	res = CheckMagicJSON("h2", "UDPC")
	if err := json.Unmarshal([]byte(res), &m); err != nil || m.Valid || m.Error == "" {
		t.Fatalf("unsupported tunnel: %s", res)
	}
}
