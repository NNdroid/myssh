package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestDBDir 与 newTestDB 相同，但返回临时目录，供断言 db/key 文件内容。
func newTestDBDir(t *testing.T) string {
	t.Helper()
	resetDB(t)
	dir := t.TempDir()
	if err := InitDB(filepath.Join(dir, "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() {
		dbMu.Lock()
		if db != nil {
			_ = db.Close()
			db = nil
		}
		dbMu.Unlock()
	})
	return dir
}

// TestCredentialEncryptRoundTrip 加密层端到端契约：凭据以密文落库（db 文件里
// 不出现明文）、读路径透明解密、公钥/指纹等非凭据字段不受影响、历史明文兼容。
func TestCredentialEncryptRoundTrip(t *testing.T) {
	dir := newTestDBDir(t)
	dbPath := filepath.Join(dir, "test.db")

	p := Profile{
		ID:                 "enc-1",
		Name:               "cred-node",
		SshAddr:            "1.2.3.4:22",
		User:               "root",
		Pass:               "s3cret-password",
		PrivateKey:         "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\ndef\n-----END OPENSSH PRIVATE KEY-----",
		KeyPass:            "key-passphrase",
		KcpPassword:        "kcp-psk",
		UdpCustomPsk:       "udp-psk",
		ProxyAuthPass:      "proxy-pass",
		UdpCustomPublicKey: "public-key-material",
		TunnelType:         "raw",
	}
	if _, err := AddProfile(p); err != nil {
		t.Fatalf("AddProfile: %v", err)
	}

	// db 文件里不允许出现任何凭据明文，但应出现密文标记与公钥明文
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read db file: %v", err)
	}
	for _, secret := range []string{p.Pass, p.PrivateKey, p.KeyPass, p.KcpPassword, p.UdpCustomPsk, p.ProxyAuthPass} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("plaintext credential %q found in db file", secret)
		}
	}
	if !strings.Contains(string(raw), encFieldPrefix) {
		t.Error("no ciphertext prefix found in db file — credentials were not encrypted")
	}
	if !strings.Contains(string(raw), p.UdpCustomPublicKey) {
		t.Error("non-credential public key must stay plaintext")
	}

	// 读路径透明解密
	got, err := GetProfile("enc-1")
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if got.Pass != p.Pass || got.PrivateKey != p.PrivateKey || got.KeyPass != p.KeyPass ||
		got.KcpPassword != p.KcpPassword || got.UdpCustomPsk != p.UdpCustomPsk || got.ProxyAuthPass != p.ProxyAuthPass {
		t.Errorf("round-trip mismatch: got pass=%q keyPass=%q", got.Pass, got.KeyPass)
	}

	profiles, err := GetProfiles()
	if err != nil {
		t.Fatalf("GetProfiles: %v", err)
	}
	if len(profiles) != 1 || profiles[0].Pass != p.Pass {
		t.Errorf("GetProfiles round-trip mismatch: len=%d pass=%q", len(profiles), profiles[0].Pass)
	}

	// 历史明文兼容：绕过 API 直接写明文，读取应原样放行
	if _, err := db.Exec("UPDATE profiles SET pass='legacy-plain' WHERE id='enc-1'"); err != nil {
		t.Fatalf("legacy write: %v", err)
	}
	got, err = GetProfile("enc-1")
	if err != nil {
		t.Fatalf("GetProfile legacy: %v", err)
	}
	if got.Pass != "legacy-plain" {
		t.Errorf("legacy plaintext pass = %q, want %q", got.Pass, "legacy-plain")
	}

	// 重新保存后明文被加密覆盖
	if err := UpdateProfile("enc-1", *got); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	raw, err = os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read db file: %v", err)
	}
	if strings.Contains(string(raw), "legacy-plain") {
		t.Error("legacy plaintext was not encrypted on re-save")
	}
}

// TestCredentialDecryptFailureReturnsEmpty 密钥丢失/不匹配时：解密失败返回空串
// （宁可表现为"缺凭据"的显性故障，不把密文当明文写进运行配置）。
func TestCredentialDecryptFailureReturnsEmpty(t *testing.T) {
	newTestDBDir(t)

	p := Profile{ID: "enc-2", Name: "n", SshAddr: "1.2.3.4:22", Pass: "the-pass", TunnelType: "raw"}
	if _, err := AddProfile(p); err != nil {
		t.Fatalf("AddProfile: %v", err)
	}

	// 模拟 key 丢失：换一把不匹配的密钥
	saved := encKey
	defer func() { encKey = saved }()
	encKey = make([]byte, 32)

	got, err := GetProfile("enc-2")
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if got.Pass != "" {
		t.Errorf("pass with mismatched key = %q, want empty", got.Pass)
	}
}

// TestMergeRedactedCredentials PUT 的凭据语义：留空 = 沿用旧值，哨兵 = 清空，
// 显式新值 = 直接采用。
func TestMergeRedactedCredentials(t *testing.T) {
	existing := &Profile{Pass: "old-pass", KeyPass: "old-keypass", PrivateKey: "old-key"}

	merged := &Profile{}
	mergeRedactedCredentials(merged, existing)
	if merged.Pass != "old-pass" || merged.KeyPass != "old-keypass" || merged.PrivateKey != "old-key" {
		t.Errorf("empty fields must keep existing values: pass=%q keyPass=%q", merged.Pass, merged.KeyPass)
	}

	merged = &Profile{Pass: credentialClearSentinel, KeyPass: "new-keypass"}
	mergeRedactedCredentials(merged, existing)
	if merged.Pass != "" {
		t.Errorf("clear sentinel must produce empty pass, got %q", merged.Pass)
	}
	if merged.KeyPass != "new-keypass" {
		t.Errorf("explicit new value must be kept, got %q", merged.KeyPass)
	}

	// 全量回写（TOFU 场景持有完整明文）不受合并影响
	merged = &Profile{Pass: "old-pass"}
	mergeRedactedCredentials(merged, existing)
	if merged.Pass != "old-pass" {
		t.Errorf("full-value write-back must be untouched, got %q", merged.Pass)
	}
}

// TestRedactSensitiveFields 响应脱敏：9 个凭据列清空、其余字段不动。
func TestRedactSensitiveFields(t *testing.T) {
	p := Profile{
		Pass: "s", PrivateKey: "s", KeyPass: "s", ProxyAuthToken: "s", ProxyAuthPass: "s",
		KcpPassword: "s", UdpCustomPsk: "s", IcmpCustomPsk: "s", DnsTunnelPsk: "s",
		User: "root", ServerFingerprint: "fp", UdpCustomPublicKey: "pub",
	}
	redactSensitiveFields(&p)
	for name, v := range map[string]string{
		"pass": p.Pass, "privateKey": p.PrivateKey, "keyPass": p.KeyPass,
		"proxyAuthToken": p.ProxyAuthToken, "proxyAuthPass": p.ProxyAuthPass,
		"kcpPassword": p.KcpPassword, "udpCustomPsk": p.UdpCustomPsk,
		"icmpCustomPsk": p.IcmpCustomPsk, "dnsTunnelPsk": p.DnsTunnelPsk,
	} {
		if v != "" {
			t.Errorf("redacted field %s = %q, want empty", name, v)
		}
	}
	if p.User != "root" || p.ServerFingerprint != "fp" || p.UdpCustomPublicKey != "pub" {
		t.Error("non-credential fields must stay untouched")
	}
}
