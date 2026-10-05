package myssh

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// setRuleSources redirects DownloadRuleFiles at test servers for the duration
// of the test, so no test can reach the real CDN.
func setRuleSources(t *testing.T, urls map[string]string) {
	t.Helper()
	old := ruleSources
	ruleSources = nil
	for name, url := range urls {
		ruleSources = append(ruleSources, struct {
			name string
			url  string
		}{name: name, url: url})
	}
	t.Cleanup(func() { ruleSources = old })
}

// TestRepairRuleFile_LeavesMissingFileAlone pins the cold-start behaviour: an
// absent rule file is reported as missing, never downloaded. config.go already
// degrades gracefully there, and fetching on every boot would add network
// latency on a device that may be offline.
func TestRepairRuleFile_LeavesMissingFileAlone(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	setRuleSources(t, map[string]string{"geoip.dat": srv.URL, "geosite.dat": srv.URL})

	dir := t.TempDir()
	path := filepath.Join(dir, "geoip.dat")

	if RepairRuleFile(path) {
		t.Fatal("a missing file must be reported as unrepaired")
	}
	if hits != 0 {
		t.Fatalf("absent file must not trigger a download, got %d request(s)", hits)
	}
}

// TestRepairRuleFile_KeepsValidFile makes sure the self-heal is not eager: a
// healthy file must be left in place untouched.
func TestRepairRuleFile_KeepsValidFile(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	setRuleSources(t, map[string]string{"geoip.dat": srv.URL, "geosite.dat": srv.URL})

	full := buildGeoIPList(t, []string{"cn", "private"})
	path := writeRuleFile(t, "geoip.dat", full)

	if !RepairRuleFile(path) {
		t.Fatal("a valid file must be reported usable")
	}
	if hits != 0 {
		t.Fatalf("a valid file must not be re-downloaded, got %d request(s)", hits)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, full) {
		t.Fatal("a valid file must not be modified")
	}
}

// TestRepairRuleFile_ReplacesCorruptFile is the regression for the reported
// field failure: a truncated geoip.dat sat on disk across the whole session
// because the only call sites for DownloadRuleFiles were the web/MCP endpoint
// and the daily worker. The load path now repairs it before routing goes
// silently wrong.
func TestRepairRuleFile_ReplacesCorruptFile(t *testing.T) {
	full := buildGeoIPList(t, []string{"cn", "private", "cloudflare"})
	_, off := splitGeoIPFixture(t, []string{"cn", "private", "cloudflare"})
	corrupt := full[:off+3]

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(full)
	}))
	defer srv.Close()
	setRuleSources(t, map[string]string{"geoip.dat": srv.URL, "geosite.dat": srv.URL})

	path := writeRuleFile(t, "geoip.dat", corrupt)
	if !RepairRuleFile(path) {
		t.Fatal("a corrupt file must be repaired")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, full) {
		t.Fatalf("repaired file holds %d bytes, want %d", len(got), len(full))
	}
	if shouldDownload(path) {
		t.Fatal("the repaired file must be considered usable")
	}
	n, err := newGeoRouter().LoadGeoIP(path, []string{"cn", "private"})
	if err != nil || n != 2 {
		t.Fatalf("the repaired file must load, got n=%d err=%v", n, err)
	}
}

// TestRepairRuleFile_KeepsBrokenCopyWhenDownloadFails: a failed repair must
// leave the previous copy in place (possibly broken) rather than deleting it,
// so the load path can still parse what is there and the failure stays visible.
func TestRepairRuleFile_KeepsBrokenCopyWhenDownloadFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	setRuleSources(t, map[string]string{"geoip.dat": srv.URL, "geosite.dat": srv.URL})

	corrupt := bytes.Repeat([]byte{0xff}, 128)
	path := writeRuleFile(t, "geoip.dat", corrupt)

	if RepairRuleFile(path) {
		t.Fatal("a failed download must be reported as unrepaired")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("previous copy must survive a failed repair: %v", err)
	}
	if !bytes.Equal(got, corrupt) {
		t.Fatalf("previous copy was clobbered (got %d bytes, want %d)", len(got), len(corrupt))
	}
}

func TestNonProxyable(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		// 这些地址无法经代理转发，必须无条件直连
		{"224.0.0.251", true}, // IPv4 mDNS 组播
		{"239.255.255.250", true},
		{"ff02::fb", true}, // IPv6 mDNS 组播
		{"ff01::1", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"169.254.10.1", true},
		{"fe80::1", true},
		{"0.0.0.0", true},
		{"::", true},
		// 其余地址仍交给 GeoIP 规则判定（含 RFC1918：依赖 geoip 的 private 标签）
		{"8.8.8.8", false},
		{"2001:4860:4860::8888", false},
		{"192.168.1.1", false},
		{"fd00::1", false},
	}

	for _, tc := range cases {
		addr, err := netip.ParseAddr(tc.addr)
		if err != nil {
			t.Fatalf("bad test address %q: %v", tc.addr, err)
		}
		if got := nonProxyable(addr); got != tc.want {
			t.Errorf("nonProxyable(%s) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

// TestGeoRouter_NonProxyableDirectWithEmptyGeoIP reproduces the field state in
// the PR #4 log: GeoIP failed to load, so the Radix tree was empty. Multicast
// was sent to the proxy and the remote rejected it with UDPGW flag 0x20.
func TestGeoRouter_NonProxyableDirectWithEmptyGeoIP(t *testing.T) {
	r := newGeoRouter() // 空规则表

	for _, host := range []string{"224.0.0.251", "ff02::fb", "127.0.0.1", "169.254.10.1"} {
		if res := r.ShouldDirect(host); !res.IsDirect {
			t.Errorf("%s must be routed direct even with an empty GeoIP table", host)
		}
	}
	// RFC1918 刻意不放进 nonProxyable：它由 geoip 的 private 标签负责，
	// 规则表恢复正常后不应被硬编码短路。
	if res := r.ShouldDirect("192.168.197.212"); res.IsDirect {
		t.Error("LAN traffic must still be decided by GeoIP rules, not hard-coded")
	}
}

// TestGeoRouter_LogRateLimitedSuppressesRepeats verifies the dedup: one target
// logs once inside the window, a distinct target is independent, an expired
// entry logs again, and the suppression table cannot grow without bound.
func TestGeoRouter_LogRateLimitedSuppressesRepeats(t *testing.T) {
	r := newGeoRouter()

	r.logRateLimited("ip:1.2.3.4", "hit")
	first, _ := r.rateLogTimes.Load("ip:1.2.3.4")

	for i := 0; i < 500; i++ {
		r.logRateLimited("ip:1.2.3.4", "hit")
	}
	again, _ := r.rateLogTimes.Load("ip:1.2.3.4")
	if !first.(time.Time).Equal(again.(time.Time)) {
		t.Fatal("suppressed repeats must not refresh the timestamp")
	}

	r.logRateLimited("ip:5.6.7.8", "hit")
	if r.rateLogCount.Load() != 2 {
		t.Fatalf("each distinct target counts once, got %d", r.rateLogCount.Load())
	}

	// 窗口过期后重新放行，并更新时间戳
	stale := time.Now().Add(-10 * time.Minute)
	r.rateLogTimes.Store("ip:9.9.9.9", stale)
	r.logRateLimited("ip:9.9.9.9", "hit")
	fresh, _ := r.rateLogTimes.Load("ip:9.9.9.9")
	if fresh.(time.Time).Equal(stale) {
		t.Fatal("an expired entry must be re-logged")
	}

	// 容量上限触发整体清空
	for i := 0; i < rateLimitedLogMaxKeys+16; i++ {
		r.logRateLimited("domain:flood", "hit")
	}
	if r.rateLogCount.Load() > rateLimitedLogMaxKeys {
		t.Fatalf("count must be reset after the overflow sweep, got %d", r.rateLogCount.Load())
	}
}
