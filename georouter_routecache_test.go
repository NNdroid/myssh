package myssh

import (
	"testing"
)

// TestGeoRouter_ShouldDirect_IPRule  info  GeoIP CIDR  info  IP  info 。
func TestGeoRouter_ShouldDirect_IPRule(t *testing.T) {
	r := setupTestRouter() //  info  8.8.8.8/32  info  192.168.0.0/16

	tests := []struct {
		name string
		ip   string
	}{
		{"exact /32 match", "8.8.8.8"},
		{"within /16 match", "192.168.1.5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.ShouldDirect(tt.ip)
			if !got.IsDirect {
				t.Errorf("ShouldDirect(%q) IsDirect = false, want true", tt.ip)
			}
			if got.DialHost != tt.ip {
				t.Errorf("ShouldDirect(%q) DialHost = %q, want %q", tt.ip, got.DialHost, tt.ip)
			}
		})
	}
}

// TestGeoRouter_ShouldDirect_Proxy  info ， info 。
func TestGeoRouter_ShouldDirect_Proxy(t *testing.T) {
	r := setupTestRouter()
	host := "www.example-not-in-rules.com"

	got := r.ShouldDirect(host)
	if got.IsDirect {
		t.Fatalf("ShouldDirect(%q) IsDirect = true, want false", host)
	}
	if got.DialHost != host {
		t.Errorf("DialHost = %q, want %q", got.DialHost, host)
	}

	//  info （routeIPCache）， info
	if _, ok := r.routeIPCache.Load(host); !ok {
		t.Errorf("expected host %q to be populated in routeIPCache after first ShouldDirect call", host)
	}
	got2 := r.ShouldDirect(host)
	if got2.IsDirect {
		t.Errorf("ShouldDirect(%q) second call IsDirect = true, want false (cache must not change routing decision)", host)
	}
}

// TestGeoRouter_ShouldDirect_ResetCache  info  ResetCacheAndStats  info 。
func TestGeoRouter_ShouldDirect_ResetCache(t *testing.T) {
	r := setupTestRouter()
	host := "www.example-reset-test.com"
	r.ShouldDirect(host)
	if _, ok := r.routeIPCache.Load(host); !ok {
		t.Fatalf("precondition failed: routeIPCache not populated")
	}

	r.ResetCacheAndStats()
	if _, ok := r.routeIPCache.Load(host); ok {
		t.Errorf("routeIPCache still contains %q after ResetCacheAndStats", host)
	}
}

// TestGeoRouter_ShouldDirect_Empty  info （ info  panic）。
func TestGeoRouter_ShouldDirect_Empty(t *testing.T) {
	r := setupTestRouter()
	if got := r.ShouldDirect(""); got.IsDirect {
		t.Errorf("ShouldDirect(\"\") IsDirect = true, want false")
	}
}
