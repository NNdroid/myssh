package main

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"myssh"
)

// resetDB clears the package-global *sql.DB so each subtest gets a fresh
// database. InitDB() early-returns when db != nil, so we must nil it out.
func resetDB(t *testing.T) {
	t.Helper()
	dbMu.Lock()
	db = nil
	dbMu.Unlock()
}

func newTestDB(t *testing.T) {
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
}

func TestBuildProxyConfigJSON_DnsTunnel(t *testing.T) {
	newTestDB(t)

	p := Profile{
		Name:             "dns-node",
		SshAddr:          "1.2.3.4:22",
		User:             "u",
		TunnelType:       "dns_custom",
		DnsTunnelDomain:  "tunnel.example.com",
		DnsTunnelServers: "8.8.8.8:53, 1.1.1.1:53",
		DnsTunnelType:    "txt",
	}
	id, err := AddProfile(p)
	if err != nil {
		t.Fatalf("AddProfile: %v", err)
	}

	// 1) Persisted fields survive a read-back (validates INSERT/SELECT columns).
	got, err := GetProfile(id)
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if got.DnsTunnelDomain != p.DnsTunnelDomain ||
		got.DnsTunnelServers != p.DnsTunnelServers ||
		got.DnsTunnelType != p.DnsTunnelType {
		t.Fatalf("persisted DNS fields mismatch: %+v", got)
	}

	// 2) Update round-trips (validates UPDATE SET/arg alignment).
	got.DnsTunnelType = "null"
	got.DnsTunnelServers = "9.9.9.9:53"
	if err := UpdateProfile(id, *got); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	updated, err := GetProfile(id)
	if err != nil {
		t.Fatalf("GetProfile after update: %v", err)
	}
	if updated.DnsTunnelType != "null" || updated.DnsTunnelServers != "9.9.9.9:53" {
		t.Fatalf("UPDATE did not persist DNS fields: %+v", updated)
	}

	// 3) BuildProxyConfigJSON emits the DNS fields into ProxyConfig.
	cfgJSON, err := BuildProxyConfigJSON(id)
	if err != nil {
		t.Fatalf("BuildProxyConfigJSON: %v", err)
	}
	var cfg myssh.ProxyConfig
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		t.Fatalf("unmarshal ProxyConfig: %v", err)
	}
	if cfg.TunnelType != "dns_custom" {
		t.Fatalf("TunnelType = %q, want dns_custom", cfg.TunnelType)
	}
	if cfg.DnsTunnelDomain != "tunnel.example.com" {
		t.Fatalf("DnsTunnelDomain = %q", cfg.DnsTunnelDomain)
	}
	wantServers := []string{"9.9.9.9:53"}
	if len(cfg.DnsTunnelServers) != len(wantServers) {
		t.Fatalf("DnsTunnelServers = %v, want %v", cfg.DnsTunnelServers, wantServers)
	}
	for i := range wantServers {
		if cfg.DnsTunnelServers[i] != wantServers[i] {
			t.Fatalf("DnsTunnelServers[%d] = %q, want %q", i, cfg.DnsTunnelServers[i], wantServers[i])
		}
	}
	if cfg.DnsTunnelType != "null" {
		t.Fatalf("DnsTunnelType = %q, want null", cfg.DnsTunnelType)
	}
}

func TestBuildProxyConfigJSON_LegacyVaydnsTranslate(t *testing.T) {
	newTestDB(t)

	p := Profile{
		Name:             "legacy",
		SshAddr:          "1.2.3.4:22",
		TunnelType:       "vaydns", // legacy selection
		DnsTunnelDomain:  "t.example.com",
		DnsTunnelServers: "8.8.4.4:53, 1.0.0.1:53",
		DnsTunnelType:    "cname",
	}
	id, err := AddProfile(p)
	if err != nil {
		t.Fatalf("AddProfile: %v", err)
	}

	cfgJSON, err := BuildProxyConfigJSON(id)
	if err != nil {
		t.Fatalf("BuildProxyConfigJSON: %v", err)
	}
	var cfg myssh.ProxyConfig
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Legacy "vaydns" must be translated to the real "dns_custom" tunnel.
	if cfg.TunnelType != "dns_custom" {
		t.Fatalf("legacy vaydns should translate to dns_custom, got %q", cfg.TunnelType)
	}
	wantServers := []string{"8.8.4.4:53", "1.0.0.1:53"}
	if len(cfg.DnsTunnelServers) != len(wantServers) {
		t.Fatalf("DnsTunnelServers = %v, want %v", cfg.DnsTunnelServers, wantServers)
	}
	for i := range wantServers {
		if cfg.DnsTunnelServers[i] != wantServers[i] {
			t.Fatalf("DnsTunnelServers[%d] = %q, want %q", i, cfg.DnsTunnelServers[i], wantServers[i])
		}
	}
	if cfg.DnsTunnelType != "cname" {
		t.Fatalf("DnsTunnelType = %q, want cname", cfg.DnsTunnelType)
	}
}
