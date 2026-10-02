package main

import (
	"encoding/json"
	"myssh"
	"testing"
)

func TestPerformanceProfileRoundTrip(t *testing.T) {
	newTestDB(t)
	p := Profile{Name: "performance", TcpBufferKB: 512, UdpMaxSessions: 256, UdpIdleTimeoutSec: 120}
	id, err := AddProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := GetProfile(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.TcpBufferKB != 512 || got.UdpMaxSessions != 256 || got.UdpIdleTimeoutSec != 120 {
		t.Fatalf("round trip: %+v", got)
	}
	got.TcpBufferKB, got.UdpMaxSessions, got.UdpIdleTimeoutSec = 1024, 512, 30
	if err := UpdateProfile(id, *got); err != nil {
		t.Fatal(err)
	}
	encoded, err := BuildProxyConfigJSON(id)
	if err != nil {
		t.Fatal(err)
	}
	var cfg myssh.ProxyConfig
	if err := json.Unmarshal([]byte(encoded), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.TcpBufferKB != 1024 || cfg.UdpMaxSessions != 512 || cfg.UdpIdleTimeoutSec != 30 {
		t.Fatalf("config: %+v", cfg)
	}
}
