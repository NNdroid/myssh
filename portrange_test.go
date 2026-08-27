package myssh

import (
	"net"
	"testing"
	"time"
)

func TestParseServerAddrWithRange(t *testing.T) {
	cases := []struct {
		raw      string
		wantHost string
		wantLen  int
		wantErr  bool
	}{
		{"1.1.1.1:1024-23000,25000-30000", "1.1.1.1", 23000 - 1024 + 1 + (30000 - 25000 + 1), false},
		{"1.1.1.1:36712", "1.1.1.1", 1, false},
		{"[::1]:1024-2000", "::1", 2000 - 1024 + 1, false},
		{"example.com:100-200", "example.com", 101, false},
		{"nohost", "", 0, true},
		{"1.1.1.1:", "", 0, true},
		{"1.1.1.1:0-10", "", 0, true},    // port < 1
		{"1.1.1.1:10-5", "", 0, true},    // lo > hi
		{"1.1.1.1:1-65536", "", 0, true}, // port > 65535
	}
	for _, c := range cases {
		host, _, ports, err := ParseServerAddrWithRange(c.raw)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseServerAddrWithRange(%q) expected error, got nil (host=%q ports=%v)", c.raw, host, ports)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseServerAddrWithRange(%q) unexpected error: %v", c.raw, err)
			continue
		}
		if host != c.wantHost {
			t.Errorf("ParseServerAddrWithRange(%q) host = %q, want %q", c.raw, host, c.wantHost)
		}
		if len(ports) != c.wantLen {
			t.Errorf("ParseServerAddrWithRange(%q) len(ports) = %d, want %d", c.raw, len(ports), c.wantLen)
		}
	}
}

func TestPortRangeMergeAndString(t *testing.T) {
	ports, err := ParsePortRangeSpec("30000,1024,25000,23000,1025")
	if err != nil {
		t.Fatalf("ParsePortRangeSpec error: %v", err)
	}
	pr, err := NewPortRange(ports)
	if err != nil {
		t.Fatalf("NewPortRange error: %v", err)
	}
	// Sorted + adjacent-merged: 1024,1025 -> 1024-1025; 23000 and 25000 disjoint; 30000 lone.
	if got := pr.String(); got != "1024-1025,23000,25000,30000" {
		t.Fatalf("PortRange.String() = %q, want 1024-1025,23000,25000,30000", got)
	}
	if pr.Total() != 5 {
		t.Fatalf("PortRange.Total() = %d, want 5", pr.Total())
	}
}

func TestPortSelectorRoundRobinCoversAll(t *testing.T) {
	ports, _ := ParsePortRangeSpec("100-102") // 100,101,102
	pr, _ := NewPortRange(ports)
	sel := NewPortSelector(pr, SelectorRoundRobin)
	seen := map[int]bool{}
	for i := 0; i < 300; i++ {
		seen[sel.Next()] = true
	}
	if len(seen) != 3 {
		t.Fatalf("round-robin selector covered %d distinct ports over 300 calls, want 3", len(seen))
	}
}

func TestPortSelectorRandomSpreads(t *testing.T) {
	ports, _ := ParsePortRangeSpec("1-65535")
	pr, _ := NewPortRange(ports)
	sel := NewPortSelector(pr, SelectorRandom)
	// Concurrent Next() must not panic / race.
	done := make(chan struct{})
	for g := 0; g < 8; g++ {
		go func() {
			for i := 0; i < 1000; i++ {
				_ = sel.Next()
			}
			done <- struct{}{}
		}()
	}
	for g := 0; g < 8; g++ {
		<-done
	}
}

func TestPortRangeContains(t *testing.T) {
	ports, _ := ParsePortRangeSpec("25000-26000,36712")
	pr, _ := NewPortRange(ports)
	in := []int{25000, 25500, 26000, 36712}
	out := []int{24999, 26001, 36711, 36713, 0, -1, 65536}
	for _, p := range in {
		if !pr.Contains(p) {
			t.Errorf("Contains(%d) = false, want true (range %s)", p, pr.String())
		}
	}
	for _, p := range out {
		if pr.Contains(p) {
			t.Errorf("Contains(%d) = true, want false (range %s)", p, pr.String())
		}
	}
}

// TestRangeUDPConnWiring verifies the rangeUDPConn wrapper actually delivers a
// datagram to a port inside the configured range (deterministic round-robin).
func TestRangeUDPConnWiring(t *testing.T) {
	// Receiver bound to a single known port inside the range.
	recvAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19001}
	recv, err := net.ListenUDP("udp4", recvAddr)
	if err != nil {
		t.Fatalf("receiver ListenUDP: %v", err)
	}
	defer recv.Close()
	_ = recv.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Unconnected send socket.
	send, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("sender ListenUDP: %v", err)
	}
	pr, _ := NewPortRange([]int{19000, 19001, 19002}) // range includes receiver port
	conn := NewRangeConn(send, "127.0.0.1", 19000, NewPortSelector(pr, SelectorRoundRobin))

	// With round-robin over 3 ports, writing 3 packets guarantees one lands on 19001.
	msg := []byte("hello-range")
	for i := 0; i < 3; i++ {
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("rangeUDPConn.Write: %v", err)
		}
	}

	buf := make([]byte, 64)
	n, _, err := recv.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("receiver read: %v (packet did not arrive on range port)", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("receiver got %q, want %q", buf[:n], msg)
	}
}
