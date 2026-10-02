package myssh

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/txthinking/socks5"
)

func regressionTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan *net.TCPConn, 1)
	go func() { c, _ := ln.AcceptTCP(); ch <- c }()
	c, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	s := <-ch
	if s == nil {
		c.Close()
		t.Fatal("accept failed")
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	s.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s
}

func TestRelayPreservesResponseAfterHalfClose(t *testing.T) {
	for _, direct := range []bool{false, true} {
		client, local := regressionTCPPair(t)
		remote, server := regressionTCPPair(t)
		done := make(chan struct{})
		go func() {
			relayBidirectional(context.Background(), local, WrapConn(remote, "halfclose.test"), direct)
			close(done)
		}()
		payload := bytes.Repeat([]byte("response"), 16384)
		serverErr := make(chan error, 1)
		go func() {
			_, err := io.ReadAll(server)
			if err == nil {
				err = writeFull(server, payload)
			}
			server.CloseWrite()
			serverErr <- err
		}()
		client.Write([]byte("request"))
		client.CloseWrite()
		got, err := io.ReadAll(client)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("direct=%v response=%d error=%v", direct, len(got), err)
		}
		if err := <-serverErr; err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("relay did not exit")
		}
	}
}

func TestRelayCancellation(t *testing.T) {
	client, local := regressionTCPPair(t)
	remote, server := regressionTCPPair(t)
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { relayBidirectional(ctx, local, WrapConn(remote, "cancel.test"), true); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel did not wake relay")
	}
}

func TestProtectedUDPInterfaceAddressType(t *testing.T) {
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}}
	matchDialerNetwork(dialer, "udp4")
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := dialer.DialContext(context.Background(), "udp4", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestUDPSessionIdleBudgetAndStaleCleanup(t *testing.T) {
	h := &SshProxyHandler{cfg: ProxyConfig{UdpMaxSessions: 1}}
	a, b := net.Pipe()
	defer b.Close()
	c, err := h.newUDPSession(a)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	x, y := net.Pipe()
	defer y.Close()
	if _, err := h.newUDPSession(x); err == nil {
		t.Fatal("budget not enforced")
	}
	key := "regression-idle"
	udpgwMap.Store(key, c)
	defer udpgwMap.Delete(key)
	readDone := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); readDone <- err }()
	h.sweepUDPSessions(time.Now().Add(time.Minute), time.Second, false)
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("read not interrupted")
		}
	case <-time.After(time.Second):
		t.Fatal("idle close did not interrupt read")
	}
	if h.sessions.Load() != 0 {
		t.Fatal("budget was not released")
	}
	x, y = net.Pipe()
	defer y.Close()
	replacement, err := h.newUDPSession(x)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	udpgwMap.Store(key, replacement)
	udpgwMap.CompareAndDelete(key, c)
	if v, ok := udpgwMap.Load(key); !ok || v != replacement {
		t.Fatal("old cleanup removed replacement")
	}
	h.sweepUDPSessions(time.Now(), time.Minute, false)
	if _, ok := udpgwMap.Load(key); !ok {
		t.Fatal("active session reaped")
	}
}

func TestCancelledSessionCannotPublish(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := &SshProxyHandler{ctx: ctx}
	a, b := net.Pipe()
	defer b.Close()
	c, err := h.newUDPSession(a)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = h.publishSession(&udpNatMap, "cancelled", c, nil)
	if err == nil || h.sessions.Load() != 0 {
		t.Fatal("cancelled session was published or leaked")
	}
}

func TestSocksUDPIngressLargePacketAndOrder(t *testing.T) {
	old := globalRouter.Load()
	r := newGeoRouter()
	r.ipTrie.Insert(net.IPv4(127, 0, 0, 1).To4(), 32)
	globalRouter.Store(r)
	defer globalRouter.Store(old)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := socks5.NewClassicServer("127.0.0.1:0", "", "", "", 0, 60)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareSocksServer(ctx, s); err != nil {
		t.Fatal(err)
	}
	h := &SshProxyHandler{ctx: ctx}
	done := make(chan error, 1)
	go func() { done <- serveSocks(ctx, s, h) }()
	defer func() {
		cancel()
		stopSocksServer(s)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("SOCKS server did not stop")
		}
	}()
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	target.SetReadBuffer(1024 * 1024)
	target.SetDeadline(time.Now().Add(5 * time.Second))
	client, err := net.DialUDP("udp", nil, s.UDPConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetReadBuffer(1024 * 1024)
	client.SetDeadline(time.Now().Add(5 * time.Second))
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(target.LocalAddr().(*net.UDPAddr).Port))
	for i := 0; i < 16; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, 8192)
		packet := socks5.NewDatagram(socks5.ATYPIPv4, []byte{127, 0, 0, 1}, port, payload).Bytes()
		if _, err := client.Write(packet); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 16; i++ {
		buf := make([]byte, 65536)
		n, addr, err := target.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		if n != 8192 || !bytes.Equal(buf[:n], bytes.Repeat([]byte{byte(i)}, 8192)) {
			t.Fatalf("packet %d size=%d first=%d", i, n, buf[0])
		}
		if _, err := target.WriteToUDP(buf[:n], addr); err != nil {
			t.Fatal(err)
		}
		n, err = client.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		d, err := socks5.NewDatagramFromBytes(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		if len(d.Data) != 8192 || d.Data[0] != byte(i) {
			t.Fatal("large response truncated or reordered")
		}
	}
}

func TestEngineStopDuringHandshakeAndRestart(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	cfg := ProxyConfig{LocalAddr: "127.0.0.1:0", SshAddr: ln.Addr().String(), AuthType: "password", TunnelType: "raw"}
	encoded, _ := json.Marshal(cfg)
	defer stopSshTProxy()
	for i := 0; i < 2; i++ {
		if startSshTProxy(string(encoded)) != 0 {
			t.Fatal("start failed")
		}
		var peer net.Conn
		select {
		case peer = <-accepted:
		case <-time.After(3 * time.Second):
			t.Fatal("no SSH dial")
		}
		done := make(chan struct{})
		go func() { stopSshTProxy(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			peer.Close()
			t.Fatal("Stop blocked on handshake")
		}
		peer.Close()
		mu.Lock()
		client := sshClient
		mu.Unlock()
		if client != nil {
			t.Fatal("stale client survived Stop")
		}
	}
}
