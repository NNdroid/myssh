package myssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	h2tunnel "github.com/NNdroid/h2tunnel"
	xhttptunnel "github.com/NNdroid/xhttptunnel/tunnel"
)

func assertSDKEcho(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}
}

func TestH2CSDKAdapterEndToEnd(t *testing.T) {
	target, stopEcho := startTCPEcho(t)
	defer stopEcho()

	authenticator, err := h2tunnel.NewTokenAuthenticator("sdk-token")
	if err != nil {
		t.Fatal(err)
	}
	server, err := h2tunnel.NewServer(h2tunnel.ServerOptions{
		Transports:    []h2tunnel.Transport{h2tunnel.TransportH2C},
		Networks:      []h2tunnel.Network{h2tunnel.NetworkTCP},
		Authenticator: authenticator,
		Dialer: func(ctx context.Context, request h2tunnel.DialRequest) (net.Conn, error) {
			if request.Network != h2tunnel.NetworkTCP || request.Target != target {
				return nil, h2tunnel.ErrForbidden
			}
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", target)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(h2tunnel.Listeners{TCP: listener}) }()
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			t.Errorf("shutdown h2tunnel server: %v", err)
		}
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("h2tunnel server: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("h2tunnel server did not stop")
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialH2SDK(ctx, ProxyConfig{
		TunnelType:        "h2c",
		ProxyAddr:         listener.Addr().String(),
		SshAddr:           target,
		ProxyAuthRequired: true,
		ProxyAuthToken:    "sdk-token",
	}, h2tunnel.TransportH2C, false)
	if err != nil {
		t.Fatal(err)
	}
	assertSDKEcho(t, conn, []byte("myssh h2tunnel SDK adapter"))
}

func TestXHTTPCSDKAdapterEndToEnd(t *testing.T) {
	target, stopEcho := startTCPEcho(t)
	defer stopEcho()

	ctx, cancel := context.WithCancel(context.Background())
	server, err := xhttptunnel.NewServer(xhttptunnel.ServerConfig{
		Listen:         "tcp://127.0.0.1:0",
		Path:           "/sdk",
		PSK:            "sdk-token",
		AllowedTargets: []string{target},
	})
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ListenAndServe(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for server.Addr() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if server.Addr() == nil {
		cancel()
		t.Fatal("xhttptunnel server did not start")
	}
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		select {
		case err := <-serveErr:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("xhttptunnel server: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("xhttptunnel server did not stop")
		}
	})

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dialCancel()
	conn, err := dialXHTTPSDK(dialCtx, ProxyConfig{
		TunnelType:        "xhttpc",
		ProxyAddr:         server.Addr().String(),
		CustomPath:        "/sdk",
		SshAddr:           target,
		ProxyAuthRequired: true,
		ProxyAuthToken:    "sdk-token",
		Alpn:              "h1",
		XhttpChunkSizeKB:  64,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	assertSDKEcho(t, conn, []byte("myssh xhttptunnel SDK adapter"))
}
