package myssh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	udpclient "github.com/NNdroid/udp_custom/tunnel"
)

type realServerCfg struct {
	Mode           string   `json:"mode"`
	Listen         string   `json:"listen"`
	PortRange      string   `json:"port_range"`
	Target         string   `json:"target"`
	AllowedTargets []string `json:"allowed_targets"`
	Passwords      []string `json:"passwords"`
	Magic          string   `json:"magic"`
	PrivKey        string   `json:"privkey"`
	LogLevel       string   `json:"log_level"`
	OrigDst        bool     `json:"origdst"`
}

func buildUDPCServer(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("UDPC_BIN"); path != "" {
		return path
	}
	lookup := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/NNdroid/udp_custom")
	lookup.Dir = "."
	source, err := lookup.CombinedOutput()
	if err != nil {
		t.Fatalf("locate udp_custom module: %v: %s", err, source)
	}
	out := t.TempDir() + string(os.PathSeparator) + "udpc.exe"
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = strings.TrimSpace(string(source))
	if data, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build udp_custom server: %v: %s", err, data)
	}
	return out
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	_ = conn.Close()
	return port
}

func startTCPEcho(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func startRealUDPCServer(t *testing.T, binary, privateKey, target string) (string, func()) {
	t.Helper()
	port := freeUDPPort(t)
	serverAddr := fmt.Sprintf("127.0.0.1:%d", port)
	cfg := realServerCfg{
		Mode:           "server",
		Listen:         serverAddr,
		PortRange:      fmt.Sprint(port),
		Target:         "tcp://" + target,
		AllowedTargets: []string{"tcp://" + target},
		Passwords:      []string{"test_psk_123"},
		Magic:          "UDPC",
		PrivKey:        privateKey,
		LogLevel:       "warn",
		OrigDst:        false,
	}
	configFile, err := os.CreateTemp("", "udpc-server-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(configFile).Encode(cfg); err != nil {
		t.Fatal(err)
	}
	_ = configFile.Close()

	cmd := exec.Command(binary, "-c", configFile.Name())
	if data, err := cmd.StdoutPipe(); err == nil {
		go io.Copy(io.Discard, data)
	}
	if data, err := cmd.StderrPipe(); err == nil {
		go io.Copy(io.Discard, data)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	return serverAddr, func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = os.Remove(configFile.Name())
	}
}

func testUDPCSDKRoundTrip(t *testing.T, binary string, useNoise bool) {
	t.Helper()
	target, stopEcho := startTCPEcho(t)
	defer stopEcho()
	privateKey, publicKey := "", ""
	if useNoise {
		pair, err := udpclient.GenerateNoiseKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		privateKey, _ = udpclient.FormatNoiseKey(pair.PrivateKey)
		publicKey, _ = udpclient.FormatNoiseKey(pair.PublicKey)
	}
	serverAddr, stopServer := startRealUDPCServer(t, binary, privateKey, target)
	defer stopServer()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	conn, err := dialUDPCustomSDK(ctx, ProxyConfig{
		ProxyAddr:           serverAddr,
		SshAddr:             target,
		UdpCustomPsk:        "test_psk_123",
		UdpCustomMagic:      "UDPC",
		UdpCustomPublicKey:  publicKey,
		UdpCustomPaths:      1,
		UdpCustomSockets:    1,
		UdpCustomSendWindow: 32,
	})
	if err != nil {
		t.Fatalf("dial SDK: %v", err)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte("udp_custom sdk interop "), 160)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("round trip mismatch")
	}
}

func TestRealServerInterop(t *testing.T) {
	binary := buildUDPCServer(t)
	t.Run("Noise", func(t *testing.T) { testUDPCSDKRoundTrip(t, binary, true) })
	t.Run("PSKOnly", func(t *testing.T) { testUDPCSDKRoundTrip(t, binary, false) })
}
