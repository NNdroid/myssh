package myssh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type PingRequest struct {
	Id     string      `json:"id"`
	Config ProxyConfig `json:"config"`
}

type PingResult struct {
	Id        string `json:"id"`
	Ok        bool   `json:"ok"`
	LatencyMs int64  `json:"latencyMs"`
	Error     string `json:"error"`
	ErrorType string `json:"errorType"` // timeout|connrefused|auth|hostkey|tcpforward|tls|dns|http|other|""

	// 分段计时。LatencyMs == HandshakeMs + HttpMs（三段之和），单列出来是为了让
	// UI 能解释「为什么这里 200ms 而系统 ping 只有 30ms」：握手含 TCP + SSH KEX/认证，
	// 跨洋节点里它往往是主要开销，而不是网络 RTT。
	//
	// 加字段是向后兼容的：pingNodes 返回的是 JSON 字符串而非 gomobile 结构体，
	// 老版本客户端解析时忽略未知键即可，**无需重新生成 AAR**。
	HandshakeMs int64 `json:"handshakeMs"` // TCP 建连 + SSH 握手
	HttpMs      int64 `json:"httpMs"`      // 隧道内 HTTP 往返
}

var pingCancel atomic.Value

func CancelPing() {
	if f, ok := pingCancel.Load().(context.CancelFunc); ok && f != nil {
		f()
	}
}

func pingNodes(profilesJson string, targetUrl string, timeoutMs int) string {
	var reqs []PingRequest
	if err := json.Unmarshal([]byte(profilesJson), &reqs); err != nil {
		zlog.Errorf("[Latency] json unmarshal failed: %v", err)
		return "[]"
	}

	if timeoutMs <= 0 {
		timeoutMs = 8000
	}
	if strings.TrimSpace(targetUrl) == "" {
		targetUrl = "http://cp.cloudflare.com/generate_204"
	}

	zlog.Infof("[Latency] ping batch start: target=%s, timeout=%dms, count=%d", targetUrl, timeoutMs, len(reqs))

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	pingCancel.Store(cancel)
	defer cancel()

	resCh := make(chan PingResult, len(reqs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)

	for _, req := range reqs {
		wg.Add(1)
		go func(r PingRequest) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			latency, handshakeMs, httpMs, err := testSingleNodeTrueLatency(ctx, r.Config, targetUrl, time.Duration(timeoutMs)*time.Millisecond)
			if err != nil {
				zlog.Errorf("[Latency] node %s failed: %v", r.Id, err)
				resCh <- PingResult{Id: r.Id, Ok: false, Error: err.Error(), ErrorType: classifyPingError(err)}
				return
			}
			zlog.Infof("[Latency] node %s success: %d ms (handshake %d ms + http %d ms)", r.Id, latency, handshakeMs, httpMs)
			resCh <- PingResult{Id: r.Id, Ok: true, LatencyMs: latency, HandshakeMs: handshakeMs, HttpMs: httpMs}
		}(req)
	}

	wg.Wait()
	close(resCh)

	var resps []PingResult
	for resp := range resCh {
		resps = append(resps, resp)
	}

	out, _ := json.Marshal(resps)
	return string(out)
}

// testSingleNodeTrueLatency 返回 (总耗时, 握手耗时, 隧道内 HTTP 耗时)。
//
// 计时分段而非只报总数，是为了让 UI 能解释延迟构成：跨洋节点里 SSH 握手
// （TCP + KEX + 认证）常占大头，把它和真实 RTT 混在一个数字里会让用户
// 误以为是链路问题。总耗时保持为两段之和，语义与旧版完全一致。
func testSingleNodeTrueLatency(ctx context.Context, cfg ProxyConfig, targetUrl string, timeout time.Duration) (int64, int64, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()

	sshClient, conn, err := DialNode(ctx, cfg, true)
	if err != nil {
		return 0, 0, 0, err
	}
	handshakeMs := time.Since(start).Milliseconds()
	defer conn.Close()
	defer sshClient.Close()

	if !strings.HasPrefix(targetUrl, "http://") && !strings.HasPrefix(targetUrl, "https://") {
		targetUrl = "http://" + targetUrl
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetUrl, nil)
	if err != nil {
		return 0, 0, 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Stun/Ping")

	// 每次探测都需要指向该节点 sshClient 的独立 Transport，无法全局复用；
	// 但必须显式关闭其空闲连接，否则批量 ping 会累积残留的 Transport 与连接。
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return sshClient.Dial("tcp", addr)
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: timeout,
	}
	defer transport.CloseIdleConnections()

	httpClient := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: timeout,
	}

	httpStart := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("http err: %w", err)
	}
	defer resp.Body.Close()
	httpMs := time.Since(httpStart).Milliseconds()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return 0, 0, 0, fmt.Errorf("status %d", resp.StatusCode)
	}

	return handshakeMs + httpMs, handshakeMs, httpMs, nil
}

func classifyPingError(err error) string {
	if err == nil {
		return ""
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline"), strings.Contains(msg, "context canceled"):
		return "timeout"
	case strings.Contains(msg, "connection refused"), strings.Contains(msg, "connect: "):
		return "connrefused"
	case strings.Contains(msg, "unable to authenticate"), strings.Contains(msg, "auth failed"), strings.Contains(msg, "password"), strings.Contains(msg, "private key"):
		return "auth"
	case strings.Contains(msg, "host key") && strings.Contains(msg, "mismatch"):
		return "hostkey"
	case strings.Contains(msg, "administratively prohibited"), strings.Contains(msg, "forwarding"):
		return "tcpforward"
	case strings.Contains(msg, "x509"), strings.Contains(msg, "certificate"), strings.Contains(msg, "tls"):
		return "tls"
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "lookup"), strings.Contains(msg, "dns"):
		return "dns"
	case strings.Contains(msg, "status "):
		return "http"
	default:
		return "other"
	}
}
