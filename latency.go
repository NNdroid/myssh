package myssh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
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
	HttpMs      int64 `json:"httpMs"`      // 隧道内 HTTP 往返（多次采样的中位数）
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
//
// 隧道内 HTTP 这一段取多次采样的中位数而不是单次首包耗时：首包要付建连与
// 隧道数据路径建立的开销（Android 上常达秒级），单次采样也会被抖动带偏，
// 两者都不是用户体感的稳态往返。
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

	targetUrl = ensureHTTPScheme(targetUrl)

	// 每次探测都需要指向该节点 sshClient 的独立 Transport，无法全局复用；
	// 但必须显式关闭其空闲连接，否则批量 ping 会累积残留的 Transport 与连接。
	transport := newSSHHTTPTransport(sshClient, timeout)
	defer transport.CloseIdleConnections()

	httpClient := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: timeout,
	}

	// 隧道内 HTTP 这一段取多次采样的中位数而不是首包耗时：首包要付建连与隧道
	// 数据路径建立的开销（Android 上常达秒级），是个冷启动离群值，恰好被中位数
	// 滤掉；跨洋链路偶发重传造成的单样本尖峰同样被滤掉。
	samples, err := collectProbeSamples(httpClient, ctx, targetUrl)
	if err != nil {
		return 0, 0, 0, err
	}
	httpMs := medianInt64(samples)

	return handshakeMs + httpMs, handshakeMs, httpMs, nil
}

// probeSamples 是隧道内 HTTP 的采样次数：取中位数而非单次，首包的冷启动开销
// 与偶发的重传尖峰都会被滤掉。
const probeSamples = 3

// collectProbeSamples 连发 probeSamples 次探测请求，返回每次的 HTTP 往返毫秒数。
// 首包失败说明隧道根本不通，如实上报；后续样本失败只可能是预算耗尽或链路抖动，
// 丢弃后按已采到的样本收尾——否则「可用但慢」的节点会因为多采几次而被误判成
// 超时不可用。
func collectProbeSamples(client *http.Client, ctx context.Context, targetUrl string) ([]int64, error) {
	samples := make([]int64, 0, probeSamples)
	for i := 0; i < probeSamples; i++ {
		ms, err := probeOnceTimed(client, ctx, targetUrl)
		if err != nil {
			if len(samples) == 0 {
				return nil, err
			}
			break
		}
		samples = append(samples, ms)
	}
	return samples, nil
}

// newProbeRequest 构造一条探测请求。User-Agent 保持浏览器样式，避免部分站点
// （Cloudflare 等）对裸 Go client 返回非 2xx 的降级页而让探测误报节点不可用。
func newProbeRequest(ctx context.Context, targetUrl string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetUrl, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Stun/Ping")
	return req, nil
}

// probeOnceTimed 经隧道发一条请求并校验状态码，返回隧道内 HTTP 往返毫秒数。
func probeOnceTimed(client *http.Client, ctx context.Context, targetUrl string) (int64, error) {
	req, err := newProbeRequest(ctx, targetUrl)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("http err: %w", err)
	}
	defer drainProbeResponse(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	return time.Since(start).Milliseconds(), nil
}

// drainProbeResponse 读空并关闭响应体，让底层连接回到空闲池供后续采样复用。
// 不读空的话连接会被直接关闭，每个样本又得重付建连开销，测出的就不是稳态往返。
// 读取总量由 http.Client.Timeout 兜底，无需再限流。
func drainProbeResponse(resp *http.Response) {
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// medianInt64 取中位数；返回 0 样本时保持 0（调用方只在采样成功后使用）。
func medianInt64(samples []int64) int64 {
	if len(samples) == 0 {
		return 0
	}
	s := append([]int64(nil), samples...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
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
