package myssh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type PingRequest struct {
	Id     string      `json:"id"`
	Config ProxyConfig `json:"config"`
}

// PingResult 结构化测速结果，供 Android 直接按字段渲染（着色/分类），
// 取代原先的 "123 ms" / "Error: ..." 字符串拼装。
type PingResult struct {
	Id        string `json:"id"`
	Ok        bool   `json:"ok"`
	LatencyMs int64  `json:"latencyMs"`
	Error     string `json:"error"`     // 完整错误信息（不截断）
	ErrorType string `json:"errorType"` // timeout|connrefused|tls|dns|http|other|""
}

// pingCancel 支持安卓中途取消正在进行的测速（CancelPing）。
var pingCancel atomic.Value // context.CancelFunc

// CancelPing 取消正在进行的 pingNodes 测速。
func CancelPing() {
	if f, ok := pingCancel.Load().(context.CancelFunc); ok && f != nil {
		f()
	}
}

// PingNodes 测试一组节点的真实访问延迟 (True Proxy Ping + VpnProtect)。
// 返回 []PingResult 的 JSON；解析请求失败返回 "[]"。
func pingNodes(profilesJson string, targetUrl string, timeoutMs int) string {
	var reqs []PingRequest
	if err := json.Unmarshal([]byte(profilesJson), &reqs); err != nil {
		zlog.Errorf("[Latency] 解析测速请求失败: %v", err)
		return "[]"
	}

	zlog.Infof("[Latency] 接收到测速请求，目标: %s，超时: %d ms，节点数: %d", targetUrl, timeoutMs, len(reqs))

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	pingCancel.Store(cancel)
	defer cancel()

	resCh := make(chan PingResult, len(reqs))
	var wg sync.WaitGroup
	// 控制并发度，防止同时建立太多 SSH 隧道拖垮手机 CPU
	sem := make(chan struct{}, 4)

	for _, req := range reqs {
		wg.Add(1)
		go func(r PingRequest) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			zlog.Infof("[Latency] 开始测速节点: %s", r.Id)
			latency, err := testSingleNodeTrueLatency(ctx, r.Config, targetUrl, time.Duration(timeoutMs)*time.Millisecond)
			if err != nil {
				zlog.Errorf("[Latency] 节点 %s 测速失败: %v", r.Id, err)
				resCh <- PingResult{Id: r.Id, Ok: false, Error: err.Error(), ErrorType: classifyPingError(err)}
				return
			}
			zlog.Infof("[Latency] 节点 %s 测速成功: %d ms", r.Id, latency)
			resCh <- PingResult{Id: r.Id, Ok: true, LatencyMs: latency}
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

// testSingleNodeTrueLatency 为单节点建立受保护隧道并完成一次真实 HTTP 请求，
// 返回从拨号到拿到 2xx 响应的耗时（毫秒）。耗时含 SSH 握手+隧道建立+首字节，
// 即“经该节点的真实首包延迟”，适合作为节点选择依据。
// ctx 可被 CancelPing 取消；context 超时被归类为 timeout。
func testSingleNodeTrueLatency(ctx context.Context, cfg ProxyConfig, targetUrl string, timeout time.Duration) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()

	// 1. 建立受保护的底层隧道并完成 SSH 握手
	sshClient, conn, err := DialNode(ctx, cfg, false)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	defer sshClient.Close()

	// 2. 解析测试网页的地址
	u, err := url.Parse(targetUrl)
	if err != nil {
		return 0, fmt.Errorf("url err: %w", err)
	}
	hostPort := u.Host
	if !strings.Contains(hostPort, ":") {
		if u.Scheme == "https" {
			hostPort += ":443"
		} else {
			hostPort += ":80"
		}
	}

	// 3. 通过 SSH 隧道建立到目标网页的 TCP 连接
	targetConn, err := sshClient.Dial("tcp", hostPort)
	if err != nil {
		return 0, fmt.Errorf("proxy dial err: %w", err)
	}
	defer targetConn.Close()

	// 4. 发起 HTTP 请求
	req, err := http.NewRequestWithContext(ctx, "GET", targetUrl, nil)
	if err != nil {
		return 0, err
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return targetConn, nil
			},
			DisableKeepAlives: true,
		},
		Timeout: timeout,
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("http err: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return 0, fmt.Errorf("status %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}

// classifyPingError 将底层错误归类为可读类型，供安卓 UI 着色/展示。
// 优先按错误链判定超时（net.Error），再按关键字匹配。
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
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline"):
		return "timeout"
	case strings.Contains(msg, "connection refused"), strings.Contains(msg, "connect: "):
		return "connrefused"
	case strings.Contains(msg, "x509"), strings.Contains(msg, "certificate"), strings.Contains(msg, "tls"):
		return "tls"
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "lookup"), strings.Contains(msg, "dns"):
		return "dns"
	case strings.HasPrefix(msg, "status "):
		return "http"
	default:
		return "other"
	}
}
