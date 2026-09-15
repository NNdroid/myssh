package myssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// SpeedTestResult 是 speedTest 的结构化返回（字节/秒 + 折算 Mbps）。
type SpeedTestResult struct {
	Ok         bool    `json:"ok"`
	DownBps    float64 `json:"downBps"`
	UpBps      float64 `json:"upBps"`
	DownMbps   float64 `json:"downMbps"`
	UpMbps     float64 `json:"upMbps"`
	BytesDown  int64   `json:"bytesDown"`
	BytesUp    int64   `json:"bytesUp"`
	DurationMs int64   `json:"durationMs"`
	Error      string  `json:"error"`
}

// speedTest 经节点链路测真实带宽：下行 GET downUrl，上行 POST upUrl（body=upBytes 随机字节）。
// 与 pingNodes 同理走 DialNode 建立 SSH 隧道，再 sshClient.Dial("tcp", addr) 把 HTTP 流量导进隧道，
// 因此测到的是“本机→节点→出口”的隧道吞吐，而不是直连本机网卡。
func speedTest(configJson, downUrl, upUrl string, upBytes int64, timeoutMs int) string {
	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(configJson), &cfg); err != nil {
		return marshalSpeedError("config unmarshal: " + err.Error())
	}
	if timeoutMs <= 0 {
		timeoutMs = 30000
	}
	if strings.TrimSpace(downUrl) == "" {
		downUrl = "https://speed.cloudflare.com/__down?bytes=104857600"
	}
	if strings.TrimSpace(upUrl) == "" {
		upUrl = "https://speed.cloudflare.com/__up"
	}
	if upBytes <= 0 {
		upBytes = 10485760
	}

	totalStart := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	zlog.Infof("[SpeedTest] dial node start: down=%s up=%s upBytes=%d timeout=%dms", downUrl, upUrl, upBytes, timeoutMs)

	sshClient, conn, err := DialNode(ctx, cfg, true)
	if err != nil {
		zlog.Errorf("[SpeedTest] dial node failed: %v", err)
		return marshalSpeedError("dial node: " + err.Error())
	}
	defer conn.Close()
	defer sshClient.Close()

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return sshClient.Dial("tcp", addr)
			},
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: time.Duration(timeoutMs) * time.Millisecond,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: time.Duration(timeoutMs) * time.Millisecond,
	}

	res := SpeedTestResult{}

	// ── 下行 ──
	if !strings.HasPrefix(downUrl, "http://") && !strings.HasPrefix(downUrl, "https://") {
		downUrl = "http://" + downUrl
	}
	{
		req, err := http.NewRequestWithContext(ctx, "GET", downUrl, nil)
		if err != nil {
			return marshalSpeedError("down req: " + err.Error())
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Stun/SpeedTest")
		start := time.Now()
		resp, err := httpClient.Do(req)
		if err != nil {
			zlog.Errorf("[SpeedTest] down http failed: %v", err)
			return marshalSpeedError("down http: " + err.Error())
		}
		n, err := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err != nil {
			zlog.Errorf("[SpeedTest] down read failed: %v", err)
			return marshalSpeedError("down read: " + err.Error())
		}
		d := time.Since(start).Seconds()
		if d <= 0 {
			d = 1e-6
		}
		res.BytesDown = n
		res.DownBps = float64(n) / d
		res.DownMbps = res.DownBps * 8 / 1e6
		zlog.Infof("[SpeedTest] down done: %d bytes in %.2fs -> %.2f Mbps", n, d, res.DownMbps)
	}

	// ── 上行 ──
	if !strings.HasPrefix(upUrl, "http://") && !strings.HasPrefix(upUrl, "https://") {
		upUrl = "http://" + upUrl
	}
	{
		body := make([]byte, upBytes)
		if _, err := rand.Read(body); err != nil {
			// 退化：零填充也足以测吞吐
			zlog.Warnf("[SpeedTest] rand.Read failed, fall back to zero body: %v", err)
		}
		req, err := http.NewRequestWithContext(ctx, "POST", upUrl, bytes.NewReader(body))
		if err != nil {
			return marshalSpeedError("up req: " + err.Error())
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Stun/SpeedTest")
		req.ContentLength = upBytes
		start := time.Now()
		resp, err := httpClient.Do(req)
		if err != nil {
			zlog.Errorf("[SpeedTest] up http failed: %v", err)
			return marshalSpeedError("up http: " + err.Error())
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		d := time.Since(start).Seconds()
		if d <= 0 {
			d = 1e-6
		}
		res.BytesUp = upBytes
		res.UpBps = float64(upBytes) / d
		res.UpMbps = res.UpBps * 8 / 1e6
		zlog.Infof("[SpeedTest] up done: %d bytes in %.2fs -> %.2f Mbps", upBytes, d, res.UpMbps)
	}

	res.Ok = true
	res.DurationMs = time.Since(totalStart).Milliseconds()
	out, _ := json.Marshal(res)
	return string(out)
}

func marshalSpeedError(msg string) string {
	res := SpeedTestResult{Ok: false, Error: msg}
	out, _ := json.Marshal(res)
	return string(out)
}
