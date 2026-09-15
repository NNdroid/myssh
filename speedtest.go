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

// SpeedTestProgressCallback reports bytes sent over the dedicated test connection.
// Phase is download, download_done, upload, or upload_done.
type SpeedTestProgressCallback interface {
	OnSpeedTestProgress(phase string, transferred, elapsedMs int64)
}

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
	return speedTestWithProgress(configJson, downUrl, upUrl, upBytes, timeoutMs, nil)
}

func speedTestWithProgress(configJson, downUrl, upUrl string, upBytes int64, timeoutMs int, progress SpeedTestProgressCallback) string {
	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(configJson), &cfg); err != nil {
		return marshalSpeedError("config unmarshal: " + err.Error())
	}
	if timeoutMs <= 0 {
		timeoutMs = 30000
	}
	if strings.TrimSpace(downUrl) == "" {
		downUrl = "https://speed.cloudflare.com/__down?bytes=10485760"
	}
	if strings.TrimSpace(upUrl) == "" {
		upUrl = "https://speed.cloudflare.com/__up"
	}
	if upBytes <= 0 {
		upBytes = 10485760
	}

	totalStart := time.Now()
	// The dial context owns the tunnel connection; keep it alive for both test phases.
	// Each HTTP phase has its own timeout below, so the aggregate needs a larger budget.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Duration(timeoutMs)*time.Millisecond)
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
		phaseCtx, phaseCancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
		defer phaseCancel()
		req, err := http.NewRequestWithContext(phaseCtx, "GET", downUrl, nil)
		if err != nil {
			return marshalPartialSpeedError(res, totalStart, "down req: "+err.Error())
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Stun/SpeedTest")
		start := time.Now()
		reportProgress(progress, "download", 0, start)
		resp, err := httpClient.Do(req)
		if err != nil {
			zlog.Errorf("[SpeedTest] down http failed: %v", err)
			return marshalPartialSpeedError(res, totalStart, "down http: "+err.Error())
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return marshalPartialSpeedError(res, totalStart, "down status: "+resp.Status)
		}
		counter := &speedProgressWriter{phase: "download", start: start, callback: progress}
		n, err := io.Copy(counter, resp.Body)
		resp.Body.Close()
		if err != nil {
			zlog.Errorf("[SpeedTest] down read failed: %v", err)
			return marshalPartialSpeedError(res, totalStart, "down read: "+err.Error())
		}
		d := time.Since(start).Seconds()
		if d <= 0 {
			d = 1e-6
		}
		res.BytesDown = n
		res.DownBps = float64(n) / d
		res.DownMbps = res.DownBps * 8 / 1e6
		reportProgress(progress, "download_done", n, start)
		zlog.Infof("[SpeedTest] down done: %d bytes in %.2fs -> %.2f Mbps", n, d, res.DownMbps)
	}

	// ── 上行 ──
	if !strings.HasPrefix(upUrl, "http://") && !strings.HasPrefix(upUrl, "https://") {
		upUrl = "http://" + upUrl
	}
	{
		phaseCtx, phaseCancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
		defer phaseCancel()
		body := make([]byte, upBytes)
		if _, err := rand.Read(body); err != nil {
			// 退化：零填充也足以测吞吐
			zlog.Warnf("[SpeedTest] rand.Read failed, fall back to zero body: %v", err)
		}
		start := time.Now()
		counter := &speedProgressReader{reader: bytes.NewReader(body), phase: "upload", start: start, callback: progress}
		req, err := http.NewRequestWithContext(phaseCtx, "POST", upUrl, counter)
		if err != nil {
			return marshalPartialSpeedError(res, totalStart, "up req: "+err.Error())
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Stun/SpeedTest")
		req.ContentLength = upBytes
		reportProgress(progress, "upload", 0, start)
		resp, err := httpClient.Do(req)
		if err != nil {
			zlog.Errorf("[SpeedTest] up http failed: %v", err)
			return marshalPartialSpeedError(res, totalStart, "up http: "+err.Error())
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			resp.Body.Close()
			return marshalPartialSpeedError(res, totalStart, "up status: "+resp.Status)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		d := time.Since(start).Seconds()
		if d <= 0 {
			d = 1e-6
		}
		res.BytesUp = counter.transferred
		res.UpBps = float64(counter.transferred) / d
		res.UpMbps = res.UpBps * 8 / 1e6
		reportProgress(progress, "upload_done", counter.transferred, start)
		zlog.Infof("[SpeedTest] up done: %d bytes in %.2fs -> %.2f Mbps", counter.transferred, d, res.UpMbps)
	}

	res.Ok = true
	res.DurationMs = time.Since(totalStart).Milliseconds()
	out, _ := json.Marshal(res)
	return string(out)
}

type speedProgressWriter struct {
	phase       string
	start       time.Time
	callback    SpeedTestProgressCallback
	transferred int64
	lastReport  time.Time
}

func (w *speedProgressWriter) Write(p []byte) (int, error) {
	w.transferred += int64(len(p))
	if w.callback != nil && time.Since(w.lastReport) >= 250*time.Millisecond {
		reportProgress(w.callback, w.phase, w.transferred, w.start)
		w.lastReport = time.Now()
	}
	return io.Discard.Write(p)
}

type speedProgressReader struct {
	reader      io.Reader
	phase       string
	start       time.Time
	callback    SpeedTestProgressCallback
	transferred int64
	lastReport  time.Time
}

func (r *speedProgressReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.transferred += int64(n)
	if r.callback != nil && time.Since(r.lastReport) >= 250*time.Millisecond {
		reportProgress(r.callback, r.phase, r.transferred, r.start)
		r.lastReport = time.Now()
	}
	return n, err
}

func reportProgress(callback SpeedTestProgressCallback, phase string, transferred int64, start time.Time) {
	if callback != nil {
		callback.OnSpeedTestProgress(phase, transferred, time.Since(start).Milliseconds())
	}
}

func marshalPartialSpeedError(res SpeedTestResult, start time.Time, msg string) string {
	res.Error = msg
	res.DurationMs = time.Since(start).Milliseconds()
	out, _ := json.Marshal(res)
	return string(out)
}

func marshalSpeedError(msg string) string {
	res := SpeedTestResult{Ok: false, Error: msg}
	out, _ := json.Marshal(res)
	return string(out)
}
