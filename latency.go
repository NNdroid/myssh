package myssh

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PingRequest struct {
	Id     string      `json:"id"`
	Config ProxyConfig `json:"config"`
}

type PingResponse struct {
	Id     string `json:"id"`
	Result string `json:"result"`
}

// PingNodes 测试一组节点的真实网页访问延迟 (True Proxy Ping + VpnProtect)
func PingNodes(profilesJson string, targetUrl string, timeoutMs int) string {
	var reqs []PingRequest
	if err := json.Unmarshal([]byte(profilesJson), &reqs); err != nil {
		return "[]"
	}

	zlog.Infof("[Latency] 接收到测速请求，目标: %s，超时: %d ms，节点数: %d", targetUrl, timeoutMs, len(reqs))

	resCh := make(chan PingResponse, len(reqs))
	var wg sync.WaitGroup
	// 控制并发度，防止同时建立太多 SSH 隧道拖垮手机 CPU
	sem := make(chan struct{}, 4)

	for _, req := range reqs {
		wg.Add(1)
		go func(r PingRequest) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			start := time.Now()
			zlog.Infof("[Latency] 开始测速节点: %s", r.Id)
			err := testSingleNodeTrueLatency(r.Config, targetUrl, time.Duration(timeoutMs)*time.Millisecond)
			latency := time.Since(start).Milliseconds()

			var resultStr string
			if err != nil {
				zlog.Errorf("[Latency] 节点 %s 测速失败: %v", r.Id, err)
				// 简化错误信息供前端展示
				errMsg := err.Error()
				if len(errMsg) > 20 {
					errMsg = errMsg[:20] + "..."
				}
				resultStr = fmt.Sprintf("Error: %s", errMsg)
			} else {
				zlog.Infof("[Latency] 节点 %s 测速成功: %d ms", r.Id, latency)
				resultStr = strconv.FormatInt(latency, 10) + " ms"
			}
			resCh <- PingResponse{Id: r.Id, Result: resultStr}
		}(req)
	}

	wg.Wait()
	close(resCh)

	var resps []PingResponse
	for resp := range resCh {
		resps = append(resps, resp)
	}

	out, _ := json.Marshal(resps)
	return string(out)
}

func testSingleNodeTrueLatency(cfg ProxyConfig, targetUrl string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 1. 建立受 VpnService.protect 保护的底层隧道
	// dialTunnel 内部使用 dialProtected，确保绕过 Android VPN 虚拟网卡
	conn, err := dialTunnel(ctx, cfg)
	if err != nil {
		return fmt.Errorf("tunnel err: %v", err)
	}
	// 确保在任何情况下最终都会关闭底层连接
	defer conn.Close()

	// 2. 执行 SSH 握手 (复用 proxy.go 中的 dialSSH 辅助函数)
	sshClient, err := dialSSH(ctx, conn, cfg, false) // 修改这里，启用指纹校验，与实际 VPN 逻辑一致
	if err != nil {
		return fmt.Errorf("ssh err: %v", err)
	}
	defer sshClient.Close()

	// 4. 解析测试网页的域名
	u, err := url.Parse(targetUrl)
	if err != nil {
		return fmt.Errorf("url err")
	}
	hostPort := u.Host
	if !strings.Contains(hostPort, ":") {
		if u.Scheme == "https" {
			hostPort += ":443"
		} else {
			hostPort += ":80"
		}
	}

	// 5. 通过 SSH 隧道建立到目标网页的 TCP 连接
	targetConn, err := sshClient.Dial("tcp", hostPort)
	if err != nil {
		return fmt.Errorf("proxy dial err")
	}
	defer targetConn.Close()

	// 6. 发起 HTTP 请求
	req, err := http.NewRequestWithContext(ctx, "GET", targetUrl, nil)
	if err != nil {
		return err
	}

	// 利用自定义的 Transport 直接走代理拿到的 targetConn
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
		return fmt.Errorf("http err")
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	return nil
}
