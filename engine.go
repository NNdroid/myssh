package myssh

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/txthinking/socks5"
	"golang.org/x/crypto/ssh"
)

// 本文件实现引擎生命周期：AutoSSH 连接循环、DNS/SOCKS5 启停、
// keepalive 监视与资源清理。共享状态定义见 proxy.go。

// isPermanentConfigError 判定拨号错误是否为配置类永久错误（类型不存在、
// 必填字段缺失、参数非法）——这类错误重连永远不会成功，AutoSSH 应终止
// 而不是无限循环重试刷日志。
func isPermanentConfigError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, marker := range []string{
		"unsupported tunnel type",
		" is required",
		"must be ",
		"must contain ",
		"requires a ",
		"not valid for",
		"invalid ",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// startSshTProxy 启动 AutoSSH mode 引擎：启动 DNS 服务、SOCKS5 服务，
// 并后台维持 SSH tunnel。返回 0 表示启动成功，非 0 表示失败。
func startSshTProxy(configJson string) int {
	engineLifecycleMu.Lock()
	defer engineLifecycleMu.Unlock()
	stopEngine()

	PrintAndroidUserInfo()

	var cfg ProxyConfig
	if err := json.Unmarshal([]byte(configJson), &cfg); err != nil {
		zlog.Errorf("%s [Core] ❌ Failed to parse config JSON: %v", TAG, err)
		emitError(-1, "config parse failed: "+err.Error())
		emitState(StateError, err.Error())
		return -1
	}
	if err := configureIPv6EgressFromJSON(configJson); err != nil {
		zlog.Errorf("%s [IPv6-Egress] ❌ Invalid policy: %v", TAG, err)
		emitError(-1, err.Error())
		emitState(StateError, err.Error())
		return -1
	}

	var ctx context.Context
	if err := validatePerformanceConfig(cfg); err != nil {
		emitError(-1, err.Error())
		emitState(StateError, err.Error())
		return -1
	}
	mu.Lock()
	ctx, engineCancel = context.WithCancel(context.Background())
	engineCtxHolder.Store(&ctx)
	mu.Unlock()

	emitState(StateStarting, "")
	zlog.Infof("%s [Core] ==================== Starting proxy engine (AutoSSH mode) ====================", TAG)

	// 创建 DNS 服务实例
	NewLocalDnsServer(cfg.UdpgwAddr, cfg.UdpgwVersion)

	// 启动 DNS 服务
	if lds := localDnsServer.Load(); lds != nil {
		// DNS 绑定失败（端口被占、地址非法）会让 VPN 模式下所有域名解析失败，而会话仍显示
		// 「已启动」。此处只留痕不中止：DNS 挂掉不必然影响 socks5 直连，但必须让排障者看得见。
		if err := lds.Start(cfg.DnsAddr); err != nil {
			zlog.Errorf("%s [Core] ❌ Local DNS failed to start on %s: %v", TAG, cfg.DnsAddr, err)
			emitError(-4, "local DNS failed to start on "+cfg.DnsAddr+": "+err.Error())
		}
	}

	srv, err := socks5.NewClassicServer(cfg.LocalAddr, "", "", "", 0, 60)
	if err != nil {
		stopEngine()
		zlog.Errorf("%s [SOCKS5] ❌ Failed to create SOCKS5 server instance: %v", TAG, err)
		emitError(-4, err.Error())
		emitState(StateError, err.Error())
		return -4
	}

	mu.Lock()
	socksServer = srv
	mu.Unlock()

	baseHandler := &SshProxyHandler{
		ctx:          ctx,
		cfg:          cfg,
		UdpgwAddr:    cfg.UdpgwAddr, // 按 config 配置，空串则禁用 UDPGW
		UdpgwVersion: cfg.UdpgwVersion,
	}
	handler := &egressAwareSocksHandler{SshProxyHandler: baseHandler}

	if err := prepareSocksServer(ctx, srv); err != nil {
		stopEngine()
		emitError(-4, err.Error())
		return -4
	}
	serverDone := make(chan struct{})
	engineServerDone = serverDone
	taskTrack()
	go func() {
		defer taskRelease()
		defer close(serverDone)
		zlog.Infof("%s [SOCKS5] 🚀 SOCKS5 proxy service started: %s", TAG, cfg.LocalAddr)
		if err := serveSocks(ctx, srv, handler); err != nil && ctx.Err() == nil {
			zlog.Errorf("%s [SOCKS5] ❌ Service exited abnormally: %v", TAG, err)
		}
		zlog.Infof("%s [SOCKS5] 🛑 SOCKS5 service has completely stopped", TAG)
	}()

	done := make(chan struct{})
	engineDone = done
	taskTrack()
	go func() {
		defer taskRelease()
		defer close(done)

		for {
			select {
			case <-ctx.Done():
				zlog.Infof("%s [AutoSSH] Received global stop signal, daemon exiting", TAG)
				return
			default:
			}

			zlog.Infof("%s [AutoSSH] 🔄 Attempting to establish tunnel and SSH connection...", TAG)
			emitState(StateConnecting, cfg.SshAddr)
			emitNodeEvent(cfg.SshAddr, NodeEventConnecting, "")
			client, _, err := DialNode(ctx, cfg, false)
			if ctx.Err() != nil {
				if client != nil {
					client.Close()
				}
				return
			}
			if err != nil {
				zlog.Errorf("%s [AutoSSH] ❌ Connection failed: %v", TAG, err)
				emitState(StateReconnecting, err.Error())
				emitNodeEvent(cfg.SshAddr, NodeEventFailed, err.Error())
				// 配置类永久错误（类型不存在/必填缺失/参数非法）重连永远不会
				// 成功：报错误并终止重连循环，而不是每 3 秒刷一次失败。
				if isPermanentConfigError(err) {
					zlog.Errorf("%s [AutoSSH] 🛑 Permanent configuration error, giving up reconnects", TAG)
					emitError(-2, "permanent config error: "+err.Error())
					emitState(StateError, err.Error())
					mu.Lock()
					sshClient = nil
					mu.Unlock()
					return
				}
				if !waitRetry(ctx, 3*time.Second) {
					return
				}
				continue
			}

			mu.Lock()
			if ctx.Err() != nil {
				mu.Unlock()
				client.Close()
				return
			}
			sshClient = client
			mu.Unlock()
			startIPv6EgressProbe(client)
			zlog.Infof("%s [AutoSSH] ✅ SSH tunnel established successfully, global traffic taken over!", TAG)
			emitState(StateConnected, cfg.SshAddr)
			emitNodeEvent(cfg.SshAddr, NodeEventConnected, "")

			// keepalive 属于长生命周期后台任务，纳入 taskTrack 计数，
			// 保证 wgWait 能等到它退出（ctx 取消 / client 关闭后即返回）。
			connectionCtx, connectionCancel := context.WithCancel(ctx)
			taskTrack()
			go func() {
				defer taskRelease()
				maintainKeepAlive(connectionCtx, client)
			}()

			err = client.Wait()
			connectionCancel()
			if ctx.Err() != nil {
				return
			}
			zlog.Warnf("%s [AutoSSH] ⚠️ Tunnel disconnected (%v), preparing to reconnect automatically...", TAG, err)
			reason := "SSH connection closed"
			if err != nil {
				reason = err.Error()
			}
			emitState(StateReconnecting, reason)

			mu.Lock()
			sshClient = nil
			mu.Unlock()

			killActiveProxyConnections()
			udpgwMap.Range(func(k, v any) bool {
				if udpgwMap.CompareAndDelete(k, v) {
					v.(net.Conn).Close()
				}
				return true
			})

			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()

	return 0
}

// stopSshTProxy 停止一切，执行 cleanup：关闭 SSH、DNS 与 SOCKS5 服务。
func stopSshTProxy() {
	engineLifecycleMu.Lock()
	defer engineLifecycleMu.Unlock()
	stopEngine()
}

func stopEngine() {
	// 持锁只做「取快照 + 置空」，把 DNS Stop / SOCKS Shutdown / 遍历关闭
	// 连接等 I/O 全部移到锁外。旧实现全程持 mu：期间所有新建 TCP 连接都
	// 会阻塞在 TCPHandle 的 mu.Lock() 上，而关闭操作本身可能阻塞。
	mu.Lock()
	cancel := engineCancel
	engineCancel = nil
	b := context.Background()
	engineCtxHolder.Store(&b)
	lds := localDnsServer.Load()
	localDnsServer.Store(nil)
	srv := socksServer
	socksServer = nil
	client := sshClient
	sshClient = nil
	mu.Unlock()

	if cancel != nil {
		cancel()
	}

	zlog.Infof("%s [Core] Stopping resources...", TAG)
	emitState(StateStopped, "")

	if lds != nil {
		lds.Stop()
	}
	if srv != nil {
		stopSocksServer(srv)
	}
	closeQuicConnCache()
	if client != nil {
		client.Close()
	}
	if engineDone != nil {
		<-engineDone
		engineDone = nil
	}

	killActiveProxyConnections()

	udpSessionCount := 0
	udpNatMap.Range(func(key, value interface{}) bool {
		// 注意：这里 value 不一定.(*net.UDPConn)，可能是 TrackedConn
		if conn, ok := value.(net.Conn); ok {
			conn.Close()
			udpSessionCount++
		}
		udpNatMap.CompareAndDelete(key, value)
		return true
	})
	if udpSessionCount > 0 {
		zlog.Infof("%s [Core] Forcibly disconnected %d active UDP sessions", TAG, udpSessionCount)
	}

	udpgwSessionCount := 0
	udpgwMap.Range(func(key, value interface{}) bool {
		if conn, ok := value.(net.Conn); ok {
			conn.Close()
			udpgwSessionCount++
		}
		udpgwMap.CompareAndDelete(key, value)
		return true
	})
	if udpgwSessionCount > 0 {
		zlog.Infof("%s [Core] Forcibly disconnected %d UDPGW proxy sessions", TAG, udpgwSessionCount)
	}
	if engineServerDone != nil {
		<-engineServerDone
		engineServerDone = nil
	}

	zlog.Infof("%s [Core] All active SSH/Proxy connections destroyed", TAG)
}

func waitRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// maintainKeepAlive 周期发送 SSH keepalive 并监视响应延迟；
// 心跳失败/超时立即关闭 client，交给 AutoSSH 循环重建连接。
func maintainKeepAlive(ctx context.Context, client *ssh.Client) {
	// 每 18 秒一次
	ticker := time.NewTicker(18 * time.Second)
	defer ticker.Stop()

	type keepAliveResult struct {
		err      error
		duration time.Duration
	}

	for {
		select {
		case <-ctx.Done():
			// Close 掉 client 才能解除内层 goroutine 阻塞在 SendRequest 上的
			// 等待，否则引擎停止时该 goroutine 会一直挂到 TCP 层超时。
			client.Close()
			return
		case <-ticker.C:
			resCh := make(chan keepAliveResult, 1)

			go func() {
				start := time.Now()
				// send SSH 心跳
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				duration := time.Since(start)

				resCh <- keepAliveResult{
					err:      err,
					duration: duration,
				}
			}()

			select {
			case <-ctx.Done():
				client.Close()
				return

			case res := <-resCh:
				if res.err != nil {
					zlog.Warnf("%s [AutoSSH] ⚠️ Failed to send heartbeat: %v (Preparing to disconnect and rebuild)", TAG, res.err)
					client.Close()
					return
				}
				zlog.Infof("%s [AutoSSH] 💓 Heartbeat normal | Latency: %dms", TAG, res.duration.Milliseconds())

			case <-time.After(8 * time.Second):
				zlog.Warnf("%s [AutoSSH] ⚠️ Heartbeat response timed out severely (suspected network freeze), forcibly cutting off and rebuilding", TAG)
				client.Close()
				return
			}
		}
	}
}
