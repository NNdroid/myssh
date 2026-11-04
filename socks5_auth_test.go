package myssh

import (
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/txthinking/socks5"
)

// 本地 SOCKS5 入站认证（RFC 1929）的配置校验与协商行为。
// 协商测试直接对 Server.Negotiate 喂字节 —— 这正是 serveSocks 每个连接
// 实际调用的入口（socks_server.go），不需要真的起监听。
// 注意 net.Pipe 是同步管道：服务端 goroutine 的每次 Write 都要等测试侧
// Read 到达才能返回，所以读写顺序必须严格按协议交替。

func TestValidateSocks5AuthConfig(t *testing.T) {
	initLoggerIfNeed()

	// 都为空 = 免认证（旧行为），合法
	assert.NoError(t, validateSocks5AuthConfig(ProxyConfig{}))
	// 成对非空 = 启用认证，合法
	assert.NoError(t, validateSocks5AuthConfig(ProxyConfig{Socks5AuthUser: "u", Socks5AuthPass: "p"}))
	// 只填一个 = 配置错误，拒绝启动
	err := validateSocks5AuthConfig(ProxyConfig{Socks5AuthUser: "u"})
	assert.ErrorContains(t, err, "must be set together")
	assert.True(t, isPermanentConfigError(err), "单边凭据应归类为永久配置错误，AutoSSH 不重试")
	err = validateSocks5AuthConfig(ProxyConfig{Socks5AuthPass: "p"})
	assert.ErrorContains(t, err, "must be set together")
}

// negotiate 走一遍完整协商：发方法请求 → 读方法应答 →（若被要求）发 RFC 1929
// 子协商 → 读子协商应答。closeAfterReply 用于「客户端只提供 0x00 但服务端要求
// 认证」的场景：服务端随后还有第二次 Write + 一次 Read，主动断开让它以错误收场，
// 否则测试会永远阻塞在 <-errCh。
func negotiate(t *testing.T, server *socks5.Server, clientMethods []byte, user, pass string, closeAfterReply bool) (chosen, upStatus byte, err error) {
	t.Helper()
	c1, c2 := net.Pipe()
	errCh := make(chan error, 1)
	go func() { errCh <- server.Negotiate(c2) }()

	req := append([]byte{5, byte(len(clientMethods))}, clientMethods...)
	go func() { _, _ = c1.Write(req) }()

	rep := make([]byte, 2)
	if _, err := io.ReadFull(c1, rep); err != nil {
		t.Fatalf("read method reply: %v", err)
	}
	chosen = rep[1]
	assert.Equal(t, byte(5), rep[0], "应答首字节应为 VER=5")

	if chosen == socks5.MethodUsernamePassword {
		upReq := append([]byte{1, byte(len(user))}, []byte(user)...)
		upReq = append(upReq, byte(len(pass)))
		upReq = append(upReq, []byte(pass)...)
		go func() { _, _ = c1.Write(upReq) }()
		upRep := make([]byte, 2)
		if _, err := io.ReadFull(c1, upRep); err != nil {
			t.Fatalf("read userpass reply: %v", err)
		}
		upStatus = upRep[1]
	}
	if closeAfterReply {
		c1.Close()
	}
	err = <-errCh
	c2.Close()
	return chosen, upStatus, err
}

func TestSocks5NegotiateRFC1929(t *testing.T) {
	initLoggerIfNeed()

	t.Run("成对凭据启用认证且正确凭据协商成功", func(t *testing.T) {
		srv, err := socks5.NewClassicServer("127.0.0.1:10808", "", "alice", "s3cret", 0, 60)
		assert.NoError(t, err)
		chosen, status, err := negotiate(t, srv, []byte{socks5.MethodUsernamePassword}, "alice", "s3cret", false)
		assert.NoError(t, err)
		assert.Equal(t, socks5.MethodUsernamePassword, chosen, "user/pass 非空时服务端必须选择 0x02")
		assert.Equal(t, byte(0x00), status, "正确凭据应回 STATUS=0x00")
	})

	t.Run("错误凭据被拒", func(t *testing.T) {
		srv, err := socks5.NewClassicServer("127.0.0.1:10808", "", "alice", "s3cret", 0, 60)
		assert.NoError(t, err)
		_, status, err := negotiate(t, srv, []byte{socks5.MethodUsernamePassword}, "alice", "wrong", false)
		assert.Error(t, err)
		assert.Equal(t, byte(0x01), status, "错误凭据应回 STATUS=0x01")
	})

	t.Run("双空凭据保持免认证旧行为", func(t *testing.T) {
		srv, err := socks5.NewClassicServer("127.0.0.1:10808", "", "", "", 0, 60)
		assert.NoError(t, err)
		chosen, _, err := negotiate(t, srv, []byte{socks5.MethodNone}, "", "", false)
		assert.NoError(t, err)
		assert.Equal(t, socks5.MethodNone, chosen)
	})

	t.Run("单边凭据被库静默降级为免认证_这正是配置层要拦的", func(t *testing.T) {
		// 文档化 txthinking/socks5 的行为：user 非空 pass 空 → MethodNone，
		// 配置者以为开了认证实际没开 —— validateSocks5AuthConfig 因此拒绝单边配置。
		srv, err := socks5.NewClassicServer("127.0.0.1:10808", "", "alice", "", 0, 60)
		assert.NoError(t, err)
		chosen, _, err := negotiate(t, srv, []byte{socks5.MethodNone}, "", "", false)
		assert.NoError(t, err)
		assert.Equal(t, socks5.MethodNone, chosen)
	})

	t.Run("客户端只提供免认证方法但服务端要求认证", func(t *testing.T) {
		srv, err := socks5.NewClassicServer("127.0.0.1:10808", "", "alice", "s3cret", 0, 60)
		assert.NoError(t, err)
		chosen, _, err := negotiate(t, srv, []byte{socks5.MethodNone}, "", "", true)
		assert.Error(t, err, "不支持服务端要求的认证方式时协商必须失败")
		assert.Equal(t, socks5.MethodUnsupportAll, chosen, "应先回 0xFF 表示不接受客户端方法")
	})
}
