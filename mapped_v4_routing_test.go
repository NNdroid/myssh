package myssh

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCtxCloseConnKeepsPacketConnInterface 是 QUIC/KCP 隧道的回归保护。
//
// ctxCloseConn 内嵌的是 net.Conn **接口**，其 promoted 方法集里没有 ReadFrom/WriteTo，
// 所以它不满足 net.PacketConn。而 quic 与 kcptun 都注册为 "udp" 网络：dialTunnel 先
// 交出 *net.UDPConn，紧接着被 watchEngineCtx 包一层，handler 里紧接着做
// `baseConn.(*net.UDPConn)` / `baseConn.(net.PacketConn)` 断言——两者必然失败。
//
// 结果不只是隧道不通：报错文案含 "requires a "，正好命中 isPermanentConfigError，
// 引擎把它判定为配置错误而**永久放弃重连**。
// packetTestConn 给一个安全的 PacketConn：fakeConn 的 Close 不碰内核 fd，
// 而 watchEngineCtx 的监视 goroutine 在 ctx 取消时确实会调 Close。
type packetTestConn struct{ fakeConn }

func (c *packetTestConn) ReadFrom(p []byte) (int, net.Addr, error) { return 0, &net.UDPAddr{}, nil }
func (c *packetTestConn) WriteTo(b []byte, addr net.Addr) (int, error)       { return len(b), nil }

func TestCtxCloseConnKeepsPacketConnInterface(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // 让 watchEngineCtx 的监视 goroutine 退出，避免 goleak 报泄漏

	wrapped := watchEngineCtx(ctx, &packetTestConn{})

	// 与 tunnel_quic.go / tunnel_kcptun.go 里的断言完全相同的表达式。
	// watchEngineCtx 的返回类型是 net.Conn，所以只能是运行期断言——但断言的正是
	// handler 里那句决定隧道生死的判断。
	pc, ok := wrapped.(net.PacketConn)
	require.True(t, ok, "watchEngineCtx must preserve net.PacketConn")
	require.NotNil(t, pc)

	// 代理不能是空转。
	_, err := pc.WriteTo([]byte("x"), &net.UDPAddr{})
	require.NoError(t, err)
	n, addr, err := pc.ReadFrom(make([]byte, 16))
	require.NoError(t, err)
	require.Equal(t, 0, n)
	require.NotNil(t, addr)
}

// TestCtxCloseConnPacketDelegation 确认代理不是空转：底层不是 PacketConn 时要报
// 可诊断的错误，而不是 panic 或返回一个假地址。
func TestCtxCloseConnPacketDelegation(t *testing.T) {
	plain := &ctxCloseConn{Conn: &net.TCPConn{}, closeCh: make(chan struct{})}

	_, addr, err := plain.ReadFrom(make([]byte, 16))
	require.Error(t, err)
	assert.Nil(t, addr)

	_, err = plain.WriteTo([]byte("x"), nil)
	require.Error(t, err)
}

func TestIsIP4Form(t *testing.T) {
	cases := []struct {
		str  string
		want bool
	}{
		{"1.2.3.4", true},
		{"::ffff:1.2.3.4", true}, // 4-in-6：Is4() 返回 false 的映射形态
		{"::ffff:0:0", true},     // 退化映射地址，同样是 4-in-6
		{"::1", false},
		{"2001:db8::1", false},
		{"::", false},
	}
	for _, c := range cases {
		addr, err := netip.ParseAddr(c.str)
		require.NoError(t, err, c.str)
		assert.Equal(t, c.want, isIP4Form(addr), c.str)
	}
}

// TestNonProxyableMappedV4：四个 Is* 判定都按存储形态解释，4-in-6 一律返回 false。
// 不先归一到 4 形态，映射形态的回环/组播地址会穿过直连判定去走代理。
func TestNonProxyableMappedV4(t *testing.T) {
	assert.True(t, nonProxyable(mustAddr(t, "::ffff:127.0.0.1")), "mapped loopback")
	assert.True(t, nonProxyable(mustAddr(t, "::ffff:224.0.0.1")), "mapped multicast")
	assert.True(t, nonProxyable(mustAddr(t, "::ffff:169.254.1.1")), "mapped link-local")
	assert.True(t, nonProxyable(mustAddr(t, "::ffff:0.0.0.0")), "mapped unspecified")
	assert.True(t, nonProxyable(mustAddr(t, "::1")), "pure v6 loopback")
	assert.True(t, nonProxyable(mustAddr(t, "ff02::1")), "pure v6 multicast")

	assert.False(t, nonProxyable(mustAddr(t, "2001:db8::1")), "pure v6 global")
	assert.False(t, nonProxyable(mustAddr(t, "::ffff:8.8.8.8")), "mapped public stays proxyable")
	assert.False(t, nonProxyable(mustAddr(t, "8.8.8.8")), "pure v4 public stays proxyable")
}

// TestMatchNetIPMappedV4：geoip 的 4 字节前缀只进 v4Root。旧实现用 Is4() 分流，
// 4-in-6 会落到 v6 分支——同一条 10.0.0.0/8 规则在纯 v4 形态命中、在映射形态
// 静默放行去走代理。
func TestMatchNetIPMappedV4(t *testing.T) {
	path := writeRuleFile(t, "geoip.dat", buildGeoIPList(t, []string{"private"}))
	r := newGeoRouter()
	n, err := r.LoadGeoIP(path, []string{"private"})
	require.NoError(t, err)
	assert.NotZero(t, n, "fixture must insert at least one subnet")

	assert.True(t, r.MatchNetIP(mustAddr(t, "10.1.2.3")), "pure v4 form")
	assert.True(t, r.MatchNetIP(mustAddr(t, "::ffff:10.1.2.3")), "4-in-6 form must match the same rule")

	assert.False(t, r.MatchNetIP(mustAddr(t, "192.168.1.1")), "outside the rule")
	assert.False(t, r.MatchNetIP(mustAddr(t, "2001:db8::1")), "v6 stays in the v6 trie")
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	require.NoError(t, err, s)
	return a
}
