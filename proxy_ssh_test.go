package myssh

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// fakeSSHConn 是 ssh.Conn 的最小实现，仅用于验证 triggerSSHReconnect
// 是否真的调用了 client.Close()（真实握手在单测里会带来 net.Pipe 死锁）。
type fakeSSHConn struct {
	closed int32
}

func (f *fakeSSHConn) User() string          { return "test" }
func (f *fakeSSHConn) SessionID() []byte     { return []byte("sid") }
func (f *fakeSSHConn) ClientVersion() []byte { return []byte("SSH-2.0-Test") }
func (f *fakeSSHConn) ServerVersion() []byte { return []byte("SSH-2.0-Test") }
func (f *fakeSSHConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}
}
func (f *fakeSSHConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}
func (f *fakeSSHConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return true, nil, nil
}
func (f *fakeSSHConn) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	return nil, nil, nil
}
func (f *fakeSSHConn) Close() error {
	atomic.StoreInt32(&f.closed, 1)
	return nil
}
func (f *fakeSSHConn) Wait() error { return nil }

func countSyncedMap(m *sync.Map) int {
	n := 0
	m.Range(func(_, _ interface{}) bool {
		n++
		return true
	})
	return n
}

func TestIsSSHConnectionLost(t *testing.T) {
	initLoggerIfNeed()

	base := errors.New("ssh: unexpected packet in response to channel open: <nil>")

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"exact message", base, true},
		{"wrapped error", fmt.Errorf("dial udpgw failed: %w", base), true},
		{"channel rejected is NOT connection lost", errors.New("ssh: rejected: administratively prohibited"), false},
		{"ordinary i/o timeout", errors.New("i/o timeout"), false},
		{"EOF", io.EOF, false},
		{"empty error", errors.New(""), false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, isSSHConnectionLost(c.err))
		})
	}
}

func TestTriggerSSHReconnectNilClient(t *testing.T) {
	initLoggerIfNeed()

	// 关键路径：sshClient 为 nil 时函数应安全提前返回（不 panic、不清理 map）。
	// 这是既有的安全守卫：没连上就没有可重连的 client，stale 连接由后续真实重连负责清理。
	mu.Lock()
	sshClient = nil
	mu.Unlock()

	assert.NotPanics(t, func() {
		triggerSSHReconnect()
	})

	mu.Lock()
	assert.Nil(t, sshClient, "sshClient must remain nil")
	mu.Unlock()
}

func TestTriggerSSHReconnectClosesClientAndClearsMaps(t *testing.T) {
	initLoggerIfNeed()

	fake := &fakeSSHConn{}
	chans := make(chan ssh.NewChannel)
	reqs := make(chan *ssh.Request)
	client := ssh.NewClient(fake, chans, reqs)
	// ssh.NewClient 会起两个 goroutine 阻塞在 chans/reqs 上，测试结束需关闭以免 goroutine 泄漏。
	defer close(chans)
	defer close(reqs)

	// map 中存放独立的连接（管道 B / C），用于验证被关闭。
	srvU, cliU := net.Pipe()
	_ = srvU
	srvT, cliT := net.Pipe()
	_ = srvT

	mu.Lock()
	sshClient = client
	udpgwMap.Store("u1", cliU)
	tcpConnMap.Store("t1", cliT)
	mu.Unlock()

	triggerSSHReconnect()

	mu.Lock()
	assert.Nil(t, sshClient, "sshClient must be set to nil after reconnect trigger")
	mu.Unlock()

	assert.Equal(t, 0, countSyncedMap(&udpgwMap), "udpgwMap must be drained")
	assert.Equal(t, 0, countSyncedMap(&tcpConnMap), "tcpConnMap must be drained")

	assert.Equal(t, int32(1), atomic.LoadInt32(&fake.closed), "old ssh client Close() must be invoked")

	// map 中存放的连接应已被关闭。
	_, err := cliU.Read(make([]byte, 1))
	assert.Error(t, err, "udpgw conn should be closed")
	_, err = cliT.Read(make([]byte, 1))
	assert.Error(t, err, "tcp conn should be closed")
}

// 确保本文件在非测试构建下也能安静编译（zap 仅测试引用）。
var _ = zap.NewNop
