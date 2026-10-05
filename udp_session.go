package myssh

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type udpSession struct {
	net.Conn
	owner        *SshProxyHandler
	lastActivity atomic.Int64
	once         sync.Once
	closeErr     error
}

func (h *SshProxyHandler) context() context.Context {
	if h.ctx != nil {
		return h.ctx
	}
	return currentEngineCtx()
}

func (h *SshProxyHandler) newUDPSession(conn net.Conn) (*udpSession, error) {
	limit := h.cfg.UdpMaxSessions
	if limit <= 0 {
		limit = 1024
	}
	if h.sessions.Add(1) > int64(limit) {
		h.sessions.Add(-1)
		conn.Close()
		return nil, fmt.Errorf("UDP session limit reached (%d)", limit)
	}
	c := &udpSession{Conn: conn, owner: h}
	c.lastActivity.Store(time.Now().UnixNano())
	return c, nil
}

func (c *udpSession) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err == nil {
		c.lastActivity.Store(time.Now().UnixNano())
	}
	return n, err
}

func (c *udpSession) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err == nil {
		c.lastActivity.Store(time.Now().UnixNano())
	}
	return n, err
}

func (c *udpSession) Close() error {
	c.once.Do(func() { c.closeErr = c.Conn.Close(); c.owner.sessions.Add(-1) })
	return c.closeErr
}

// Publish under the same lock used to cancel the engine. Late dials cannot
// insert sessions after Stop's cleanup, or attach an old SSH session to a new client.
func (h *SshProxyHandler) publishSession(m *sync.Map, key string, c net.Conn, valid func() bool) (net.Conn, bool, error) {
	mu.Lock()
	if h.context().Err() != nil || (valid != nil && !valid()) {
		mu.Unlock()
		c.Close()
		return nil, false, context.Canceled
	}
	actual, loaded := m.LoadOrStore(key, c)
	mu.Unlock()
	if loaded {
		c.Close()
	}
	return actual.(net.Conn), loaded, nil
}

func (h *SshProxyHandler) sweepUDPSessions(now time.Time, idle time.Duration, closeAll bool) {
	for _, m := range []*sync.Map{&udpNatMap, &udpgwMap} {
		m.Range(func(k, v any) bool {
			c, ok := v.(*udpSession)
			// ⚠️ 刻意**不**按 c.owner == h 过滤。两张表都是进程级单例，而回收判据是
			// 「已空闲 idle」，与会话属于哪个 handler 无关。加了 owner 过滤后，
			// SSH 重连换 handler 会让旧会话永远没人回收 —— 它们在表里躺着、
			// 计数不减、socket 不关，几次重连就把连接数顶到几十倍。
			// Close() 内部走的是 c.owner.sessions.Add(-1)，计数仍归原 handler，不受影响。
			if ok && (closeAll || now.Sub(time.Unix(0, c.lastActivity.Load())) >= idle) {
				if m.CompareAndDelete(k, c) {
					c.Close()
				}
			}
			return true
		})
	}
}

func (h *SshProxyHandler) reapUDPSessions(ctx context.Context) {
	idle := time.Duration(h.cfg.UdpIdleTimeoutSec) * time.Second
	if idle <= 0 {
		idle = 60 * time.Second
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer h.sweepUDPSessions(time.Now(), idle, true)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			h.sweepUDPSessions(now, idle, false)
		}
	}
}
