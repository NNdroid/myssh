package myssh

import (
	"net"
	"time"
)

// fakeConn is shared by transport registration tests that only need a net.Conn.
type fakeConn struct {
	closed bool
}

func (c *fakeConn) Read([]byte) (int, error)         { return 0, nil }
func (c *fakeConn) Write([]byte) (int, error)        { return 0, nil }
func (c *fakeConn) Close() error                     { c.closed = true; return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }
