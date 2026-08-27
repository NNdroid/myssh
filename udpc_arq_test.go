package myssh

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- minimal net.Conn for exercising UDPCConn without a real socket ----------
type arqTestConn struct {
	once   sync.Once
	doneCh chan struct{}
}

func (c *arqTestConn) Read(p []byte) (int, error)  { <-c.doneCh; return 0, io.EOF }
func (c *arqTestConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *arqTestConn) Close() error {
	c.once.Do(func() { close(c.doneCh) })
	return nil
}
func (c *arqTestConn) LocalAddr() net.Addr              { return arqTestAddr{} }
func (c *arqTestConn) RemoteAddr() net.Addr             { return arqTestAddr{} }
func (c *arqTestConn) SetDeadline(time.Time) error      { return nil }
func (c *arqTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *arqTestConn) SetWriteDeadline(time.Time) error { return nil }

type arqTestAddr struct{}

func (arqTestAddr) Network() string { return "test" }
func (arqTestAddr) String() string  { return "test" }

func newARQTestConn() (*UDPCConn, *arqTestConn) {
	tc := &arqTestConn{doneCh: make(chan struct{})}
	c := newUDPCConn(tc, arqTestAddr{}, 1, UDPC_MAGIC_DEFAULT, "", false, nil)
	return c, tc
}

// TestUDPCConn_HandleAckSamplesRTT verifies the RTT sample feeds the estimator.
func TestUDPCConn_HandleAckSamplesRTT(t *testing.T) {
	initLoggerIfNeed()
	c, _ := newARQTestConn()
	defer c.Close()

	now := time.Now()
	c.unackedMu.Lock()
	c.unacked[7] = &unackedPacket{
		frame:     &UDPCFrame{Seq: 7},
		firstSent: now.Add(-100 * time.Millisecond),
		sentTime:  now.Add(-100 * time.Millisecond),
		rto:       500 * time.Millisecond,
		retries:   0,
	}
	c.unackedMu.Unlock()

	c.handleAck(7)

	// First sample of 100ms => rto = 3*100ms = 300ms (~), clearly != initial 500ms.
	rto := c.rttEst.RTO()
	if rto < 250*time.Millisecond || rto > 350*time.Millisecond {
		t.Fatalf("rto=%v, want ~300ms after 100ms sample", rto)
	}
}

// TestUDPCConn_HandleAckKarnNoSample enforces Karn's rule: retransmitted packets
// must NOT be used as RTT samples.
func TestUDPCConn_HandleAckKarnNoSample(t *testing.T) {
	initLoggerIfNeed()
	c, _ := newARQTestConn()
	defer c.Close()

	c.rttEst.Sample(100 * time.Millisecond) // seed: rto=300ms, hasData=true
	before := c.rttEst.RTO()

	now := time.Now()
	c.unackedMu.Lock()
	c.unacked[8] = &unackedPacket{
		frame:     &UDPCFrame{Seq: 8},
		firstSent: now.Add(-500 * time.Millisecond), // would be 500ms if sampled
		sentTime:  now.Add(-500 * time.Millisecond),
		rto:       500 * time.Millisecond,
		retries:   1, // already retransmitted => must NOT sample
	}
	c.unackedMu.Unlock()

	c.handleAck(8)
	if c.rttEst.RTO() != before {
		t.Fatalf("Karn violated: rto changed from %v to %v", before, c.rttEst.RTO())
	}
}

// TestUDPCConn_WriteUsesAdaptiveRTO checks that a freshly written packet takes
// the estimator's current RTO rather than the old fixed 500ms default.
func TestUDPCConn_WriteUsesAdaptiveRTO(t *testing.T) {
	initLoggerIfNeed()
	c, _ := newARQTestConn()
	defer c.Close()

	// Converge the estimator to a low RTT so RTO shrinks well below 500ms.
	for i := 0; i < 30; i++ {
		c.rttEst.Sample(50 * time.Millisecond)
	}
	if c.rttEst.RTO() >= 500*time.Millisecond {
		t.Fatalf("estimator did not shrink: rto=%v", c.rttEst.RTO())
	}

	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	seq := atomic.LoadUint32(&c.sendSeq) - 1
	c.unackedMu.Lock()
	pkt, ok := c.unacked[seq]
	c.unackedMu.Unlock()
	if !ok {
		t.Fatal("written packet not tracked in unacked")
	}
	if pkt.rto >= 500*time.Millisecond {
		t.Fatalf("Write used non-adaptive rto=%v (want <500ms)", pkt.rto)
	}
}
