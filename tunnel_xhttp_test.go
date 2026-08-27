package myssh

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
)

// TestXHTTPFrameRoundTrip  info  xhttpFramedConn  info / info bytes info ，
//
//	info supportbidirectional info （client↔ info  net.Pipe）。
func TestXHTTPFrameRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	la := &net.TCPAddr{IP: net.IPv4zero, Port: 0}

	ca := newXhttpFramedConn(a, a, func() error { return nil }, la, la)
	cb := newXhttpFramedConn(b, b, func() error { return nil }, la, la)
	//  info closed info  pipe  info closed info ：close  info closed info  pipe  info ，
	//  info （ info ， info ）。
	defer func() {
		_ = a.Close()
		_ = b.Close()
		_ = ca.Close()
		_ = cb.Close()
	}()

	// a → b： info （ info  +  info  padding）
	msgAB := bytes.Repeat([]byte("A"), 5000)
	go func() {
		if _, err := ca.Write(msgAB); err != nil {
			t.Logf("ca write: %v", err)
		}
	}()
	gotAB := make([]byte, len(msgAB))
	if _, err := io.ReadFull(cb, gotAB); err != nil {
		t.Fatalf("read a→b: %v", err)
	}
	if !bytes.Equal(gotAB, msgAB) {
		t.Fatal("a→b frame round-trip mismatch")
	}

	// b → a： info
	msgBA := []byte("small-ba-payload")
	go func() {
		if _, err := cb.Write(msgBA); err != nil {
			t.Logf("cb write: %v", err)
		}
	}()
	gotBA := make([]byte, len(msgBA))
	if _, err := io.ReadFull(ca, gotBA); err != nil {
		t.Fatalf("read b→a: %v", err)
	}
	if !bytes.Equal(gotBA, msgBA) {
		t.Fatal("b→a frame round-trip mismatch")
	}
}

// TestMeekVirtualConnReorder  info  PutReadData  info 。
func TestMeekVirtualConnReorder(t *testing.T) {
	vc := newMeekVirtualConn(context.Background(), "sess", &net.TCPAddr{}, &net.TCPAddr{})
	defer vc.Close()

	//  info  seq=5（ info ）， info  seq=0（ info ）， info  "helloworld"。
	vc.PutReadData(5, []byte("world"))
	vc.PutReadData(0, []byte("hello"))

	buf := make([]byte, 10)
	if _, err := io.ReadFull(vc, buf); err != nil {
		t.Fatalf("read reassembled: %v", err)
	}
	if string(buf) != "helloworld" {
		t.Fatalf("reorder mismatch: got %q want %q", buf, "helloworld")
	}
}

// TestMeekVirtualConnClosed  info closed info  Read  info  EOF、Write  info  ErrClosedPipe。
func TestMeekVirtualConnClosed(t *testing.T) {
	vc := newMeekVirtualConn(context.Background(), "sess", &net.TCPAddr{}, &net.TCPAddr{})
	vc.Close()

	if _, err := vc.Write([]byte("x")); err != io.ErrClosedPipe {
		t.Fatalf("Write after close: got %v, want ErrClosedPipe", err)
	}
	buf := make([]byte, 4)
	if _, err := vc.Read(buf); err != io.EOF {
		t.Fatalf("Read after close: got %v, want EOF", err)
	}
}

// TestReliableBuffer  info 、 info 、Ack cleanup info 。
func TestReliableBuffer(t *testing.T) {
	rb := newReliableBuffer(1024)
	//  info （ info  cond.Wait  info ）， info  goroutine  info ，
	//  info  GetSlice  info completed info 。
	if _, err := rb.Write([]byte("abc")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	//  info  0  info （ info  Pool  info ， info ）。
	data, _, bufPtr := rb.GetSlice(0, 0, 100)
	if string(data) != "abc" {
		t.Fatalf("GetSlice: got %q want %q", data, "abc")
	}
	safelyPutBuf(xhttpFrameBufPool, bufPtr)

	// Ack=3 cleanup info ， info 。
	rb.GetSlice(3, 3, 100)
	if rb.Len() != 0 {
		t.Fatalf("after ack, Len = %d, want 0", rb.Len())
	}

	rb.Close()
	if _, err := rb.Write([]byte("x")); err != io.ErrClosedPipe {
		t.Fatalf("Write after Close: got %v, want ErrClosedPipe", err)
	}
}

// TestBoundedBufPool  info  Get/Put  info  panic  info 。
func TestBoundedBufPool(t *testing.T) {
	p := newBoundedBufPool(4, 1<<20, 256)

	b1 := p.Get()
	if b1 == nil || len(*b1) != 0 {
		t.Fatal("Get returned unexpected buffer")
	}
	*b1 = (*b1)[:16]
	p.Put(b1)

	b2 := p.Get()
	if b2 == nil {
		t.Fatal("Get returned nil after Put")
	}
	p.Put(b2)

	//  info  maxIdle  info  Put  info discarded，Get  info （ info ）， info  panic。
	for i := 0; i < 8; i++ {
		bp := p.Get()
		*bp = (*bp)[:8]
		p.Put(bp)
	}
}

// TestRetryEnqueue  info  seq  info 。
func TestRetryEnqueue(t *testing.T) {
	var q []retryChunk
	q = retryEnqueue(q, retryChunk{seq: 3, data: []byte("c")})
	q = retryEnqueue(q, retryChunk{seq: 1, data: []byte("a")})
	q = retryEnqueue(q, retryChunk{seq: 2, data: []byte("b")})

	if len(q) != 3 {
		t.Fatalf("len = %d, want 3", len(q))
	}
	want := []uint64{1, 2, 3}
	for i, c := range q {
		if c.seq != want[i] {
			t.Fatalf("q[%d].seq = %d, want %d", i, c.seq, want[i])
		}
	}
}
