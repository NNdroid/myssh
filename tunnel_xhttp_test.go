package myssh

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
)

// TestXHTTPFrameRoundTrip 验证 xhttpFramedConn 的帧封装/解封装在任意字节上往返一致，
// 且支持双向并发（客户端↔服务端各持一端 net.Pipe）。
func TestXHTTPFrameRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	la := &net.TCPAddr{IP: net.IPv4zero, Port: 0}

	ca := newXhttpFramedConn(a, a, func() error { return nil }, la, la)
	cb := newXhttpFramedConn(b, b, func() error { return nil }, la, la)
	// 先关闭底层 pipe 再关闭连接：close 帧写入已关闭的 pipe 会立即报错返回，
	// 避免两端互相等待读取而永久阻塞（生产环境对端始终在读，无此问题）。
	defer func() {
		_ = a.Close()
		_ = b.Close()
		_ = ca.Close()
		_ = cb.Close()
	}()

	// a → b：大包（触发分帧 + 动态 padding）
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

	// b → a：小包
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

// TestMeekVirtualConnReorder 验证乱序到达时 PutReadData 能正确重组为连续流。
func TestMeekVirtualConnReorder(t *testing.T) {
	vc := newMeekVirtualConn(context.Background(), "sess", &net.TCPAddr{}, &net.TCPAddr{})
	defer vc.Close()

	// 先到 seq=5（乱序），再到 seq=0（补齐），应重组为 "helloworld"。
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

// TestMeekVirtualConnClosed 验证关闭后 Read 立即返回 EOF、Write 返回 ErrClosedPipe。
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

// TestReliableBuffer 验证可靠缓冲区的写入、按偏移切片取出、Ack 清理逻辑。
func TestReliableBuffer(t *testing.T) {
	rb := newReliableBuffer(1024)
	// 小数据写入是同步的（不会触发 cond.Wait 阻塞），无需放在 goroutine 中，
	// 否则 GetSlice 可能在写入完成前读取到空缓冲区。
	if _, err := rb.Write([]byte("abc")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// 取出从偏移 0 开始的切片（返回从统一 Pool 分配的拷贝，用完需归还）。
	data, _, bufPtr := rb.GetSlice(0, 0, 100)
	if string(data) != "abc" {
		t.Fatalf("GetSlice: got %q want %q", data, "abc")
	}
	safelyPutBuf(xhttpFrameBufPool, bufPtr)

	// Ack=3 清理已确认数据后，缓冲区应为空。
	rb.GetSlice(3, 3, 100)
	if rb.Len() != 0 {
		t.Fatalf("after ack, Len = %d, want 0", rb.Len())
	}

	rb.Close()
	if _, err := rb.Write([]byte("x")); err != io.ErrClosedPipe {
		t.Fatalf("Write after Close: got %v, want ErrClosedPipe", err)
	}
}

// TestBoundedBufPool 验证带上限的缓冲池 Get/Put 不 panic 且能正常复用。
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

	// 超过 maxIdle 时 Put 仅丢弃，Get 仍能返回（新建），不应 panic。
	for i := 0; i < 8; i++ {
		bp := p.Get()
		*bp = (*bp)[:8]
		p.Put(bp)
	}
}

// TestRetryEnqueue 验证重传队列按 seq 升序有序插入。
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
