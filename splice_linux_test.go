//go:build linux || android

package myssh

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestSpliceTrackedDataAndStatistics(t *testing.T) {
	w, src := regressionTCPPair(t)
	dst, sink := regressionTCPPair(t)
	source := WrapConn(src, "splice-source.test").(*TrackedConn)
	destination := WrapConn(dst, "splice-destination.test").(*TrackedConn)
	defer source.Close()
	defer destination.Close()
	payload := bytes.Repeat([]byte("splice"), 65536)
	writeDone := make(chan error, 1)
	go func() { err := writeFull(w, payload); w.CloseWrite(); writeDone <- err }()
	type result struct {
		n       int64
		err     error
		handled bool
	}
	done := make(chan result, 1)
	go func() {
		n, err, handled := trySplice(destination, source)
		dst.CloseWrite()
		done <- result{n, err, handled}
	}()
	got, err := io.ReadAll(sink)
	if err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil || !r.handled || r.n != int64(len(payload)) || !bytes.Equal(got, payload) {
		t.Fatalf("splice: %+v bytes=%d", r, len(got))
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if source.info.ReadBytes.Load() != uint64(len(payload)) || destination.info.WriteBytes.Load() != uint64(len(payload)) {
		t.Fatal("splice bypassed traffic counters")
	}
}

func TestSpliceReadDeadline(t *testing.T) {
	_, src := regressionTCPPair(t)
	dst, _ := regressionTCPPair(t)
	src.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	_, err, handled := trySplice(dst, src)
	ne, ok := err.(net.Error)
	if !handled || !ok || !ne.Timeout() {
		t.Fatalf("handled=%v error=%v", handled, err)
	}
}

func TestSpliceBackpressureWriteDeadline(t *testing.T) {
	w, src := regressionTCPPair(t)
	dst, sink := regressionTCPPair(t)
	dst.SetWriteBuffer(1024)
	sink.SetReadBuffer(1024)
	dst.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	writeDone := make(chan struct{})
	go func() { writeFull(w, make([]byte, 8*1024*1024)); close(writeDone) }()
	n, err, handled := trySplice(dst, src)
	src.Close()
	w.Close()
	<-writeDone
	ne, ok := err.(net.Error)
	if !handled || !ok || !ne.Timeout() || n == 0 {
		t.Fatalf("n=%d handled=%v error=%v", n, handled, err)
	}
}

func TestSpliceDoesNotBypassProtocolWrapper(t *testing.T) {
	w, src := regressionTCPPair(t)
	defer w.Close()
	dst, _ := regressionTCPPair(t)
	if _, _, handled := trySplice(dst, &ctxCloseConn{Conn: src}); handled {
		t.Fatal("unknown wrapper was bypassed")
	}
}
