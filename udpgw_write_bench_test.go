package myssh

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
)

type discardFrameConn struct {
	net.Conn
	writes int
}

func (c *discardFrameConn) Write(p []byte) (int, error) { c.writes++; return len(p), nil }

func BenchmarkBadvpnFrameWrite(b *testing.B) {
	sink := &discardFrameConn{}
	c := &BadvpnUdpgwConn{Conn: sink, targetIP: net.IPv4(1, 2, 3, 4), targetPort: 8080, conID: 1, closed: make(chan struct{})}
	payload := make([]byte, 1400)
	c.Write(payload)
	sink.writes = 0
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(sink.writes)/float64(b.N), "writes/packet")
}

type shortFrameConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *shortFrameConn) Write(p []byte) (int, error) {
	if len(p) > 7 {
		p = p[:7]
	}
	return c.buf.Write(p)
}

func TestUDPGWConcurrentShortWrites(t *testing.T) {
	for _, badvpn := range []bool{false, true} {
		sink := &shortFrameConn{}
		var writer io.Writer
		if badvpn {
			writer = &BadvpnUdpgwConn{Conn: sink, targetIP: net.IPv4(1, 2, 3, 4), targetPort: 8080, conID: 1, closed: make(chan struct{})}
		} else {
			writer = &UdpgwConn{Conn: sink, addressType: UdpgwAtypIPv4, targetAddressData: []byte{1, 2, 3, 4}, targetPortData: []byte{0x1f, 0x90}, closed: make(chan struct{})}
		}
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				p := bytes.Repeat([]byte{byte(i)}, 64)
				if n, err := writer.Write(p); err != nil || n != len(p) {
					t.Errorf("write n=%d err=%v", n, err)
				}
			}(i)
		}
		wg.Wait()
		seen := make(map[byte]bool)
		for sink.buf.Len() > 0 {
			var prefix [2]byte
			if _, err := io.ReadFull(&sink.buf, prefix[:]); err != nil {
				t.Fatal(err)
			}
			n := binary.BigEndian.Uint16(prefix[:])
			header := 10
			if badvpn {
				n = binary.LittleEndian.Uint16(prefix[:])
				header = 9
			}
			body := make([]byte, n)
			if _, err := io.ReadFull(&sink.buf, body); err != nil {
				t.Fatal(err)
			}
			if len(body) != header+64 {
				t.Fatalf("bad frame length %d", len(body))
			}
			p := body[header:]
			if !bytes.Equal(p, bytes.Repeat(p[:1], 64)) || seen[p[0]] {
				t.Fatal("interleaved or duplicate frame")
			}
			seen[p[0]] = true
		}
		if len(seen) != 16 {
			t.Fatal("missing frames")
		}
	}
}
