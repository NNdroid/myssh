package myssh

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// TestBadvpnUdpgwConn_WriteRead 验证 BadvpnUdpgwConn 的读写封装/解封装逻辑
func TestBadvpnUdpgwConn_WriteRead(t *testing.T) {
	// 1. 模拟底层连接
	clientPipe, serverPipe := net.Pipe()

	// 2. 模拟客户端 (BadvpnUdpgwConn)
	targetIP := net.ParseIP("1.2.3.4")
	targetPort := uint16(8080)
	conID := uint16(12345)

	badvpnConn := &BadvpnUdpgwConn{
		Conn:       clientPipe,
		targetIP:   targetIP,
		targetPort: targetPort,
		isIPv6:     false,
		conID:      conID,
		closed:     make(chan struct{}),
	}
	defer badvpnConn.Close()

	// --- 测试 Write ---
	go func() {
		payload := []byte("hello")
		n, err := badvpnConn.Write(payload)
		if err != nil {
			t.Errorf("BadvpnUdpgwConn.Write() error = %v", err)
		}
		if n != len(payload) {
			t.Errorf("BadvpnUdpgwConn.Write() = %v, want %v", n, len(payload))
		}
	}()

	// 3. 模拟服务端，验证接收到的数据
	// 读取 2 字节长度前缀
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(serverPipe, lenBuf); err != nil {
		t.Fatalf("Server failed to read length prefix: %v", err)
	}
	frameLen := binary.LittleEndian.Uint16(lenBuf)

	// 读取整个帧
	frameBuf := make([]byte, frameLen)
	if _, err := io.ReadFull(serverPipe, frameBuf); err != nil {
		t.Fatalf("Server failed to read frame body: %v", err)
	}

	// 解析帧
	// Flags(1) + ConID(2) + IP(4) + Port(2) + Payload
	expectedHeaderLen := 1 + 2 + 4 + 2
	if len(frameBuf) < expectedHeaderLen {
		t.Fatalf("Received frame too short: got %d, want at least %d", len(frameBuf), expectedHeaderLen)
	}

	flags := frameBuf[0]
	if flags != 0 {
		t.Errorf("Expected flags 0, got %d", flags)
	}

	receivedConID := binary.LittleEndian.Uint16(frameBuf[1:3])
	if receivedConID != conID {
		t.Errorf("Expected conID %d, got %d", conID, receivedConID)
	}

	receivedIP := net.IP(frameBuf[3:7])
	if !receivedIP.Equal(targetIP) {
		t.Errorf("Expected IP %s, got %s", targetIP, receivedIP)
	}

	receivedPort := binary.BigEndian.Uint16(frameBuf[7:9])
	if receivedPort != targetPort {
		t.Errorf("Expected port %d, got %d", targetPort, receivedPort)
	}

	receivedPayload := frameBuf[9:]
	if !bytes.Equal(receivedPayload, []byte("hello")) {
		t.Errorf("Expected payload 'hello', got '%s'", receivedPayload)
	}

	// --- 测试 Read ---
	go func() {
		// 模拟服务端发送响应
		respPayload := []byte("world")
		respPacket := make([]byte, 3+4+2+len(respPayload))
		respPacket[0] = 0 // flags
		binary.LittleEndian.PutUint16(respPacket[1:3], conID)
		copy(respPacket[3:7], targetIP.To4())
		binary.BigEndian.PutUint16(respPacket[7:9], targetPort)
		copy(respPacket[9:], respPayload)

		// 封装 Badvpn 帧
		respLenBuf := make([]byte, 2)
		binary.LittleEndian.PutUint16(respLenBuf, uint16(len(respPacket)))

		serverPipe.Write(respLenBuf)
		serverPipe.Write(respPacket)
	}()

	readBuf := make([]byte, 1024)
	badvpnConn.SetReadDeadline(time.Now().Add(2 * time.Second)) // 设置超时
	n, err := badvpnConn.Read(readBuf)
	if err != nil {
		t.Fatalf("BadvpnUdpgwConn.Read() error = %v", err)
	}
	if n != len("world") {
		t.Errorf("BadvpnUdpgwConn.Read() got %d bytes, want %d", n, len("world"))
	}
	if !bytes.Equal(readBuf[:n], []byte("world")) {
		t.Errorf("BadvpnUdpgwConn.Read() got payload '%s', want 'world'", readBuf[:n])
	}
}
