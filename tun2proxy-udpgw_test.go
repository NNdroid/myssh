package myssh

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// TestTun2proxyUdpgwConn_WriteRead 验证 UdpgwConn 的读写封装/解封装逻辑
func TestTun2proxyUdpgwConn_WriteRead(t *testing.T) {
	// 1. 模拟底层连接
	clientPipe, serverPipe := net.Pipe()

	// 2. 模拟客户端 (UdpgwConn)
	targetIP := net.ParseIP("1.2.3.4")
	targetPort := uint16(8080)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, targetPort)

	udpgwConn := &UdpgwConn{
		Conn:              clientPipe,
		addressType:       UdpgwAtypIPv4,
		targetAddressData: targetIP.To4(),
		targetPortData:    portBytes,
		closed:            make(chan struct{}),
	}
	defer udpgwConn.Close()

	// --- 测试 Write ---
	go func() {
		payload := []byte("hello")
		n, err := udpgwConn.Write(payload)
		if err != nil {
			t.Errorf("UdpgwConn.Write() error = %v", err)
		}
		if n != len(payload) {
			t.Errorf("UdpgwConn.Write() = %v, want %v", n, len(payload))
		}
	}()

	// 3. 模拟服务端，验证接收到的数据
	// 读取 2 字节长度前缀 (大端序)
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(serverPipe, lenBuf); err != nil {
		t.Fatalf("Server failed to read length prefix: %v", err)
	}
	frameLen := binary.BigEndian.Uint16(lenBuf)

	// 读取整个帧
	frameBuf := make([]byte, frameLen)
	if _, err := io.ReadFull(serverPipe, frameBuf); err != nil {
		t.Fatalf("Server failed to read frame body: %v", err)
	}

	// 解析帧
	// Flag(1) + ConnID(2) + ATYP(1) + Addr(4) + Port(2) + Payload
	expectedHeaderLen := 1 + 2 + 1 + 4 + 2
	if len(frameBuf) < expectedHeaderLen {
		t.Fatalf("Received frame too short: got %d, want at least %d", len(frameBuf), expectedHeaderLen)
	}

	flag := frameBuf[0]
	if flag != UdpgwFlagData {
		t.Errorf("Expected flag %d, got %d", UdpgwFlagData, flag)
	}

	connID := binary.BigEndian.Uint16(frameBuf[1:3])
	if connID != 1 {
		t.Errorf("Expected connID 1, got %d", connID)
	}

	atyp := frameBuf[3]
	if atyp != UdpgwAtypIPv4 {
		t.Errorf("Expected atyp %d, got %d", UdpgwAtypIPv4, atyp)
	}

	receivedIP := net.IP(frameBuf[4:8])
	if !receivedIP.Equal(targetIP) {
		t.Errorf("Expected IP %s, got %s", targetIP, receivedIP)
	}

	receivedPort := binary.BigEndian.Uint16(frameBuf[8:10])
	if receivedPort != targetPort {
		t.Errorf("Expected port %d, got %d", targetPort, receivedPort)
	}

	receivedPayload := frameBuf[10:]
	if !bytes.Equal(receivedPayload, []byte("hello")) {
		t.Errorf("Expected payload 'hello', got '%s'", receivedPayload)
	}

	// --- 测试 Read ---
	go func() {
		// 模拟服务端发送响应
		respPayload := []byte("world")
		// 响应帧格式: Flag(1) + ConnID(2) + ATYP(1) + Addr(4) + Port(2) + Payload
		respPacket := make([]byte, 1+2+1+4+2+len(respPayload))
		respPacket[0] = UdpgwFlagData
		binary.BigEndian.PutUint16(respPacket[1:3], 1) // ConnID
		respPacket[3] = UdpgwAtypIPv4
		copy(respPacket[4:8], targetIP.To4())
		binary.BigEndian.PutUint16(respPacket[8:10], targetPort)
		copy(respPacket[10:], respPayload)

		// 封装 tun2proxy 帧
		respLenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(respLenBuf, uint16(len(respPacket)))

		serverPipe.Write(respLenBuf)
		serverPipe.Write(respPacket)
	}()

	readBuf := make([]byte, 1024)
	udpgwConn.SetReadDeadline(time.Now().Add(2 * time.Second)) // 设置超时
	n, err := udpgwConn.Read(readBuf)
	if err != nil {
		t.Fatalf("UdpgwConn.Read() error = %v", err)
	}
	if n != len("world") {
		t.Errorf("UdpgwConn.Read() got %d bytes, want %d", n, len("world"))
	}
	if !bytes.Equal(readBuf[:n], []byte("world")) {
		t.Errorf("UdpgwConn.Read() got payload '%s', want 'world'", readBuf[:n])
	}
}
