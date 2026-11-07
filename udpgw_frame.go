package myssh

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// readUdpgwFrame 读取「2 字节帧长前缀 + 帧体」一帧到 bodyBuf，返回帧体长度。
// tun2proxy 用大端、badvpn 用小端，由 byteOrder 决定。
//
// 主动关闭（closed 广播）后返回 io.EOF 而不是底层读错误：停机/会话清理时
// Close 会立刻解除阻塞在管道上的 Read，把那次返回当 ERROR 刷日志，会把正常
// 清理淹没成故障现场——两份协议实现曾在这里漂移（badvpn 侧漏了该抑制），
// 抽成公共 helper 统一语义。
//
// 帧长超出 bodyBuf 容量时报错（协议上限 65535，异常包按错误处理触发上层
// 重建会话，防 OOM）。pLen==0 不在这里处理，由调用方按各自协议语义跳过。
func readUdpgwFrame(c net.Conn, closed <-chan struct{}, bodyBuf []byte, byteOrder binary.ByteOrder) (int, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		select {
		case <-closed:
			return 0, io.EOF
		default:
		}
		zlog.Errorf("%s [UDPGW-Frame] ❌ Read length prefix failed: %v", TAG, err)
		return 0, err
	}
	pLen := int(byteOrder.Uint16(lenBuf[:]))
	if pLen > len(bodyBuf) {
		return 0, fmt.Errorf("udpgw frame too large: %d (buffer %d)", pLen, len(bodyBuf))
	}
	if _, err := io.ReadFull(c, bodyBuf[:pLen]); err != nil {
		select {
		case <-closed:
			return 0, io.EOF
		default:
		}
		zlog.Errorf("%s [UDPGW-Frame] ❌ Read frame body (%d bytes) failed: %v", TAG, pLen, err)
		return 0, err
	}
	return pLen, nil
}
