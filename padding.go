package myssh

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"sync"
)

var paddingGarbage [4096]byte
var paddingWritePool = sync.Pool{
	New: func() interface{} {
		//  info  chunk  info  1MB (1048576)
		// Header(6) + Padding( info  512)
		//  info  1048576 + 1024 = 1049600 bytes， info
		buf := make([]byte, 1049600)
		return &buf
	},
}

func init() {
	if _, err := rand.Read(paddingGarbage[:]); err != nil {
		zlog.Warnf("%s [Init] Failed to seed padding garbage: %v", TAG, err)
	}
}

// info 。
//
// info ， info / info ， info 。
// info  crypto/rand.Read（ info ）， info 、 info  1MB  info
// info  syscall  info 。 info  math/rand/v2  info （ info ）， info ，
// info （ info ）。
func fastRand(max int) int {
	return mrand.IntN(max)
}

// calculatePadding  info
//
//	info ： info  +  info
func calculatePadding(dataLen int) int {
	var targetPad int

	//  info
	switch {
	case dataLen < 128:
		//  info （ info 、 info ）： info ， info  128 ~ 384 bytes
		targetPad = 128 + fastRand(256)
	case dataLen < 512:
		//  info （ info ）： info ， info  64 ~ 192 bytes
		targetPad = 64 + fastRand(128)
	case dataLen < 8192:
		//  info ： info ， info  16 ~ 64 bytes
		targetPad = 16 + fastRand(48)
	default:
		//  info data stream（ info ）
		targetPad = 0
	}

	//  info  (Block Alignment)
	//  info  ( info  + Padding)  info  64 bytes info ，
	//  info  AES/ChaCha20  info 。
	totalLen := dataLen + targetPad
	remainder := totalLen % 64
	if remainder != 0 {
		targetPad += (64 - remainder)
	}

	//  info
	//  info  Padding  info  paddingGarbage  info
	if targetPad >= len(paddingGarbage) {
		targetPad = len(paddingGarbage) - 1
	}

	return targetPad
}

// ==========================================
// Padding  info
// ==========================================

// PaddingWriter  info  io.Writer  info
type PaddingWriter struct {
	w io.Writer
}

func (pw *PaddingWriter) Write(p []byte) (nTotal int, err error) {
	for len(p) > 0 {
		chunk := p
		//  info  1MB
		if len(chunk) > 1048576 {
			chunk = chunk[:1048576]
		}

		//  info  Padding  info
		padLen := calculatePadding(len(chunk))
		totalLen := 6 + len(chunk) + padLen

		// 🌟  info ： info “ info ” info ， info  make
		bufPtr := paddingWritePool.Get().(*[]byte)
		buf := *bufPtr

		//  info  6 bytes Header
		binary.BigEndian.PutUint32(buf[0:4], uint32(len(chunk)))
		binary.BigEndian.PutUint16(buf[4:6], uint16(padLen))

		//  info
		copy(buf[6:], chunk)

		//  info  Padding
		if padLen > 0 {
			copy(buf[6+len(chunk):], paddingGarbage[:padLen])
		}

		// 🌟  info send（ info  totalLen）
		_, errW := pw.w.Write(buf[:totalLen])

		// 🌟  info “ info ” info ， info
		paddingWritePool.Put(bufPtr)

		if errW != nil {
			return nTotal, errW
		}

		nTotal += len(chunk)
		p = p[len(chunk):]
	}
	return nTotal, nil
}

// info  Writer
func (pw *PaddingWriter) Close() error {
	if closer, ok := pw.w.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// PaddingReader  info
type PaddingReader struct {
	r        io.Reader
	leftData uint32
	leftPad  uint16
}

func (pr *PaddingReader) Read(p []byte) (n int, err error) {
	for pr.leftData == 0 {
		//  info  Padding ( info )
		if pr.leftPad > 0 {
			_, err := io.CopyN(io.Discard, pr.r, int64(pr.leftPad))
			if err != nil {
				return 0, err
			}
			pr.leftPad = 0
		}

		// 读取 6 字节 Header
		var header [6]byte
		if _, err := io.ReadFull(pr.r, header[:]); err != nil {
			return 0, err
		}
		pr.leftData = binary.BigEndian.Uint32(header[0:4]) // 解析 4 字节数据长度
		pr.leftPad = binary.BigEndian.Uint16(header[4:6])

		// 边界防护：防御损坏或恶意超大报文导致内存耗尽
		if pr.leftData > 16*1024*1024 || pr.leftPad > 16384 {
			return 0, fmt.Errorf("corrupted padding frame: dataLen=%d, padLen=%d", pr.leftData, pr.leftPad)
		}
	}

	//  info
	toRead := pr.leftData
	if uint32(len(p)) < toRead {
		toRead = uint32(len(p)) //  info ： info  slice  info
	}
	n, err = pr.r.Read(p[:toRead])
	if err != nil && err != io.EOF {
		zlog.Debugf("[PaddingReader] Exception reading actual data: %v", err)
	}
	pr.leftData -= uint32(n)
	return n, err
}

// info  Reader
func (pr *PaddingReader) Close() error {
	if closer, ok := pr.r.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
