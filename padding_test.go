package myssh

import (
	"bytes"
	"go.uber.org/zap"
	"io"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func init() {
	if zlog == nil {
		zlog = zap.NewNop().Sugar()
	}
}

func TestCalculatePadding(t *testing.T) {
	pad1 := calculatePadding(100)
	assert.GreaterOrEqual(t, pad1, 0, "Padding should be non-negative")
	assert.True(t, (100+pad1)%64 == 0, "Total length should be aligned to 64 bytes")

	pad2 := calculatePadding(200)
	assert.GreaterOrEqual(t, pad2, 0)
	assert.True(t, (200+pad2)%64 == 0, "Total length should be aligned to 64 bytes")

	pad3 := calculatePadding(9000)
	assert.GreaterOrEqual(t, pad3, 0)
	assert.True(t, (9000+pad3)%64 == 0, "Total length should be aligned to 64 bytes")
}

func TestPaddingReaderWriter(t *testing.T) {
	var buf bytes.Buffer

	pw := &PaddingWriter{w: &buf}
	testData1 := []byte("Hello World, this is a test payload for padding!")
	n, err := pw.Write(testData1)
	assert.NoError(t, err)
	assert.Equal(t, len(testData1), n)

	assert.True(t, buf.Len()%64 == 6, "Buffer length should be (multiple of 64) + 6 bytes header")

	testData2 := []byte("Second payload")
	n, err = pw.Write(testData2)
	assert.NoError(t, err)
	assert.Equal(t, len(testData2), n)

	pr := &PaddingReader{r: &buf}

	outBuf1 := make([]byte, len(testData1))
	n, err = io.ReadFull(pr, outBuf1)
	assert.NoError(t, err)
	assert.Equal(t, len(testData1), n)
	assert.Equal(t, testData1, outBuf1)

	outBuf2 := make([]byte, len(testData2))
	n, err = io.ReadFull(pr, outBuf2)
	assert.NoError(t, err)
	assert.Equal(t, len(testData2), n)
	assert.Equal(t, testData2, outBuf2)
}

func TestPaddingLargeDataSync(t *testing.T) {
	var buf bytes.Buffer
	pw := &PaddingWriter{w: &buf}
	pr := &PaddingReader{r: &buf}

	largeData := make([]byte, 2*1024*1024) // 2MB
	rand.Read(largeData)

	n, err := pw.Write(largeData)
	assert.NoError(t, err)
	assert.Equal(t, len(largeData), n)

	readBuf := make([]byte, len(largeData))
	n, err = io.ReadFull(pr, readBuf)
	assert.NoError(t, err)
	assert.Equal(t, len(largeData), n)
	assert.Equal(t, largeData, readBuf)
}
