package myssh

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

type testSpeedProgress struct {
	phase string
	bytes int64
}

func (p *testSpeedProgress) OnSpeedTestProgress(phase string, transferred, elapsedMs int64) {
	p.phase = phase
	p.bytes = transferred
}

func TestSpeedProgressCountsBothDirections(t *testing.T) {
	callback := &testSpeedProgress{}
	down := &speedProgressWriter{phase: "download", start: time.Now(), callback: callback}
	n, err := io.Copy(down, strings.NewReader("download payload"))
	if err != nil || n != int64(len("download payload")) || down.transferred != n {
		t.Fatalf("download count: n=%d transferred=%d err=%v", n, down.transferred, err)
	}
	if callback.phase != "download" || callback.bytes != n {
		t.Fatalf("download callback: %+v", callback)
	}

	up := &speedProgressReader{reader: bytes.NewReader([]byte("upload payload")), phase: "upload", start: time.Now(), callback: callback}
	got, err := io.ReadAll(up)
	if err != nil || string(got) != "upload payload" || up.transferred != int64(len(got)) {
		t.Fatalf("upload count: got=%q transferred=%d err=%v", got, up.transferred, err)
	}
	if callback.phase != "upload" || callback.bytes != int64(len(got)) {
		t.Fatalf("upload callback: %+v", callback)
	}
}

func TestSpeedErrorKeepsCompletedDownload(t *testing.T) {
	partial := SpeedTestResult{BytesDown: 1024, DownMbps: 8.0}
	result := marshalPartialSpeedError(partial, time.Now(), "up status: 500")
	if !strings.Contains(result, `"bytesDown":1024`) || !strings.Contains(result, `"downMbps":8`) || !strings.Contains(result, `"ok":false`) {
		t.Fatalf("partial result lost completed download: %s", result)
	}
}
