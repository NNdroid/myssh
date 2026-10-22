package myssh

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
)

// probeRTT 是可编程的 RoundTripper：按调用次序返回预设错误，其余返回 204。
type probeRTT struct {
	trips int
	errs  []error
}

func (p *probeRTT) RoundTrip(*http.Request) (*http.Response, error) {
	i := p.trips
	p.trips++
	if i < len(p.errs) && p.errs[i] != nil {
		return nil, p.errs[i]
	}
	return &http.Response{StatusCode: 204, Body: http.NoBody, Proto: "HTTP/1.1"}, nil
}

// TestMedianInt64 中位数要滤掉冷启动首包与偶发的重传尖峰。
func TestMedianInt64(t *testing.T) {
	cases := []struct {
		name string
		in   []int64
		want int64
	}{
		{"empty", nil, 0},
		{"single", []int64{300}, 300},
		{"cold_first_packet_filtered", []int64{1513, 320, 310}, 320},
		{"equal", []int64{300, 300, 300}, 300},
		{"late_spike_filtered", []int64{300, 900, 500}, 500},
		{"even_upper_median", []int64{300, 900}, 900},
	}
	for _, tc := range cases {
		if got := medianInt64(tc.in); got != tc.want {
			t.Errorf("%s: medianInt64(%v) = %d, want %d", tc.name, tc.in, got, tc.want)
		}
	}

	// 采样结果直接来自调用方，排序前必须拷贝，不能改写原切片。
	in := []int64{300, 900, 500}
	medianInt64(in)
	if !reflect.DeepEqual(in, []int64{300, 900, 500}) {
		t.Errorf("medianInt64 mutated its input: %v", in)
	}
}

// TestCollectProbeSamples 采样必须容忍后续失败：首包失败说明隧道根本不通，
// 如实上报；后续样本失败（预算耗尽或链路抖动）只截断采样。这条不变量保证
// 「可用但慢」的节点不会因为多采几次就被误判成超时不可用。
func TestCollectProbeSamples(t *testing.T) {
	ctx := context.Background()
	newClient := func(rt *probeRTT) *http.Client { return &http.Client{Transport: rt} }

	rt := &probeRTT{}
	s, err := collectProbeSamples(newClient(rt), ctx, "http://x/")
	if err != nil || len(s) != probeSamples || rt.trips != probeSamples {
		t.Fatalf("all ok: samples=%v err=%v trips=%d", s, err, rt.trips)
	}

	rt = &probeRTT{errs: []error{errors.New("boom")}}
	_, err = collectProbeSamples(newClient(rt), ctx, "http://x/")
	if err == nil {
		t.Fatal("first-sample failure must be reported")
	} else if rt.trips != 1 {
		t.Fatalf("first-sample failure: want 1 trip, got %d", rt.trips)
	}

	rt = &probeRTT{errs: []error{nil, errors.New("deadline")}}
	s, err = collectProbeSamples(newClient(rt), ctx, "http://x/")
	if err != nil || len(s) != 1 || rt.trips != 2 {
		t.Fatalf("late failure truncates: samples=%v err=%v trips=%d", s, err, rt.trips)
	}

	rt = &probeRTT{errs: []error{nil, errors.New("d"), errors.New("d")}}
	s, err = collectProbeSamples(newClient(rt), ctx, "http://x/")
	if err != nil || len(s) != 1 || rt.trips != 2 {
		t.Fatalf("stop at first late failure: samples=%v err=%v trips=%d", s, err, rt.trips)
	}

	rt = &probeRTT{errs: []error{nil, nil, errors.New("d")}}
	s, err = collectProbeSamples(newClient(rt), ctx, "http://x/")
	if err != nil || len(s) != 2 || rt.trips != 3 {
		t.Fatalf("two samples survive: samples=%v err=%v trips=%d", s, err, rt.trips)
	}
}
