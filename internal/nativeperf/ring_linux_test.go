//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"unsafe"
)

func testRing(data []byte, tail uint64, record []byte) *Ring {
	meta := make([]byte, 4096)
	r := &Ring{meta: meta, data: data}
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&meta[1032])), tail)
	for i, b := range record {
		data[(int(tail)+i)%len(data)] = b
	}
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&meta[1024])), tail+uint64(len(record)))
	return r
}
func TestRingWrappedAndReleaseTail(t *testing.T) {
	for _, tail := range []uint64{0, 123, 127, 250} {
		rec := cpuRecord(0x1000).first
		r := testRing(make([]byte, 128), tail, rec)
		calls := 0
		e := r.consume(func(v KernelRecordView) error {
			calls++
			s, e := decodeCPUSample(v, DecodeContext{Method: MethodSoftwareCPUClock, MaxFrames: 128})
			if e != nil || s.IP != 0x1234 {
				t.Fatal(s, e)
			}
			if r.tail() != tail {
				t.Fatal("tail published before decode")
			}
			return nil
		})
		if e != nil || calls != 1 || r.tail() != tail+uint64(len(rec)) {
			t.Fatal(e, calls, r.tail())
		}
	}
}
func TestRingMalformedPartialAndOverwrite(t *testing.T) {
	for _, size := range []uint16{0, 7, 65} {
		b := make([]byte, 16)
		binary.LittleEndian.PutUint16(b[6:], size)
		r := testRing(make([]byte, 64), 0, b)
		if e := r.consume(func(KernelRecordView) error { t.Fatal("decoded malformed"); return nil }); e == nil || r.tail() != 0 {
			t.Fatal("malformed advanced", e)
		}
	}
	r := testRing(make([]byte, 64), 0, []byte{1, 2, 3})
	if e := r.consume(func(KernelRecordView) error { return nil }); e == nil {
		t.Fatal("partial header accepted")
	}
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&r.meta[1024])), 65)
	if e := r.consume(func(KernelRecordView) error { return nil }); !errors.Is(e, ErrRingOverwrite) {
		t.Fatal(e)
	}
}
func TestRingEmitFailureRetainsBorrow(t *testing.T) {
	r := testRing(make([]byte, 128), 0, cpuRecord(0x1000).first)
	want := errors.New("stop")
	if e := r.consume(func(KernelRecordView) error { return want }); e != want || r.tail() != 0 {
		t.Fatal(e, r.tail())
	}
}
func TestRingLossAndThrottle(t *testing.T) {
	for _, tc := range []struct {
		typ    uint32
		words  []uint64
		reason Reason
		count  uint64
	}{{2, []uint64{17, 123}, ReasonLoss, 123}, {13, []uint64{456}, ReasonSampleLost, 456}, {5, []uint64{999, 17, 18}, ReasonThrottle, 0}, {6, []uint64{1000, 17, 18}, ReasonUnthrottle, 0}} {
		b := make([]byte, 8+8*len(tc.words))
		binary.LittleEndian.PutUint32(b, tc.typ)
		binary.LittleEndian.PutUint16(b[6:], uint16(len(b)))
		for i, v := range tc.words {
			binary.LittleEndian.PutUint64(b[8+8*i:], v)
		}
		loss, _, e := decodeCPULoss(KernelRecordView{first: b})
		if e != nil || loss.Count != tc.count || loss.Reason != tc.reason || !loss.valid() {
			t.Fatalf("%+v %v", loss, e)
		}
	}
}
func TestCPUAcquisitionCancellationAndOwnership(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "owned")
	if e != nil {
		t.Fatal(e)
	}
	source := &cpuSource{rings: []*Ring{{fd: f}}, done: make(chan struct{})}
	if e := source.Close(); e != nil {
		t.Fatal(e)
	}
	if e := source.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = f.Stat(); e == nil {
		t.Fatal("FD leaked")
	}
	if _, e := source.Next(context.Background()); !errors.Is(e, ErrAcquisitionClosed) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := NewCPUAcquisition(ctx, AuthorizedTargets{}, DefaultConfig(1), nil); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := NewCPUAcquisition(context.Background(), AuthorizedTargets{mode: ModeCPUOffCPU}, DefaultConfig(1), nil); e == nil {
		t.Fatal("scheduler mode fabricated")
	}
}
