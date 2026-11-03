//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"encoding/binary"
	"runtime"
	"sync/atomic"
	"testing"
	"unsafe"
)

func TestRingAcquireHeadReleaseTailOrdering(t *testing.T) {
	r := &Ring{meta: make([]byte, 4096), data: make([]byte, 128)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for n := range 100 {
			position := uint64(n * 64)
			for r.tail() != position {
				runtime.Gosched()
			}
			record := cpuRecord(uint64(0x1000 + n)).first
			binary.LittleEndian.PutUint64(record[8:], uint64(0x2000+n))
			for i, b := range record {
				r.data[(int(position)+i)%len(r.data)] = b
			}
			atomic.StoreUint64((*uint64)(unsafe.Pointer(&r.meta[1024])), position+64)
		}
	}()
	for n := range 100 {
		for r.head() == r.tail() {
			runtime.Gosched()
		}
		if e := r.consume(func(v KernelRecordView) error {
			sample, e := decodeCPUSample(v, DecodeContext{Method: MethodSoftwareCPUClock, MaxFrames: 128})
			if e != nil {
				return e
			}
			if sample.IP != uint64(0x2000+n) || sample.Callchain[0].IP != uint64(0x1000+n) {
				t.Error("payload read before publication or reused before release")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	}
	<-done
}
