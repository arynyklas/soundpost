//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestCPUControlRecordsNeverExportNames(t *testing.T) {
	b := make([]byte, 64)
	binary.LittleEndian.PutUint32(b, 3)
	binary.LittleEndian.PutUint16(b[6:], 64)
	copy(b[16:], "SOUNDPOST_CPU_COMMAND_CANARY")
	ring := &Ring{}
	if _, ok, e := decodeCPURecord(KernelRecordView{first: b}, ring); e != nil || ok {
		t.Fatal("comm exported", e)
	}
	binary.LittleEndian.PutUint16(b[4:], 1<<13)
	if _, _, e := decodeCPURecord(KernelRecordView{first: b}, ring); !errors.Is(e, ErrTargetIdentity) {
		t.Fatal("exec not refused", e)
	}
	b = make([]byte, 56)
	binary.LittleEndian.PutUint32(b, 7)
	binary.LittleEndian.PutUint16(b[6:], 56)
	if _, _, e := decodeCPURecord(KernelRecordView{first: b}, ring); !errors.Is(e, ErrThreadCoverageChanged) {
		t.Fatal("fork silently omitted", e)
	}
}
func TestCPULossUsesActualCPUAndMonotonicSampleID(t *testing.T) {
	b := make([]byte, 48)
	binary.LittleEndian.PutUint32(b, 2)
	binary.LittleEndian.PutUint16(b[6:], 48)
	binary.LittleEndian.PutUint64(b[8:], 17)
	binary.LittleEndian.PutUint64(b[16:], 9007199254740993)
	binary.LittleEndian.PutUint64(b[32:], 987654321)
	binary.LittleEndian.PutUint32(b[40:], ^uint32(0))
	event, ok, e := decodeCPURecord(KernelRecordView{first: b}, &Ring{})
	if e != nil || !ok || event.Time != 987654321 || event.CPU != ^uint32(0) || event.Task != (TaskKey{}) || event.Loss.Count != 9007199254740993 {
		t.Fatalf("wrong loss %+v %v", event, e)
	}
	binary.LittleEndian.PutUint32(b[44:], 1)
	if _, _, e = decodeCPURecord(KernelRecordView{first: b}, &Ring{}); e == nil {
		t.Fatal("reserved boundary accepted")
	}
}
func TestCPUDecodedSampleDoesNotRetainRingMemory(t *testing.T) {
	raw := cpuRecord(0x1000)
	sample, e := decodeCPUSample(raw, DecodeContext{Method: MethodSoftwareCPUClock, MaxFrames: 128})
	if e != nil {
		t.Fatal(e)
	}
	clear(raw.first)
	if sample.IP != 0x1234 || len(sample.Callchain) != 1 || sample.Callchain[0].IP != 0x1000 {
		t.Fatal("decoded DTO retained borrowed bytes")
	}
}
func TestCPUMalformedSourceStaysFailed(t *testing.T) {
	source := &cpuSource{done: make(chan struct{}), rings: []*Ring{{}}, lastCheck: time.Now()}
	defer source.Close()
	if _, e := source.Next(context.Background()); !errors.Is(e, ErrRingMalformed) {
		t.Fatal(e)
	}
	source.rings = nil
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, e := source.Next(ctx); !errors.Is(e, ErrRingMalformed) {
		t.Fatal("failed acquisition resumed", e)
	}
}
