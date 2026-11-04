//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"encoding/binary"
	"testing"
)

func cpuRecord(ips ...uint64) KernelRecordView {
	b := make([]byte, 56+8*len(ips))
	binary.LittleEndian.PutUint32(b, 9)
	binary.LittleEndian.PutUint16(b[4:], 2)
	binary.LittleEndian.PutUint16(b[6:], uint16(len(b)))
	for i, v := range []uint64{0x1234, uint64(71)<<32 | 70, 123456, 3, 10101010, uint64(len(ips))} {
		binary.LittleEndian.PutUint64(b[8+i*8:], v)
	}
	for i, v := range ips {
		binary.LittleEndian.PutUint64(b[56+8*i:], v)
	}
	return KernelRecordView{first: b}
}
func TestCPUAttrPrivacy(t *testing.T) {
	for _, method := range []SamplingMethod{MethodSoftwareCPUClock, MethodHardwareCycles} {
		a, e := cpuAttr(method, 128)
		if e != nil {
			t.Fatal(e)
		}
		if a.SampleType != uint64(1|2|4|32|128|256) || a.Frequency != 99 || a.ClockID != 1 || a.Flags&(1<<25) == 0 || a.Flags&(1<<10) == 0 {
			t.Fatalf("wrong fixed ABI: %+v", a)
		}
		if a.SampleRegsUser != 0 || a.SampleStackUser != 0 || a.SampleRegsIntr != 0 || a.BranchSampleType != 0 || a.Flags&(1<<1) != 0 || a.Flags&(1<<5) == 0 || a.Flags&(1<<6) == 0 {
			t.Fatal("unsafe capture or inheritance")
		}
		for _, required := range []uint64{1 << 9, 1 << 13, 1 << 18, 1 << 21, 1 << 24} {
			if a.Flags&required == 0 {
				t.Fatal("missing generation-control, sample identity or kernel-callchain exclusion flag")
			}
		}
		if method == MethodHardwareCycles && (a.Type != 0 || a.Config != 0) {
			t.Fatal("cycles not explicit")
		}
	}
	if _, e := cpuAttr("arbitrary", 128); e == nil {
		t.Fatal("unknown selector accepted")
	}
	cfg := DefaultConfig(1)
	cfg.CPUHz = 50
	if cfg.Validate() == nil {
		t.Fatal("lower rate admitted without threading the fixed attr/DTO rate contract")
	}
}
func TestCPUCallchainPrivacyAndBookkeeping(t *testing.T) {
	r := cpuRecord(^uint64(511), 0x1000, ^uint64(127), 0xffff800000001234, ^uint64(511), 0, 0x2000, ^uint64(4094))
	s, e := decodeCPUSample(r, DecodeContext{Method: MethodSoftwareCPUClock, MaxFrames: 128})
	if e != nil {
		t.Fatal(e)
	}
	if s.IP != 0x1234 || s.Period != 10101010 || s.RequestedHz != 99 || s.Unit != UnitCPUClockNanoseconds || s.Truncated != ReasonUnresolved {
		t.Fatalf("wrong sample %+v", s)
	}
	frames := 0
	for _, f := range s.Callchain {
		if f.IP != 0 {
			frames++
			if f.IP != 0x1000 && f.IP != 0x2000 {
				t.Fatal("unsafe IP escaped")
			}
		}
	}
	if frames != 2 {
		t.Fatalf("frames %d", frames)
	}
	if !s.valid() {
		t.Fatal("invalid DTO")
	}
}
func TestCPUCallchainBounds(t *testing.T) {
	ips := make([]uint64, 140)
	for i := range ips {
		ips[i] = 0x1000 + uint64(i)
	}
	s, e := decodeCPUSample(cpuRecord(ips...), DecodeContext{Method: MethodHardwareCycles, MaxFrames: 4})
	if e != nil || len(s.Callchain) != 4 || s.Truncated != ReasonTruncated || s.Unit != UnitHardwareCycles {
		t.Fatalf("%+v %v", s, e)
	}
	r := cpuRecord(0x1000)
	r.first = r.first[:len(r.first)-1]
	if _, e := decodeCPUSample(r, DecodeContext{Method: MethodSoftwareCPUClock, MaxFrames: 128}); e == nil {
		t.Fatal("partial accepted")
	}
	r = cpuRecord()
	binary.LittleEndian.PutUint64(r.first[48:], ^uint64(0))
	if _, e := decodeCPUSample(r, DecodeContext{Method: MethodSoftwareCPUClock, MaxFrames: 128}); e == nil {
		t.Fatal("overflow accepted")
	}
	r = cpuRecord(0x1000)
	binary.LittleEndian.PutUint16(r.first[4:], 1)
	if _, e := decodeCPUSample(r, DecodeContext{Method: MethodSoftwareCPUClock, MaxFrames: 128}); e == nil {
		t.Fatal("kernel IP accepted")
	}
}
