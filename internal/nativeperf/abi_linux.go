//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import "errors"

// Independently authored from perf_event_open(2) and Linux perf_event.h UAPI.
// Only the fixed little-endian 64-bit amd64/arm64 ABI is supported.
const cpuSampleType uint64 = 1 | 2 | 4 | 32 | 128 | 256
const (
	perfRecordLost        = 2
	perfRecordComm        = 3
	perfRecordExit        = 4
	perfRecordThrottle    = 5
	perfRecordUnthrottle  = 6
	perfRecordFork        = 7
	perfRecordSample      = 9
	perfRecordLostSamples = 13
)

var (
	ErrRingMalformed         = errors.New("native profiling: malformed perf ring")
	ErrRingOverwrite         = errors.New("native profiling: perf ring overwritten")
	ErrAcquisitionClosed     = errors.New("native profiling: acquisition closed")
	ErrAcquisitionFailed     = errors.New("native profiling: acquisition failed")
	ErrThreadCoverageChanged = errors.New("native profiling: thread topology changed; restart capture")
)

// VER5 (112 bytes) includes explicit clockid and sample_max_stack. No union
// member used for probes, breakpoint addresses, raw data or register capture.
type cpuPerfAttr struct {
	Type, Size                                         uint32
	Config, Frequency, SampleType, ReadFormat, Flags   uint64
	Wakeup, BPType                                     uint32
	Config1, Config2, BranchSampleType, SampleRegsUser uint64
	SampleStackUser                                    uint32
	ClockID                                            int32
	SampleRegsIntr                                     uint64
	AUXWatermark                                       uint32
	SampleMaxStack                                     uint16
	Reserved                                           uint16
}

func cpuAttr(method SamplingMethod, maxFrames uint16) (cpuPerfAttr, error) {
	a := cpuPerfAttr{Size: 112, Type: 1, Frequency: 99, SampleType: cpuSampleType, Wakeup: 1, ClockID: 1, SampleMaxStack: maxFrames}
	if maxFrames == 0 || maxFrames > 128 {
		return cpuPerfAttr{}, ErrInvalid
	}
	// The Linux default perf_event_max_stack is 127. Keep the fixed request
	// within that baseline without changing the host's global sysctl.
	a.SampleMaxStack = min(maxFrames, 127)
	switch method {
	case MethodSoftwareCPUClock:
		a.Config = 0
	case MethodHardwareCycles:
		a.Type = 0
		a.Config = 0
	default:
		return cpuPerfAttr{}, ErrInvalid
	}
	// disabled, exclude_kernel, exclude_hv, comm, freq, task, sample_id_all,
	// use_clockid, comm_exec, exclude_callchain_kernel. No inheritance.
	a.Flags = 1 | 1<<5 | 1<<6 | 1<<9 | 1<<10 | 1<<13 | 1<<18 | 1<<21 | 1<<25 | 1<<24
	return a, nil
}

// KernelRecordView borrows up to two mmap slices. It never copies raw bytes and
// cannot outlive the consumer callback or the release-store of data_tail.
type KernelRecordView struct{ first, second []byte }

func (v KernelRecordView) len() int { return len(v.first) + len(v.second) }
func (v KernelRecordView) byteAt(i int) byte {
	if i < len(v.first) {
		return v.first[i]
	}
	return v.second[i-len(v.first)]
}
func (v KernelRecordView) u16(i int) uint16 { return uint16(v.byteAt(i)) | uint16(v.byteAt(i+1))<<8 }
func (v KernelRecordView) u32(i int) uint32 { return uint32(v.u16(i)) | uint32(v.u16(i+2))<<16 }
func (v KernelRecordView) u64(i int) uint64 { return uint64(v.u32(i)) | uint64(v.u32(i+4))<<32 }
func (v KernelRecordView) valid() bool      { return v.len() >= 8 && int(v.u16(6)) == v.len() }
