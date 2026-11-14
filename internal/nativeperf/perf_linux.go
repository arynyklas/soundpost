//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

func openThreadCPU(t TaskKey, c Config, method SamplingMethod) (*Ring, error) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return nil, &CapabilityError{Unsupported, ReasonPlatform}
	}
	a, e := cpuAttr(method, uint16(c.MaxFrames))
	if e != nil {
		return nil, e
	}
	fd, _, errno := syscall.Syscall6(syscall.SYS_PERF_EVENT_OPEN, uintptr(unsafe.Pointer(&a)), uintptr(t.TID), ^uintptr(0), ^uintptr(0), 8, 0)
	if errno != 0 {
		status, reason := probeStatus(errno)
		return nil, &CapabilityError{status, reason}
	}
	r := &Ring{fd: os.NewFile(fd, "cpu-perf"), task: t, method: method, maxFrames: uint16(c.MaxFrames)}
	length := int(c.RingBytes) + os.Getpagesize()
	mapping, e := syscall.Mmap(int(fd), 0, length, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if e != nil {
		r.Close()
		return nil, &CapabilityError{Error, ReasonEvent}
	}
	r.mapping = mapping
	r.meta = mapping[:os.Getpagesize()]
	// data_offset/data_size are initialized by the kernel on mmap. Refuse an
	// unexpected layout; never interpret metadata pages as sample payload.
	offset := *(*uint64)(unsafe.Pointer(&mapping[1040]))
	size := *(*uint64)(unsafe.Pointer(&mapping[1048]))
	if offset != uint64(os.Getpagesize()) || size != c.RingBytes || offset+size != uint64(length) {
		r.Close()
		return nil, ErrRingMalformed
	}
	r.data = mapping[int(offset):]
	return r, nil
}
func enableCPU(r *Ring) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, r.fd.Fd(), 0x2400, 0)
	if errno != 0 {
		return &CapabilityError{Error, ReasonEvent}
	}
	return nil
}
