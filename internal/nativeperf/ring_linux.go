//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

type Ring struct {
	mu                  sync.Mutex
	fd                  *os.File
	mapping, meta, data []byte
	task                TaskKey
	method              SamplingMethod
	maxFrames           uint16
	closed              bool
}

func (r *Ring) head() uint64 { return atomic.LoadUint64((*uint64)(unsafe.Pointer(&r.meta[1024]))) }
func (r *Ring) tail() uint64 { return atomic.LoadUint64((*uint64)(unsafe.Pointer(&r.meta[1032]))) }

// Go's sequentially consistent atomics are stronger than the perf ABI's acquire
// head / release tail requirements on amd64 and arm64. No payload read occurs
// before head acquire, and no tail publication occurs until callback completion.
// The ring must have exactly one consumer, serialized by cpuSource.nextMu.
func (r *Ring) consume(emit func(KernelRecordView) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrAcquisitionClosed
	}
	if len(r.meta) < 1040 || len(r.data) == 0 {
		return ErrRingMalformed
	}
	head, tail := r.head(), r.tail()
	available := head - tail
	if available > uint64(len(r.data)) {
		return ErrRingOverwrite
	}
	if available == 0 {
		return nil
	}
	if available < 8 {
		return ErrRingMalformed
	}
	at := int(tail % uint64(len(r.data)))
	view := KernelRecordView{first: r.data[at:]}
	if at+8 > len(r.data) {
		view.second = r.data[:8-len(view.first)]
	}
	size := int(view.u16(6))
	if size < 8 || uint64(size) > available || size > len(r.data) {
		return ErrRingMalformed
	}
	end := at + size
	if end <= len(r.data) {
		view = KernelRecordView{first: r.data[at:end]}
	} else {
		view = KernelRecordView{first: r.data[at:], second: r.data[:end-len(r.data)]}
	}
	if e := emit(view); e != nil {
		return e
	}
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&r.meta[1032])), tail+uint64(size))
	return nil
}
func (r *Ring) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var first error
	if r.fd != nil {
		_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, r.fd.Fd(), 0x2401, 0)
	}
	if len(r.mapping) != 0 {
		first = syscall.Munmap(r.mapping)
		r.mapping = nil
		r.meta = nil
		r.data = nil
	}
	if r.fd != nil {
		if e := r.fd.Close(); first == nil {
			first = e
		}
		r.fd = nil
	}
	return first
}

// exited reports whether the task of a task-scoped event has exited. A task-scoped perf event reports POLLHUP from
// the moment its task exits (the kernel sets the event's state before the thread is released, so before its TID can
// be reused). The question is one zero-timeout ppoll on the ring's own descriptor: no /proc read, no extra
// descriptor and no work that grows with the thread count. Events are not requested: POLLHUP is always reported and
// readiness of the sample data (POLLIN) is not asked for.
func (r *Ring) exited() (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.fd == nil {
		return false, ErrAcquisitionClosed
	}
	poll := struct {
		fd              int32
		events, revents int16
	}{fd: int32(r.fd.Fd())}
	var now syscall.Timespec
	for {
		n, _, errno := syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(&poll)), 1, uintptr(unsafe.Pointer(&now)), 0, 0, 0)
		switch errno {
		case 0:
			return n > 0 && poll.revents&pollHangup != 0, nil
		case syscall.EINTR:
		default:
			return false, ErrAcquisitionFailed
		}
	}
}

const pollHangup = 0x10

// drainRing consumes one record, bounding cancellation latency and avoiding a
// copied event queue. Non-CPU control records are decoded by the source.
func drainRing(r *Ring, emit func(SanitizedEvent) error) error {
	return r.consume(func(v KernelRecordView) error {
		event, ok, e := decodeCPURecord(v, r)
		if e != nil || !ok {
			return e
		}
		return emit(event)
	})
}

// ringLayoutOK is the mmap layout the kernel must report for a perf ring: the data area starts exactly one page in, has exactly the requested size and ends exactly at the mapping's end (the metadata page is never read as payload).
func ringLayoutOK(offset, size uint64, mappingBytes, page int, ringBytes uint64) bool {
	return offset == uint64(page) && size == ringBytes && offset+size == uint64(mappingBytes)
}
