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
