//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"unsafe"
)

func TestCPURingCloseActuallyUnmapsMemory(t *testing.T) {
	page := os.Getpagesize()
	mapping, e := syscall.Mmap(-1, 0, 2*page, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if e != nil {
		t.Fatal(e)
	}
	address := uintptr(unsafe.Pointer(&mapping[0]))
	ring := &Ring{mapping: mapping, meta: mapping[:page], data: mapping[page:]}
	if e = ring.Close(); e != nil {
		t.Fatal(e)
	}
	var resident byte
	_, _, errno := syscall.Syscall(syscall.SYS_MINCORE, address, uintptr(page), uintptr(unsafe.Pointer(&resident)))
	if errno != syscall.ENOMEM {
		t.Fatalf("mmap retained after Close: %v", errno)
	}
	if e = ring.consume(func(KernelRecordView) error { t.Fatal("closed ring callback"); return nil }); !errors.Is(e, ErrAcquisitionClosed) {
		t.Fatal(e)
	}
	if e = ring.Close(); e != nil {
		t.Fatal(e)
	}
}
