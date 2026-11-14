//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestHelperGrantExpiryInterruptsStalledControlRead(t *testing.T) {
	_, server := cpuSocketPair(t)
	ctx, release, e := helperCaptureContext(context.Background(), server, time.Now().Add(40*time.Millisecond))
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	done := make(chan error, 1)
	go func() {
		var stop struct {
			Stop bool `json:"stop"`
		}
		done <- readMessage(server, &stop)
	}()
	select {
	case e = <-done:
		if e == nil {
			t.Fatal("stalled read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("grant expiry did not interrupt read")
	}
	<-ctx.Done()
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal(ctx.Err())
	}
}
func TestHelperGrantExpiryInterruptsStalledStreamAndReleasesOwnership(t *testing.T) {
	_, server := cpuSocketPair(t)
	if e := server.SetWriteBuffer(4096); e != nil {
		t.Fatal(e)
	}
	raw, e := server.SyscallConn()
	if e != nil {
		t.Fatal(e)
	}
	full := false
	if e = raw.Control(func(fd uintptr) {
		one := [1]byte{}
		for range 65536 {
			_, err := syscall.Write(int(fd), one[:])
			if err == syscall.EINTR {
				continue
			}
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				full = true
				break
			}
			if err != nil {
				break
			}
		}
	}); e != nil || !full {
		t.Fatal("could not fill private socket", e)
	}
	cfg := DefaultConfig(1)
	budget := NewResourceBudget()
	lease, e := budget.Reserve(AuthorizedTargets{targets: []Target{{}}, mode: ModeCPU}, cfg, Topology{CPUs: 1, FDLimit: 1024, PageBytes: uint64(os.Getpagesize())}, MemoryUsage{})
	if e != nil {
		t.Fatal(e)
	}
	defer lease.Close()
	file, e := os.CreateTemp(t.TempDir(), "owned")
	if e != nil {
		t.Fatal(e)
	}
	ring := &Ring{fd: file}
	if e = lease.Own(ring); e != nil {
		t.Fatal(e)
	}
	source := &cpuSource{done: make(chan struct{}), rings: []*Ring{ring}}
	ctx, release, e := helperCaptureContext(context.Background(), server, time.Now().Add(200*time.Millisecond))
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer lease.Close()
		defer source.Close()
		streamHelperEvents(ctx, server, source)
	}()
	select {
	case <-done:
		t.Fatal("stream did not actually stall before expiry")
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stalled authenticated stream retained ownership past expiry")
	}
	<-ctx.Done()
	if _, e = file.Stat(); e == nil {
		t.Fatal("owned FD leaked")
	}
	if budget.memory != 0 || budget.fds != 0 {
		t.Fatal("reservation leaked")
	}
}
func TestHelperCapturePreservesEarlierParentDeadline(t *testing.T) {
	_, server := cpuSocketPair(t)
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx, release, e := helperCaptureContext(parent, server, time.Now().Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	got, _ := ctx.Deadline()
	want, _ := parent.Deadline()
	if !got.Equal(want) {
		t.Fatal("signed expiry widened parent deadline")
	}
}
