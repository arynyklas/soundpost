//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLockBytesFromCombinesRlimitAndPerfAllowance(t *testing.T) {
	const infinity = ^uint64(0)
	for _, tc := range []struct {
		name                 string
		memlock, perfKB, cpu uint64
		want                 uint64
	}{
		{"default 8 MiB rlimit and 516 KiB allowance on 8 CPUs", 8 << 20, 516, 8, 8<<20 + 8*516<<10},
		{"the allowance scales with online CPUs", 8 << 20, 516, 64, 8<<20 + 64*516<<10},
		{"zero CPUs count as one", 8 << 20, 516, 0, 8<<20 + 516<<10},
		{"rlimit zero keeps the allowance", 0, 516, 2, 2 * 516 << 10},
		{"allowance zero keeps the rlimit", 64 << 10, 0, 8, 64 << 10},
		{"both zero must refuse, not read as unbounded", 0, 0, 8, 1},
		{"infinite rlimit is unbounded", infinity, 516, 8, 0},
		{"overflow is unbounded", infinity - 1, 516, 8, 0},
		{"allowance overflow is unbounded", 1, 1 << 60, 8, 0},
	} {
		if got := lockBytesFrom(tc.memlock, tc.perfKB, tc.cpu); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestMmapFailureIsAResourceLimitForLockedMemory(t *testing.T) {
	for _, e := range []error{syscall.EPERM, &os.PathError{Op: "mmap", Err: syscall.EPERM}} {
		if got := mmapFailure(e); !errors.Is(got, ErrResources) {
			t.Errorf("%v: %v", e, got)
		}
	}
	var capability *CapabilityError
	if got := mmapFailure(syscall.EINVAL); !errors.As(got, &capability) || errors.Is(got, ErrResources) || helperErrorCode(got) != "acquisition_failed" {
		t.Errorf("EINVAL: %v", mmapFailure(syscall.EINVAL))
	}
	if helperErrorCode(mmapFailure(syscall.EPERM)) != "resource_limit" {
		t.Error("a locked-memory refusal must reach the client as resource_limit")
	}
}

func TestHoldsIPCLockReadsEffectiveCapabilities(t *testing.T) {
	dir := t.TempDir()
	status := func(cap string) string {
		p := filepath.Join(dir, "status-"+cap)
		body := "Name:\tx\nCapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t" + cap + "\nCapBnd:\t000001ffffffffff\n"
		if e := os.WriteFile(p, []byte(body), 0o600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	if !holdsIPCLock(status("0000000000004000")) { // bit 14
		t.Error("CAP_IPC_LOCK alone not recognised")
	}
	if !holdsIPCLock(status("000001ffffffffff")) {
		t.Error("full capability set not recognised")
	}
	if holdsIPCLock(status("0000000000003fff")) || holdsIPCLock(status("0000000000008000")) {
		t.Error("neighbouring capabilities read as CAP_IPC_LOCK")
	}
	if holdsIPCLock(status("zz")) || holdsIPCLock(filepath.Join(dir, "missing")) {
		t.Error("unreadable capability set read as CAP_IPC_LOCK")
	}
	empty := filepath.Join(dir, "no-capeff")
	if e := os.WriteFile(empty, []byte("Name:\tx\n"), 0o600); e != nil {
		t.Fatal(e)
	}
	if holdsIPCLock(empty) {
		t.Error("status without CapEff read as CAP_IPC_LOCK")
	}
}

// A capture whose rings cannot all be mapped under RLIMIT_MEMLOCK is refused up front with a resource error, before any
// perf FD is opened (it used to fail as acquisition_failed after the rings were opened one by one).
func TestReservationRefusesRingsBeyondLockedMemory(t *testing.T) {
	needs4KPages(t)
	cfg := DefaultConfig(1)
	per := cfg.RingBytes + testPage
	topology := func(lock uint64) Topology {
		return Topology{CPUs: 8, FDLimit: 4096, PageBytes: testPage, LockBytes: lock}
	}
	for _, tc := range []struct {
		name   string
		lock   uint64
		accept bool
	}{
		{"exactly the rings", 2 * per, true},
		{"one byte short of the rings", 2*per - 1, false},
		{"one ring only", per, false},
		{"unbounded", 0, true},
	} {
		r, e := NewResourceBudget().Reserve(authTargets(2, ModeCPU), cfg, topology(tc.lock), MemoryUsage{})
		if (e == nil) != tc.accept || e != nil && !errors.Is(e, ErrResources) {
			t.Errorf("%s: %v", tc.name, e)
		}
		if r != nil {
			r.Close()
		}
	}
	// The extension to one ring per initial thread honours the same bound.
	r, e := NewResourceBudget().Reserve(authTargets(1, ModeCPU), cfg, topology(5*per), MemoryUsage{})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if _, e := r.ReserveCPURings(6, cfg, testPage); !errors.Is(e, ErrResources) {
		t.Fatalf("6 rings under a 5-ring lock bound: %v", e)
	}
	if r.FDs != 6 || r.cpuRings != 1 {
		t.Fatal("refusal charged the lease")
	}
	rollback, e := r.ReserveCPURings(5, cfg, testPage)
	if e != nil {
		t.Fatalf("exactly the bound refused: %v", e)
	}
	rollback()
}
