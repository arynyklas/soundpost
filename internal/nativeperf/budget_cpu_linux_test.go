//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"os"
	"testing"
)

func TestCPUReservationRollbackOwnsPartialFailure(t *testing.T) {
	cfg := DefaultConfig(1)
	budget := NewResourceBudget()
	lease, e := budget.Reserve(AuthorizedTargets{targets: []Target{{}}, mode: ModeCPU}, cfg, Topology{CPUs: 2, FDLimit: 1024, PageBytes: uint64(os.Getpagesize())}, MemoryUsage{})
	if e != nil {
		t.Fatal(e)
	}
	defer lease.Close()
	baselineMemory, baselineFDs := lease.Memory, lease.FDs
	rollback, e := lease.ReserveCPURings(3, cfg, uint64(os.Getpagesize()))
	if e != nil {
		t.Fatal(e)
	}
	if lease.Memory != baselineMemory+2*(cfg.RingBytes+uint64(os.Getpagesize())) || lease.FDs != baselineFDs+2 {
		t.Fatal("initial threads not reserved")
	}
	f, e := os.CreateTemp(t.TempDir(), "partial")
	if e != nil {
		t.Fatal(e)
	}
	if e = lease.Own(f); e != nil {
		t.Fatal(e)
	}
	rollback()
	rollback()
	if _, e = f.Stat(); e == nil {
		t.Fatal("partial open leaked")
	}
	if lease.Memory != baselineMemory || lease.FDs != baselineFDs || budget.memory != baselineMemory || budget.fds != baselineFDs {
		t.Fatal("rollback leaked or released baseline")
	}
	rollback, e = lease.ReserveCPURings(2, cfg, uint64(os.Getpagesize()))
	if e != nil {
		t.Fatal(e)
	}
	lease.Close()
	rollback()
	if budget.memory != 0 || budget.fds != 0 {
		t.Fatal("double release")
	}
}
func TestCPUReservationRefusesBeforeOpen(t *testing.T) {
	cfg := DefaultConfig(1)
	budget := NewResourceBudget()
	lease, e := budget.Reserve(AuthorizedTargets{targets: []Target{{}}, mode: ModeCPU}, cfg, Topology{CPUs: 1, FDLimit: 40, PageBytes: uint64(os.Getpagesize())}, MemoryUsage{})
	if e != nil {
		t.Fatal(e)
	}
	defer lease.Close()
	before := lease.Memory
	if _, e = lease.ReserveCPURings(16, cfg, uint64(os.Getpagesize())); e == nil {
		t.Fatal("original FD ceiling lost")
	}
	if lease.Memory != before {
		t.Fatal("refusal charged resources")
	}
}
