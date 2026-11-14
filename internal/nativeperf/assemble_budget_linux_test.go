//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import "testing"

func TestAssembleWorkingBudgetSharesAcquisitionCeiling(t *testing.T) {
	b := NewResourceBudget()
	cfg := DefaultConfig(1)
	a := AuthorizedTargets{targets: []Target{{TGID: 1, PIDNamespace: 2, ProcessStart: 3}}, mode: ModeCPU}
	r, e := b.Reserve(a, cfg, Topology{CPUs: 1, FDLimit: 1024, PageBytes: 4096}, MemoryUsage{})
	if e != nil {
		t.Fatal(e)
	}
	base := r.Memory
	w, e := r.ReserveWorking(10<<20, 9)
	if e != nil {
		t.Fatal(e)
	}
	if b.memory != base+10<<20 || w.Bytes() != 10<<20 {
		t.Fatal("working set not aggregate charged")
	}
	if _, e = r.ReserveWorking(64<<20, 0); e == nil {
		t.Fatal("second memory pool admitted")
	}
	if _, e = r.ReserveWorking(1, 256); e == nil {
		t.Fatal("FD ceiling bypass")
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	if b.memory != base {
		t.Fatal("double release or leak")
	}
	w, e = r.ReserveWorking(2<<20, 6)
	if e != nil {
		t.Fatal(e)
	}
	r.Close()
	w.Close()
	if b.memory != 0 || b.fds != 0 {
		t.Fatal("reservation/child close leaked")
	}
	if _, e = r.ReserveWorking(1, 1); e == nil {
		t.Fatal("closed parent extension")
	}
}
