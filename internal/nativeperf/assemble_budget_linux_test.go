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

// The product's admission of a profile capture is the Reserve charge plus the three ProfileSource leases; the headroom
// the replay reports is what is left for a consumer, and a capture whose peers already fill the budget is refused by
// the same ReserveWorking the product calls.
func TestProfileAdmissionHeadroomIsTheBudgetAfterTheCaptureChargeAndTheLeases(t *testing.T) {
	cfg := DefaultConfig(1)
	m := MemoryUsage{HelperRSS: 11 << 20, ExportRSS: 12 << 20}
	charge, err := CaptureCharge(true, 1, 8, cfg, 4096, m)
	if err != nil {
		t.Fatal(err)
	}
	mapping, assembly, export := ProfileWorkingBytes(1)
	if mapping != 14<<20 || assembly != 8<<20 || export != 2<<20 {
		t.Fatalf("leases %d %d %d", mapping, assembly, export)
	}
	got, err := ProfileAdmissionHeadroom(cfg, true, 1, 8, 4096, m)
	if want := cfg.MaxMemory - charge - mapping - assembly - export; err != nil || got != want {
		t.Fatalf("headroom %d, want %d (%v)", got, want, err)
	}
	if more, err := ProfileAdmissionHeadroom(cfg, true, 2, 8, 4096, m); err != nil || more >= got {
		t.Fatalf("a second target must cost its own rings, buffers and mapping table: %d vs %d (%v)", more, got, err)
	}
	// 24 MiB of leases do not fit behind a charge of 45 MiB
	if _, err = ProfileAdmissionHeadroom(cfg, true, 1, 8, 4096, MemoryUsage{HelperRSS: 20 << 20, ExportRSS: 30 << 20}); err == nil {
		t.Fatal("the product's leases were admitted behind a charge that leaves less than 24 MiB")
	}
	if _, err = ProfileAdmissionHeadroom(cfg, true, 0, 8, 4096, m); err == nil {
		t.Fatal("no targets")
	}
}
