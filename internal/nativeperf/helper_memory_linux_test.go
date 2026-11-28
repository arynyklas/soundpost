//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import "testing"

// Numbers measured from the privacy fixture on Debian 12 (6.1.0-54) and
// upstream 6.6.162: the helper runs inside the exporting process, so SO_PEERCRED
// names the helper's own PID, and its 25579520-byte resident set was charged
// once as HelperRSS and again as ExportRSS. The baseline reservation (3 ring
// sets + overhead + 2*RSS) then left too little for the 12+2+8+2 MiB assembly
// working leases and the helper answered resource_limit.
const measuredSharedProcessRSS = 25579520

func TestHelperDoesNotChargeOneProcessTwice(t *testing.T) {
	rss := func(pid int) (uint64, error) { return measuredSharedProcessRSS, nil }
	usage, err := chargeableMemory(4242, 4242, rss)
	if err != nil {
		t.Fatal(err)
	}
	if usage.HelperRSS != measuredSharedProcessRSS || usage.ExportRSS != 0 {
		t.Fatalf("one address space was charged %+v; want it once", usage)
	}
	cfg := DefaultConfig(1)
	targets := AuthorizedTargets{targets: []Target{{TGID: 1, PIDNamespace: 2, ProcessStart: 3}}, mode: ModeCPUOffCPU}
	r, err := NewResourceBudget().Reserve(targets, cfg, Topology{CPUs: 2, FDLimit: 1048575, OpenFDs: 12, PageBytes: 4096}, usage)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// The assembled profile source's three working leases (assemble_source_linux.go).
	for _, memory := range []uint64{(12 << 20) + 2<<20, 8 << 20, 2 << 20} {
		w, err := r.ReserveWorking(memory, 0)
		if err != nil {
			t.Fatalf("working lease %d MiB refused after the shared-process baseline of %d bytes: %v", memory>>20, r.Memory, err)
		}
		defer w.Close()
	}
	if r.Memory > cfg.MaxMemory {
		t.Fatalf("reservation %d exceeds the %d budget", r.Memory, cfg.MaxMemory)
	}
}

// Separate processes are different address spaces: both stay charged, so the
// 64 MiB budget is not relaxed for a real helper plus a real export client.
func TestHelperStillChargesSeparateExportProcess(t *testing.T) {
	rss := func(pid int) (uint64, error) { return measuredSharedProcessRSS, nil }
	usage, err := chargeableMemory(4242, 4243, rss)
	if err != nil {
		t.Fatal(err)
	}
	if usage.HelperRSS != measuredSharedProcessRSS || usage.ExportRSS != measuredSharedProcessRSS {
		t.Fatalf("separate processes charged %+v", usage)
	}
	cfg := DefaultConfig(1)
	targets := AuthorizedTargets{targets: []Target{{TGID: 1, PIDNamespace: 2, ProcessStart: 3}}, mode: ModeCPUOffCPU}
	r, err := NewResourceBudget().Reserve(targets, cfg, Topology{CPUs: 2, FDLimit: 1048575, OpenFDs: 12, PageBytes: 4096}, usage)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err = r.ReserveWorking((12<<20)+2<<20, 0); err == nil {
		t.Fatal("two 25 MiB processes plus the assembly working set fit in 64 MiB")
	}
}
