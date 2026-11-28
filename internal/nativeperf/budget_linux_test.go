//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import "testing"

func TestResourceReservationIsAtomic(t *testing.T) {
	b := NewResourceBudget()
	cfg := DefaultConfig(1)
	targets := AuthorizedTargets{targets: []Target{{TGID: 1, PIDNamespace: 2, ProcessStart: 3}}, mode: ModeCPUOffCPU}
	if _, err := b.Reserve(targets, cfg, Topology{CPUs: 96, FDLimit: 128, OpenFDs: 8, PageBytes: 4096}, MemoryUsage{}); err == nil {
		t.Fatal("96 CPUs exceeded FD ceiling")
	}
	targets.mode = ModeCPU
	r, err := b.Reserve(targets, cfg, Topology{CPUs: 1, FDLimit: 256, OpenFDs: 8, PageBytes: 4096}, MemoryUsage{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Reserve(targets, cfg, Topology{CPUs: 1, FDLimit: 256, OpenFDs: 8, PageBytes: 4096}, MemoryUsage{HelperRSS: MaxMemoryBytes}); err == nil {
		t.Fatal("baseline bypass")
	}
	r.Close()
	r.Close()
	if b.memory != 0 || b.fds != 0 {
		t.Fatal("lease leaked")
	}
}
