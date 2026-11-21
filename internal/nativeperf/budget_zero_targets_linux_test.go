//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"testing"
)

// 04.02-C16 mutation battery re-run (mut0402, P-B03): since CaptureCharge refuses a capture of zero rings, a capture of no
// targets in CPU mode was refused twice and the explicit `len(a.targets) == 0` of Reserve went unobserved. In off-CPU mode
// the scheduler rings alone are rings (3 per online CPU), so only that explicit check refuses a capture that names no target:
// Reserve has to refuse it itself, and charge nothing.
func TestReserveRefusesACaptureOfNoTargetsInEveryMode(t *testing.T) {
	cfg := DefaultConfig(1)
	for _, mode := range []CaptureMode{ModeCPU, ModeCPUOffCPU} {
		b := NewResourceBudget()
		r, e := b.Reserve(authTargets(0, mode), cfg, Topology{CPUs: 8, FDLimit: 4096, PageBytes: testPage}, MemoryUsage{})
		if !errors.Is(e, ErrResources) || r != nil {
			t.Errorf("mode %v: no targets: %v, lease %v, want ErrResources and no lease", mode, e, r)
			if r != nil {
				r.Close()
			}
		}
		if b.memory != 0 || b.fds != 0 {
			t.Errorf("mode %v: the refusal charged %d bytes and %d descriptors", mode, b.memory, b.fds)
		}
	}
}

// P-B15 (Reserve and CaptureCharge both carry `rings > MaxMemory/per`): the largest ring count whose rings alone fit
// MaxMemory is admitted when the fixed buffers still fit in the remainder. With 4 MiB rings (per ring 4 MiB + a page) the
// rings of a 64 MiB budget stop at 15 and leave 3.9 MiB, which holds the 1.75 MiB of fixed buffers of 3 targets: 15 rings
// is admitted, 16 is not. (The earlier argument that the fixed buffers always refuse the capture whose rings fill
// MaxMemory/per holds only for small rings.)
func TestReserveAdmitsTheLargestRingCountThatFitsAndRefusesOneMore(t *testing.T) {
	cfg := DefaultConfig(1)
	cfg.RingBytes = 4 << 20
	per := cfg.RingBytes + testPage
	if cfg.MaxMemory/per != 15 {
		t.Fatalf("the fixture assumes 15 rings fit, got %d", cfg.MaxMemory/per)
	}
	topology := Topology{CPUs: 4, FDLimit: 4096, PageBytes: testPage}
	// off-CPU: rings = targets + 3 per CPU = 3 + 12
	b := NewResourceBudget()
	r, e := b.Reserve(authTargets(3, ModeCPUOffCPU), cfg, topology, MemoryUsage{})
	if e != nil {
		t.Fatalf("15 rings of 4 MiB under 64 MiB with 1.75 MiB of fixed buffers: %v", e)
	}
	if want := 15*per + uint64(1<<20) + 3*(256<<10); r.Memory != want {
		t.Errorf("charged %d, want %d", r.Memory, want)
	}
	r.Close()
	// CaptureCharge is the public half of the same arithmetic and has its own copy of the bound.
	if got, e := CaptureCharge(true, 3, 4, cfg, testPage, MemoryUsage{}); e != nil || got != 15*per+uint64(1<<20)+3*(256<<10) {
		t.Errorf("CaptureCharge of 15 rings: %d, %v", got, e)
	}
	// 16 rings: 4 targets + 12
	if r, e = NewResourceBudget().Reserve(authTargets(4, ModeCPUOffCPU), cfg, topology, MemoryUsage{}); !errors.Is(e, ErrResources) {
		t.Errorf("16 rings of 4 MiB: %v", e)
		if r != nil {
			r.Close()
		}
	}
	if _, e = CaptureCharge(true, 4, 4, cfg, testPage, MemoryUsage{}); !errors.Is(e, ErrResources) {
		t.Errorf("CaptureCharge of 16 rings: %v", e)
	}
}
