//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"testing"
)

// 04.02-C16 mutation battery re-run (mut0402, G119 G126 G128 G129 G146 G155 G159): the working lease and the profile
// admission replay at their boundaries.

func TestReserveWorkingRefusesNothingAndANilLease(t *testing.T) {
	if w, e := (*Reservation)(nil).ReserveWorking(1, 0); !errors.Is(e, ErrResources) || w != nil {
		t.Errorf("a nil reservation: %v, %v", w, e)
	}
	r, e := NewResourceBudget().Reserve(authTargets(1, ModeCPU), DefaultConfig(1), Topology{CPUs: 8, FDLimit: 4096, PageBytes: testPage}, MemoryUsage{})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	before := r.Memory
	if w, e := r.ReserveWorking(0, 0); !errors.Is(e, ErrResources) || w != nil {
		t.Errorf("a lease of no memory: %v, %v", w, e)
	}
	if r.Memory != before {
		t.Errorf("the refusal charged %d bytes", r.Memory-before)
	}
}

func TestReserveWorkingAdmitsExactlyWhatIsLeftOfTheSharedBudget(t *testing.T) {
	cfg := DefaultConfig(1)
	b := NewResourceBudget()
	r, e := b.Reserve(authTargets(1, ModeCPU), cfg, Topology{CPUs: 8, FDLimit: 4096, PageBytes: testPage}, MemoryUsage{})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	left := cfg.MaxMemory - b.memory
	if w, e := r.ReserveWorking(left+1, 0); !errors.Is(e, ErrResources) || w != nil {
		t.Errorf("one byte more than is left: %v, %v", w, e)
	}
	w, e := r.ReserveWorking(left, 0)
	if e != nil || w == nil {
		t.Fatalf("exactly what is left: %v, %v", w, e)
	}
	if b.memory != cfg.MaxMemory {
		t.Errorf("the budget holds %d of %d", b.memory, cfg.MaxMemory)
	}
	if w2, e := r.ReserveWorking(1, 0); !errors.Is(e, ErrResources) || w2 != nil {
		t.Errorf("one byte when nothing is left: %v, %v", w2, e)
	}
	w.Close()
	if b.memory != cfg.MaxMemory-left {
		t.Errorf("the lease did not give its bytes back: %d", b.memory)
	}
}

// The budget is shared between captures, each with the memory ceiling of its own signed configuration. What the other
// captures hold counts against a lease's ceiling: a 16 MiB capture cannot take working memory while 33 MiB are charged.
func TestReserveWorkingCountsWhatOtherCapturesHoldAgainstItsOwnCeiling(t *testing.T) {
	b := NewResourceBudget()
	topology := Topology{CPUs: 8, FDLimit: 4096, PageBytes: testPage}
	small := smallRing(16 << 20)
	mine, e := b.Reserve(authTargets(1, ModeCPU), small, topology, MemoryUsage{})
	if e != nil {
		t.Fatal(e)
	}
	defer mine.Close()
	other, e := b.Reserve(authTargets(1, ModeCPU), DefaultConfig(1), topology, MemoryUsage{})
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if _, e = other.ReserveWorking(30<<20, 0); e != nil {
		t.Fatal(e)
	}
	if b.memory <= small.MaxMemory {
		t.Fatalf("the fixture needs the shared budget above 16 MiB, got %d", b.memory)
	}
	if w, e := mine.ReserveWorking(1, 0); !errors.Is(e, ErrResources) || w != nil {
		t.Errorf("1 byte of working memory with %d bytes charged against a 16 MiB ceiling: %v, %v", b.memory, w, e)
	}
}

func TestProfileAdmissionHeadroomRefusalsAndBoundaries(t *testing.T) {
	cfg := DefaultConfig(1)
	for _, targets := range []uint64{0, 257, 1 << 40} {
		if _, e := ProfileAdmissionHeadroom(cfg, true, targets, 8, 4096, MemoryUsage{}); !errors.Is(e, ErrInvalid) {
			t.Errorf("%d targets: %v, want ErrInvalid", targets, e)
		}
	}
	// A reservation the budget refuses is the refusal of the replay (no lease exists to close).
	if _, e := ProfileAdmissionHeadroom(cfg, true, 1, 8, 4096, MemoryUsage{HelperRSS: 2 * MaxMemoryBytes}); !errors.Is(e, ErrResources) {
		t.Errorf("helper resident size above the budget: %v", e)
	}
	// The working leases take 3 descriptors per target and 6 more: with 4 KiB rings and 40 CPUs, 17 targets use 190 for the
	// capture and 57 for the leases (247 of the 256); one descriptor per target more would not fit.
	small := cfg
	small.RingBytes = 4096
	if head, e := ProfileAdmissionHeadroom(small, true, 17, 40, 4096, MemoryUsage{}); e != nil || head == 0 {
		t.Errorf("17 targets on 40 CPUs: %d, %v", head, e)
	}
	// 20 targets need more than the budget leaves (22+2*20 MiB of leases behind 6 MiB of buffers)
	if _, e := ProfileAdmissionHeadroom(small, true, 20, 40, 4096, MemoryUsage{}); !errors.Is(e, ErrResources) {
		t.Errorf("20 targets on 40 CPUs: %v, want ErrResources", e)
	}
}
