//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"testing"
	"unsafe"
)

// CaptureCharge is the one formula the helper's admission uses and the harness
// ledger sums against the 64 MiB budget: they must never drift apart.
func TestCaptureChargeIsExactlyWhatReserveCharges(t *testing.T) {
	cfg := DefaultConfig(1)
	targets := AuthorizedTargets{targets: []Target{{TGID: 1, PIDNamespace: 2, ProcessStart: 3}}, mode: ModeCPUOffCPU}
	usage := MemoryUsage{HelperRSS: 10 << 20, ExportRSS: 12 << 20}
	r, err := NewResourceBudget().Reserve(targets, cfg, Topology{CPUs: 8, FDLimit: 256, OpenFDs: 8, PageBytes: 4096}, usage)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := CaptureCharge(true, 1, 8, cfg, 4096, usage)
	if err != nil || got != r.Memory {
		t.Fatalf("CaptureCharge %d (%v), Reserve charged %d", got, err, r.Memory)
	}
	// 1 target + 3 rings x 8 CPUs = 25 rings of (256 KiB + one 4 KiB page), 1 MiB + 256 KiB of per-target
	// buffers, and the helper's and its peer's resident sizes
	if want := uint64(25*(256<<10+4096) + (1<<20 + 256<<10) + 10<<20 + 12<<20); got != want {
		t.Fatalf("charge %d, want %d", got, want)
	}
	if _, err := CaptureCharge(true, 1, 8, cfg, 4096, MemoryUsage{HelperRSS: MaxMemoryBytes}); err == nil {
		t.Fatal("a charge over the budget was computed")
	}
}

// The reservation handed to the correlator is nominal: 16 KiB per buffered event
// and per task state. It is only a sound budget share if the physical worst case of
// one slot (an event carrying a full 128-frame switch-out stack and both task
// identities; a task state retaining its own full stack, in its map entries)
// stays under that, so the real allocation never exceeds what was reserved.
func TestCorrelatorPhysicalWorstCaseFitsItsReservation(t *testing.T) {
	const frames = 128
	chain := uint64(frames) * uint64(unsafe.Sizeof(CallchainEntry{}))
	key := uint64(unsafe.Sizeof(TaskKey{}))
	event := uint64(unsafe.Sizeof(SanitizedEvent{})) + uint64(unsafe.Sizeof(SchedulerSwitch{})) + 2*key + chain
	// a task state, its map entry (key, pointer, the map's own overhead taken as 2x) and its process entry
	task := uint64(unsafe.Sizeof(correlationTaskState{})) + chain + 2*(key+8) + 2*(uint64(unsafe.Sizeof(correlationProcess{}))+uint64(unsafe.Sizeof(correlationProcessState{})))
	if event > correlationSlotBytes || task > correlationSlotBytes {
		t.Fatalf("worst-case event %d B / task state %d B exceed the %d B slot", event, task, correlationSlotBytes)
	}
	c := NewCorrelator(DefaultConfig(1))
	if err := c.Configure(correlationDomain, []uint32{0, 1, 2, 3, 4, 5, 6, 7}, 32<<20); err != nil {
		t.Fatal(err)
	}
	if physical := uint64(c.maxEvents)*event + uint64(c.maxTasks)*task; physical > c.reserved {
		t.Fatalf("worst-case physical %d B over the %d B reservation", physical, c.reserved)
	}
	if c.maxEvents < 1000 {
		t.Fatalf("32 MiB must buffer about 1000 events (the 100 ms reorder window of a contended CPU), got %d", c.maxEvents)
	}
}
