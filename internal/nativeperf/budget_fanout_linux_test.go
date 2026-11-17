//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package nativeperf

import (
	"errors"
	"os"
	"testing"
)

// Wave 18 (04.03-C11): the overhead measurement of a 64-thread target summed 76.4 MB against the 64 MiB budget. The
// product's own admission is the authority on what a target of that many threads costs: every ring (data plus metadata
// page) of every thread, the fixed per-target buffers and the resident sizes of the helper and of the exporting peer.
// These pin that admission at the sizes the fan-out fixtures use: 16, 64 and 256 threads.

func fanoutAdmission(t *testing.T, cfg Config, threads uint64, usage MemoryUsage) (*Reservation, error) {
	t.Helper()
	page := uint64(os.Getpagesize())
	r, err := NewResourceBudget().Reserve(authTargets(1, ModeCPU), cfg, Topology{CPUs: 8, FDLimit: 4096, PageBytes: page}, usage)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { r.Close() })
	if _, err = r.ReserveCPURings(threads, cfg, page); err != nil {
		return nil, err
	}
	return r, nil
}

func TestFanoutTargetsAreAdmittedWithinTheBudgetOrRefused(t *testing.T) {
	cfg := DefaultConfig(1)
	// what the 64-thread fixture measured: a 21.6 MB helper and a 12 MB exporting peer
	usage := MemoryUsage{HelperRSS: 22 << 20, ExportRSS: 12 << 20}
	page := uint64(os.Getpagesize())
	for _, threads := range []uint64{1, 16, 65, 100} {
		r, err := fanoutAdmission(t, cfg, threads, usage)
		if err != nil {
			t.Errorf("%d threads refused at default ring size: %v", threads, err)
			continue
		}
		want := threads*(cfg.RingBytes+page) + (1<<20 + 256<<10) + usage.HelperRSS + usage.ExportRSS
		if r.Memory != want || r.Memory > cfg.MaxMemory {
			t.Errorf("%d threads: charged %d, want %d (budget %d)", threads, r.Memory, want, cfg.MaxMemory)
		}
	}
	// Whatever is admitted fits; what does not fit is refused at admission with resource_limit, and refusal is monotonic:
	// no larger target is admitted after a smaller one was refused.
	refused := false
	for threads := uint64(1); threads <= 257; threads++ {
		r, err := fanoutAdmission(t, cfg, threads, usage)
		switch {
		case err != nil:
			refused = true
			if !errors.Is(err, ErrResources) {
				t.Fatalf("%d threads: %v", threads, err)
			}
		case refused:
			t.Fatalf("%d threads admitted after a smaller target was refused", threads)
		case r.Memory > cfg.MaxMemory:
			t.Fatalf("%d threads admitted at %d bytes, over the %d budget", threads, r.Memory, cfg.MaxMemory)
		}
	}
	if !refused {
		t.Fatal("257 threads were admitted")
	}
	// a 256-thread fixture is 257 threads with the main thread: refused by the session's descriptor ceiling at any ring size
	if page != 4096 {
		return
	}
	small := cfg
	small.RingBytes = 4096
	if _, err := fanoutAdmission(t, small, 257, MemoryUsage{}); !errors.Is(err, ErrResources) {
		t.Errorf("257 threads with the smallest rings and no resident baseline: %v", err)
	}
	if _, err := fanoutAdmission(t, small, MaxSessionFDs-5, MemoryUsage{}); err != nil {
		t.Errorf("the largest target the descriptor ceiling allows (%d threads) with the smallest rings: %v", MaxSessionFDs-5, err)
	}
}
