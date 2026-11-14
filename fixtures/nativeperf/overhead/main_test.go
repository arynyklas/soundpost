//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"math"
	"testing"
)

// The runs below are hand-made arithmetic inputs for the verdict logic. They are
// not measurements and never appear in a report.

func runs(mode string, cpuNs, thru float64, n int, hwmKiB uint64) []run {
	var out []run
	for i := 0; i < n; i++ {
		out = append(out, run{Mode: mode, CPUNsPerIter: cpuNs, ThroughputPS: thru, HelperCPUSec: 1, ClientCPUSec: 1, HelperHWMKiB: hwmKiB, ClientHWMKiB: hwmKiB, RingBytes: 1 << 20, HelperFDsPeak: 20, Samples: 100})
	}
	return out
}

func TestCPUOverheadBudgetIsThreePercentInclusive(t *testing.T) {
	for _, tc := range []struct {
		capture float64
		ok      bool
	}{{100, true}, {102.99, true}, {103, true}, {103.01, false}, {150, false}, {90, true}} {
		var fr fixtureResult
		evaluate(&fr, runs("baseline", 100, 1000, 5, 1000), runs("capture", tc.capture, 1000, 5, 1000), 120)
		if fr.CPUBudgetOK != tc.ok {
			t.Errorf("capture %.2f ns/iter vs baseline 100: budget ok=%v, want %v (overhead %.4f%%)", tc.capture, fr.CPUBudgetOK, tc.ok, fr.OverheadPct)
		}
		if tc.ok != (len(fr.Failures) == 0) {
			t.Errorf("capture %.2f: failures %v", tc.capture, fr.Failures)
		}
	}
	var fr fixtureResult
	evaluate(&fr, runs("baseline", 100, 1000, 5, 1000), runs("capture", 110, 900, 5, 1000), 120)
	if math.Abs(fr.OverheadPct-10) > 1e-9 || math.Abs(fr.ThroughputPct+10) > 1e-9 {
		t.Errorf("overhead %.6f%% throughput %.6f%%", fr.OverheadPct, fr.ThroughputPct)
	}
}

func TestMemoryBudgetIs64MiBCombinedConservative(t *testing.T) {
	// helper HWM + client HWM + ring bytes, per capture run, worst run wins
	limit := uint64(64 << 20)
	ring := uint64(1 << 20)
	half := (limit - ring) / 2 >> 10 // KiB per process so the sum is exactly the limit
	var fr fixtureResult
	evaluate(&fr, runs("baseline", 100, 1000, 3, 0), runs("capture", 100, 1000, 3, half), 10)
	if fr.MemoryBytes != limit || !fr.MemoryBudgetOK {
		t.Errorf("exactly at the budget: %d bytes ok=%v", fr.MemoryBytes, fr.MemoryBudgetOK)
	}
	fr = fixtureResult{}
	evaluate(&fr, runs("baseline", 100, 1000, 3, 0), runs("capture", 100, 1000, 3, half+1), 10)
	if fr.MemoryBudgetOK || len(fr.Failures) == 0 {
		t.Errorf("over the budget by one KiB per process passed: %d bytes", fr.MemoryBytes)
	}
	// one bad run among good ones is not averaged away
	mixed := append(runs("capture", 100, 1000, 4, 1000), runs("capture", 100, 1000, 1, half+1)...)
	fr = fixtureResult{}
	evaluate(&fr, runs("baseline", 100, 1000, 5, 0), mixed, 10)
	if fr.MemoryBudgetOK {
		t.Error("the worst run must decide the memory budget")
	}
}

func TestEvaluateNeverPassesWithoutBothModes(t *testing.T) {
	for name, tc := range map[string]struct{ base, capt []run }{"no baseline": {nil, runs("capture", 100, 1000, 5, 1)}, "no capture": {runs("baseline", 100, 1000, 5, 1), nil}, "neither": {nil, nil}} {
		var fr fixtureResult
		evaluate(&fr, tc.base, tc.capt, 10)
		if len(fr.Failures) == 0 || fr.CPUBudgetOK || fr.MemoryBudgetOK {
			t.Errorf("%s: failures %v cpu ok %v memory ok %v", name, fr.Failures, fr.CPUBudgetOK, fr.MemoryBudgetOK)
		}
	}
}

func TestSummarizeStatistics(t *testing.T) {
	s := summarize([]float64{2, 4, 4, 4, 5, 5, 7, 9})
	if s.Mean != 5 || s.Min != 2 || s.Max != 9 || math.Abs(s.Stdev-2.138089935) > 1e-6 || math.Abs(s.StdErr-s.Stdev/math.Sqrt(8)) > 1e-12 {
		t.Errorf("%+v", s)
	}
	if got := summarize(nil); got != (stat{}) {
		t.Errorf("empty: %+v", got)
	}
}

func TestBudgetsAreTheApprovedOnes(t *testing.T) {
	if cpuOverheadBudgetPercent != 3.0 || memoryBudgetBytes != 64<<20 {
		t.Fatalf("budgets changed: %v %v", cpuOverheadBudgetPercent, memoryBudgetBytes)
	}
}
