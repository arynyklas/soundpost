//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"math"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
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

// The overhead client used to keep every sample of the capture (a callchain of up to 128 frames each) in memory for the
// whole run and to read a process high-water mark that only ever grows, so the "client" term of the memory budget was
// the harness's own retention and its earlier runs. The sink counts what the report needs and keeps no event.
func TestCaptureStatsKeepNoEventAndMatchSampleGaps(t *testing.T) {
	chain := make([]nativeperf.CallchainEntry, 128)
	cpu := func(tid uint32, at uint64) nativeperf.SanitizedEvent {
		return nativeperf.SanitizedEvent{Task: nativeperf.TaskKey{TID: tid}, Time: model.MonoNano(at), CPUEvent: &nativeperf.CPUSample{Callchain: chain}}
	}
	events := []nativeperf.SanitizedEvent{cpu(1, 100), cpu(2, 150), cpu(1, 400), {Task: nativeperf.TaskKey{TID: 1}, Time: 500}, cpu(2, 160), cpu(1, 350)}
	var s captureStats
	for i, e := range events {
		if s.Event(e) {
			t.Errorf("event %d retained: the sink must keep nothing", i)
		}
	}
	if s.samples != 5 || s.threads() != 2 {
		t.Errorf("samples %d threads %d, want 5 and 2", s.samples, s.threads())
	}
	want := qual.SampleGaps(events)
	if !reflect.DeepEqual(s.gaps, want) {
		t.Errorf("gaps %v, want the harness's %v", s.gaps, want)
	}
}

// 04 plan Task 2: a session has a fixed 256-descriptor ceiling and a target that does not fit it is refused explicitly with
// resource_limit. That refusal is the specified behavior; a refusal of a target that does fit is a defect and stays a failure.
func TestRefusalIsByThePlanOnlyWhenTheTargetCannotFitTheFDCeiling(t *testing.T) {
	for _, tc := range []struct {
		code    string
		threads int
		byPlan  bool
	}{
		{"resource_limit", 257, true},  // 256 workers + the main thread: 257 rings + 3 + 2
		{"resource_limit", 252, true},  // 252 + 5 = 257
		{"resource_limit", 251, false}, // 251 + 5 = 256 fits exactly
		{"resource_limit", 65, false},
		{"acquisition_failed", 257, false},
		{"", 257, false},
	} {
		got := classifyRefusal(tc.code, tc.threads)
		if (got != nil) != tc.byPlan {
			t.Errorf("%s with %d threads: by plan %v, want %v", tc.code, tc.threads, got != nil, tc.byPlan)
		}
		if got != nil && (got.FDsRequired != uint64(tc.threads)+5 || got.FDCeiling != nativeperf.MaxSessionFDs) {
			t.Errorf("%d threads: %+v", tc.threads, got)
		}
	}
}

func TestAFixtureRefusedByThePlanIsNotAFailureButAnExplicitOutcome(t *testing.T) {
	fr := fixtureResult{Refusal: classifyRefusal("resource_limit", 257)}
	if !fixtureOK(&fr) {
		t.Error("the plan's own admission refusal failed the fixture")
	}
	fr.Failures = []string{"capture run 1: workload exit 3"}
	if fixtureOK(&fr) {
		t.Error("a refusal does not excuse another failure")
	}
	if fixtureOK(&fixtureResult{}) {
		t.Error("a fixture with no result and no refusal passed")
	}
}

// The memory budget stays helper HWM + client HWM + rings (the rings are counted again on purpose, they are resident in the
// helper only as far as they were touched); the report breaks the worst run down so the number can be read.
func TestEvaluateReportsTheMemoryLedgerOfTheWorstRun(t *testing.T) {
	small := runs("capture", 100, 1000, 2, 1000)
	worst := run{Mode: "capture", CPUNsPerIter: 100, ThroughputPS: 1000, HelperHWMKiB: 21552, HelperAnonKiB: 5000, HelperFileKiB: 9000, ClientHWMKiB: 12000, ClientStartKiB: 9000, RingBytes: 65 * (256<<10 + 4096), Threads: 65}
	var fr fixtureResult
	evaluate(&fr, runs("baseline", 100, 1000, 3, 0), append(small, worst), 10)
	l, ok := fr.Detail["memory_ledger"].(memoryLedger)
	if !ok {
		t.Fatalf("no memory ledger in %v", fr.Detail)
	}
	if l.ConservativeBytes != fr.MemoryBytes || l.HelperHWMBytes != 21552<<10 || l.ClientHWMBytes != 12000<<10 || l.RingBytesAccounted != 65*(256<<10+4096) || l.Threads != 65 ||
		l.HelperAnonBytes != 5000<<10 || l.HelperFileBytes != 9000<<10 || l.ClientStartBytes != 9000<<10 || l.BudgetBytes != memoryBudgetBytes {
		t.Errorf("%+v", l)
	}
}
