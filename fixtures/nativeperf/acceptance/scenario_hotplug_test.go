//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// fakeSysfs lays out a CPU directory like /sys/devices/system/cpu: the online list and cpuN/online for the CPUs but CPU 0.
func fakeSysfs(t *testing.T, online string, cpus ...int) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "online"), []byte(online+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range cpus {
		dir := filepath.Join(root, "cpu"+strconv.Itoa(c))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "online"), []byte("1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestCPUHotplugIsAnOptInScenarioReportedNotRunUntilAsked(t *testing.T) {
	if _, ok := hostScenarios["cpu_hotplug"]; !ok {
		t.Fatal("cpu_hotplug is not a registered host scenario")
	}
	a := &accept{res: &qual.QualificationResult{}}
	a.runHostScenarios()
	row := a.res.Scenarios["cpu_hotplug"]
	if row.State != qual.StateNotRun || !strings.Contains(row.Reason, "--host-scenarios cpu_hotplug") {
		t.Fatalf("cpu_hotplug without the flag: %+v", row)
	}
}

func TestPlanHotplugPicksTheHighestOnlineCPUButNeverCPUZeroAndSaysWhyItCannotRun(t *testing.T) {
	// the happy path: the highest-numbered online CPU
	root := fakeSysfs(t, "0-3", 1, 2, 3)
	h, why := planHotplug(root, 0)
	if why != "" || h.cpu != 3 || h.orig != "0-3" || len(h.online) != 4 {
		t.Fatalf("plan %+v %q", h, why)
	}
	// holes in the online list: the highest online CPU, not the highest number below the count
	root = fakeSysfs(t, "0,2-5", 2, 3, 4, 5)
	if h, why = planHotplug(root, 0); why != "" || h.cpu != 5 {
		t.Fatalf("plan %+v %q", h, why)
	}
	for _, tc := range []struct {
		name   string
		root   string
		euid   int
		reason string
	}{
		{"not root", fakeSysfs(t, "0-3", 1, 2, 3), 1000, "needs root"},
		{"fewer than four CPUs", fakeSysfs(t, "0-2", 1, 2), 0, "3 online CPUs"},
		{"one CPU", fakeSysfs(t, "0"), 0, "1 online CPUs"},
		{"no online list", t.TempDir(), 0, "unreadable"},
		{"garbled online list", fakeSysfs(t, "0-x", 1), 0, "bad CPU list"},
		{"hotplug file absent", fakeSysfs(t, "0-3", 1, 2), 0, "cannot be opened for writing"},
	} {
		if h, why := planHotplug(tc.root, tc.euid); h != nil || !strings.Contains(why, tc.reason) {
			t.Errorf("%s: plan %+v, reason %q, want one containing %q", tc.name, h, why, tc.reason)
		}
	}
	// a read-only hotplug file (a kernel without CPU hotplug, or a locked down host) is a precise reason, not a failure
	root = fakeSysfs(t, "0-3", 1, 2, 3)
	if err := os.Chmod(filepath.Join(root, "cpu3", "online"), 0o444); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 { // root writes through the mode bits
		if h, why := planHotplug(root, 0); h != nil || !strings.Contains(why, "cannot be opened for writing") {
			t.Errorf("read-only hotplug file: %+v %q", h, why)
		}
	}
}

func TestRestoreWritesTheCPUBackAndFailsWhenTheSetDiffers(t *testing.T) {
	root := fakeSysfs(t, "0-3", 1, 2, 3)
	h, why := planHotplug(root, 0)
	if why != "" {
		t.Fatal(why)
	}
	if err := h.set(false); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(h.file(3)); strings.TrimSpace(string(b)) != "0" {
		t.Fatalf("offline write: %q", b)
	}
	// the fake kernel does not update the list, so "restored" only holds when the list still reads as it did
	if err := h.restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if b, _ := os.ReadFile(h.file(3)); strings.TrimSpace(string(b)) != "1" {
		t.Fatalf("restore did not write 1: %q", b)
	}
	// the set differs from the one before: reported
	if err := os.WriteFile(filepath.Join(root, "online"), []byte("0-2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := h.restore(); err == nil || !strings.Contains(err.Error(), "was not restored") {
		t.Fatalf("a changed set was reported as restored: %v", err)
	}
}

// The CPU comes back on every exit path of the scenario, a panic included, and a body that left the set changed is a failed
// row rather than a green one.
func TestHotplugRestoreRunsOnReturnPanicAndFailedRestore(t *testing.T) {
	newHost := func() *hotplugHost {
		h, why := planHotplug(fakeSysfs(t, "0-3", 1, 2, 3), 0)
		if why != "" {
			t.Fatal(why)
		}
		return h
	}
	a := &accept{res: &qual.QualificationResult{}}

	h := newHost()
	row := a.withHotplugRestore(h, func() qual.Row {
		h.set(false)
		return qual.Supported([]string{"e"}, nil)
	})
	if b, _ := os.ReadFile(h.file(3)); strings.TrimSpace(string(b)) != "1" || row.State != qual.StateSupported {
		t.Fatalf("after a normal return: file %q row %+v", b, row)
	}

	h = newHost()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic was swallowed")
			}
		}()
		a.withHotplugRestore(h, func() qual.Row {
			h.set(false)
			panic("boom")
		})
	}()
	if b, _ := os.ReadFile(h.file(3)); strings.TrimSpace(string(b)) != "1" {
		t.Fatalf("the CPU was left offline after a panic: %q", b)
	}

	h = newHost()
	row = a.withHotplugRestore(h, func() qual.Row {
		os.WriteFile(filepath.Join(h.root, "online"), []byte("0-2\n"), 0o644)
		return qual.Supported([]string{"e"}, nil)
	})
	if row.State != qual.StateFailed || !strings.Contains(row.Reason, "not restored") {
		t.Fatalf("a changed CPU set passed as supported: %+v", row)
	}
}

func hotplugSample(at uint64, cpu uint32) nativeperf.SanitizedEvent {
	return nativeperf.SanitizedEvent{Kind: nativeperf.EventCPU, Time: model.MonoNano(at), CPU: cpu, CPUEvent: &nativeperf.CPUSample{}}
}

func TestJudgeCPUHotplug(t *testing.T) {
	const cpu, offDone, onStart, onDone = 7, 3_000, 5_000, 5_100
	var good []nativeperf.SanitizedEvent
	for i := range 10 {
		good = append(good, hotplugSample(uint64(1000+i), 2))
	}
	good = append(good, hotplugSample(3_500, 1), hotplugSample(6_000, 7), hotplugSample(6_100, 1))
	if v, why := judgeCPUHotplug(good, cpu, offDone, onStart, onDone); why != "" || v.Before != 10 || v.While != 1 || v.After != 2 || v.AfterOnTheCPU != 1 {
		t.Fatalf("an honest capture: %+v %q", v, why)
	}
	for _, tc := range []struct {
		name   string
		events func() []nativeperf.SanitizedEvent
		offEnd uint64
		reason string
	}{
		{"change not made", func() []nativeperf.SanitizedEvent { return good }, 0, "did not happen"},
		{"no samples before", func() []nativeperf.SanitizedEvent { return good[10:] }, offDone, "samples before the change"},
		{"nothing while offline", func() []nativeperf.SanitizedEvent {
			return append(append([]nativeperf.SanitizedEvent{}, good[:10]...), good[11:]...)
		}, offDone, "no samples while"},
		{"a sample names the offline CPU", func() []nativeperf.SanitizedEvent {
			return append(append([]nativeperf.SanitizedEvent{}, good...), hotplugSample(4_000, 7))
		}, offDone, "while it was offline"},
		{"nothing after", func() []nativeperf.SanitizedEvent { return good[:11] }, offDone, "after the CPU came back"},
		{"the CPU is never seen again", func() []nativeperf.SanitizedEvent {
			return append(append([]nativeperf.SanitizedEvent{}, good[:11]...), hotplugSample(6_100, 1))
		}, offDone, "no sample from CPU 7"},
	} {
		if _, why := judgeCPUHotplug(tc.events(), cpu, tc.offEnd, onStart, onDone); !strings.Contains(why, tc.reason) {
			t.Errorf("%s: %q, want one containing %q", tc.name, why, tc.reason)
		}
	}
}

// schedRun builds the scenResult of a scheduler capture that lost a CPU, the way runScenarioWith would have.
func schedRun(code string, complete, revoked bool) (*scenResult, *hotplugInjector) {
	r := &scenResult{Name: "x", Mode: "blocking", Extra: map[string]any{}, HelperBefore: qual.ProcUsage{FDs: 12}, HelperFDsAfter: 12}
	r.Cap.Ready, r.Cap.ErrorCode, r.Cap.Complete = true, code, complete
	domain := nativeperf.ClockDomain{HostID: "h", BootID: "b"}
	r.Cap.Proofs = []nativeperf.AcquisitionProof{{Domain: domain, CPUs: []uint32{0, 1, 2, 3}, Through: 1_000_000_000}, {Domain: domain, CPUs: []uint32{0, 1, 2, 3}, Through: 2_000_000_000, Progress: true}}
	for i := range 20 {
		r.Cap.Events = append(r.Cap.Events, hotplugSample(1_100_000_000+uint64(i)*10_000_000, 1))
	}
	c := &qual.Correlation{Revoked: revoked}
	if revoked {
		c.RevokedFrom = 2_900_000_000
		c.Intervals = []nativeperf.Interval{{Kind: nativeperf.IntervalUnknown, Start: 2_900_000_000, End: 3_200_000_000, Reason: nativeperf.ReasonGeneration, Correction: true}}
	}
	if complete {
		r.Cap.Proofs = append(r.Cap.Proofs, nativeperf.AcquisitionProof{Domain: domain, CPUs: []uint32{0, 1, 2, 3}, Through: 3_000_000_000, Final: true})
		c.FinalThrough = 3_000_000_000
	}
	r.Corr = c
	in := &hotplugInjector{}
	in.offDone = 3_000_000_000
	return r, in
}

func TestHotplugSchedPhaseAcceptsTheExplicitEndingAndRejectsEverySilentOne(t *testing.T) {
	if p := judgeRun("topology_changed", false, true); p.fail != "" || p.unknown != "" || p.pass == "" {
		t.Fatalf("the honest capture: %+v", p)
	}
	// the capture that goes on to a complete, final-proof ending after the CPU left is the defect: failed
	if p := judgeRun("", true, false); !strings.Contains(p.fail, "silent claim of complete coverage") {
		t.Fatalf("a silent complete capture: %+v", p)
	}
	// a stream that ended on topology_changed whose correlation was never revoked
	if p := judgeRun("topology_changed", false, false); !strings.Contains(p.fail, "not revoked") {
		t.Fatalf("an error without revocation: %+v", p)
	}
	// a leaked descriptor fails an otherwise honest capture
	r, in := schedRun("topology_changed", false, true)
	r.HelperFDsAfter = 14
	if p := judgeHotplugSchedPhase("p", r, in); !strings.Contains(p.fail, "descriptors") {
		t.Fatalf("a leak: %+v", p)
	}
	r, in = schedRun("topology_changed", false, true)
	r.HelperPerfAfter = 3
	if p := judgeHotplugSchedPhase("p", r, in); !strings.Contains(p.fail, "perf events still open") {
		t.Fatalf("an open perf event: %+v", p)
	}
	// nothing was provoked: not a pass and not a failure of the product
	r, in = schedRun("topology_changed", false, true)
	in.offDone = 0
	if p := judgeHotplugSchedPhase("p", r, in); p.unknown == "" || p.fail != "" || p.pass != "" {
		t.Fatalf("an unprovoked capture: %+v", p)
	}
	// a helper that refused the capture could not be judged
	r, in = schedRun("topology_changed", false, true)
	r.Cap.Ready, r.Cap.ErrorCode = false, "resource_limit"
	if p := judgeHotplugSchedPhase("p", r, in); !strings.Contains(p.unknown, "refused") {
		t.Fatalf("a refused capture: %+v", p)
	}
}

func judgeRun(code string, complete, revoked bool) hotplugPhase {
	r, in := schedRun(code, complete, revoked)
	return judgeHotplugSchedPhase("p", r, in)
}

// The row is supported only when every capture passed and the CPU set is what it was.
func TestHotplugRowFoldsThePhases(t *testing.T) {
	host := func() *hotplugHost {
		h, why := planHotplug(fakeSysfs(t, "0-3", 1, 2, 3), 0)
		if why != "" {
			t.Fatal(why)
		}
		return h
	}
	pass := hotplugPhase{name: "a", pass: "fine", detail: map[string]any{}}
	if row := foldHotplug(host(), map[string]any{}, []hotplugPhase{pass, {name: "b", pass: "fine too", detail: map[string]any{}}}); row.State != qual.StateSupported || row.Validate("cpu_hotplug") != nil || len(row.Evidence) != 3 {
		t.Fatalf("all passed: %+v", row)
	}
	if row := foldHotplug(host(), map[string]any{}, []hotplugPhase{pass, {name: "b", fail: "silent complete", detail: map[string]any{}}}); row.State != qual.StateFailed || !strings.Contains(row.Reason, "silent complete") {
		t.Fatalf("one failed: %+v", row)
	}
	if row := foldHotplug(host(), map[string]any{}, []hotplugPhase{pass, {name: "b", unknown: "nothing provoked", detail: map[string]any{}}}); row.State != qual.StateUnqualified || row.Exercised || !strings.Contains(row.Reason, "nothing provoked") {
		t.Fatalf("one unjudged: %+v", row)
	}
	h := host()
	os.WriteFile(filepath.Join(h.root, "online"), []byte("0-1\n"), 0o644)
	if row := foldHotplug(h, map[string]any{}, []hotplugPhase{pass}); row.State != qual.StateFailed || !strings.Contains(row.Reason, "not restored") {
		t.Fatalf("the CPU set was not restored: %+v", row)
	}
	// a failure is never hidden by a pass next to it
	if row := foldHotplug(host(), map[string]any{}, []hotplugPhase{{name: "x", fail: "f", detail: map[string]any{}}, {name: "y", unknown: "u", detail: map[string]any{}}}); row.State != qual.StateFailed {
		t.Fatalf("fail and unknown: %+v", row)
	}
}
