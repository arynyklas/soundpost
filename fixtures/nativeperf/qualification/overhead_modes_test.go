//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
)

// modeReport is a bound full-run overhead report measuring the named fixtures (CPU mode names them cpu, fanout16...;
// the scheduler capture mode names them cpu_offcpu, fanout16_offcpu... in a report of its own).
func modeReport(kernel, arch, command string, overhead float64, fixtures ...string) overheadReport {
	o := overheadFor(kernel, arch, true, overhead, 30<<20)
	o.Command = command
	o.Fixtures = nil
	for _, name := range fixtures {
		o.Fixtures = append(o.Fixtures, overheadFixture{Fixture: name, Seconds: 120, Repeats: 5, OverheadPct: overhead, MemoryBytes: 30 << 20, CPUBudgetOK: overhead <= 3, MemoryBudgetOK: true})
	}
	return sealed(o)
}

func TestSchedulerModeOverheadIsMergedBesideTheCPUModeReport(t *testing.T) {
	advertised := []string{"cpu", "fanout16", "cpu_offcpu", "fanout16_offcpu"}
	cpu := modeReport("k", "amd64", "overhead --capture-mode cpu", 0.5, "cpu", "fanout16")
	sched := modeReport("k", "amd64", "overhead --capture-mode offcpu", 1.5, "cpu_offcpu", "fanout16_offcpu")

	r := supportedResult("k", "amd64")
	if problems := mergeOverheads(r, []overheadReport{cpu, sched}, advertised); len(problems) != 0 {
		t.Fatalf("bound reports were refused: %v", problems)
	}
	if r.Overhead.State != qual.StateSupported {
		t.Fatalf("CPU-mode and scheduler-mode full runs did not support the overhead row: %+v", r.Overhead)
	}
	if err := r.Overhead.Validate("overhead"); err != nil {
		t.Fatal(err)
	}

	// the scheduler-mode measurement is required, not optional: without it the row is not supported
	r = supportedResult("k", "amd64")
	mergeOverheads(r, []overheadReport{cpu}, advertised)
	if r.Overhead.State == qual.StateSupported || !strings.Contains(r.Overhead.Reason, "cpu_offcpu") {
		t.Fatalf("an advertised scheduler-mode fixture without a result was reported as supported: %+v", r.Overhead)
	}

	// the 3% budget applies to scheduler mode as measured: a failing scheduler-mode fixture fails the row
	r = supportedResult("k", "amd64")
	mergeOverheads(r, []overheadReport{cpu, modeReport("k", "amd64", "overhead --capture-mode offcpu", 3.4, "cpu_offcpu", "fanout16_offcpu")}, advertised)
	if r.Overhead.State != qual.StateFailed || !strings.Contains(r.Overhead.Reason, "cpu_offcpu") {
		t.Fatalf("a scheduler-mode fixture over the 3%% budget did not fail the row: %+v", r.Overhead)
	}
}

func TestPooledOverheadReportsAreEachBoundAndNeverMeasureTheSameFixtureTwice(t *testing.T) {
	advertised := []string{"cpu", "cpu_offcpu"}
	cpu := modeReport("k", "amd64", "overhead --capture-mode cpu", 0.5, "cpu")
	sched := modeReport("k", "amd64", "overhead --capture-mode offcpu", 1.0, "cpu_offcpu")

	foreign := sched
	foreign.HostID = "host-2"
	foreign = sealed(foreign)
	r := supportedResult("k", "amd64")
	before := r.Overhead
	problems := mergeOverheads(r, []overheadReport{cpu, foreign}, advertised)
	if len(problems) == 0 {
		t.Fatal("a report of another host was pooled silently")
	}
	if r.Overhead.State == qual.StateSupported {
		t.Fatalf("a foreign report supplied the scheduler-mode measurement: %+v (before %+v)", r.Overhead, before)
	}

	twice := modeReport("k", "amd64", "overhead --capture-mode cpu again", 0.1, "cpu")
	r = supportedResult("k", "amd64")
	problems = mergeOverheads(r, []overheadReport{cpu, twice, sched}, advertised)
	if len(problems) == 0 || !strings.Contains(strings.Join(problems, ";"), "measured in two reports") {
		t.Fatalf("a fixture measured in two reports (the better run could be picked) was not refused: %v", problems)
	}
}
