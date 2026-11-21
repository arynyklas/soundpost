//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/privacy/scan"
)

// A clean trace is not enough: the audit must also have seen the real acquisition, the helper's THP opt-out and, in a
// scheduler capture, the ring exit probe. Each missing piece must be reported, never passed as vacuously clean.
func TestVacuityFailureNamesWhatTheTraceDoesNotShow(t *testing.T) {
	full := scan.StraceSummary{CPUOpens: 14, PerfIoctls: 69, Prctls: 3000, ThpDisables: 1, Ppolls: 100}
	if got := vacuityFailure(full, true); got != "" {
		t.Fatalf("a full trace was called vacuous: %s", got)
	}
	// Without a scheduler capture there is no ring exit probe to see.
	noPpoll := full
	noPpoll.Ppolls = 0
	if got := vacuityFailure(noPpoll, false); got != "" {
		t.Fatalf("a CPU-only run without ppoll was called vacuous: %s", got)
	}
	cases := map[string]struct {
		sum       scan.StraceSummary
		scheduler bool
		want      string
	}{
		"no acquisition":       {scan.StraceSummary{ThpDisables: 1, Ppolls: 1}, true, "real perf acquisition"},
		"one cpu open only":    {scan.StraceSummary{CPUOpens: 1, PerfIoctls: 69, ThpDisables: 1, Ppolls: 1}, true, "real perf acquisition"},
		"no thp opt-out":       {scan.StraceSummary{CPUOpens: 14, PerfIoctls: 69, Prctls: 3000, Ppolls: 100}, true, "PR_SET_THP_DISABLE"},
		"no thp opt-out (cpu)": {scan.StraceSummary{CPUOpens: 14, PerfIoctls: 69, Prctls: 3000}, false, "PR_SET_THP_DISABLE"},
		"scheduler no ppoll":   {scan.StraceSummary{CPUOpens: 14, PerfIoctls: 69, ThpDisables: 1}, true, "no ppoll"},
	}
	for name, c := range cases {
		if got := vacuityFailure(c.sum, c.scheduler); !strings.Contains(got, c.want) {
			t.Errorf("%s: got %q, want it to mention %q", name, got, c.want)
		}
	}
}
