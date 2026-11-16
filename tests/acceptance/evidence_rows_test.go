// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package acceptance

import (
	"strings"
	"testing"
)

// goodEvidenceReport is a report whose every row comes to what evExpected says for a host whose sandbox usability is given.
func goodEvidenceReport(sandboxUsable bool) *evReport {
	r := &evReport{}
	for id, want := range evExpected {
		ok := want == evSatisfied || want == evNeedsSandbox && sandboxUsable
		r.add(id, true, ok, "observed")
	}
	return r
}

// The in-process acceptance run is a verdict: problems names every row that is missing, repeated, unknown, optional, reasonless or that comes
// out other than evExpected says. Each case below changes one thing in an otherwise good report.
func TestEvidenceReportProblemsFailsEveryDeviation(t *testing.T) {
	for _, usable := range []bool{true, false} {
		if p := goodEvidenceReport(usable).problems(usable); len(p) != 0 {
			t.Fatalf("a report that comes to evExpected has problems (sandbox usable %v): %v", usable, p)
		}
	}
	cases := []struct {
		name    string
		usable  bool
		mutate  func(r *evReport)
		contain string
	}{
		{"a required row unsatisfied", true, func(r *evReport) { r.rows[evIndex(r, "canary_storage_scan")].Satisfied = false }, `row "canary_storage_scan" must be SATISFIED`},
		{"an inconclusive probe is not acceptance", true, func(r *evReport) {
			r.rows[evIndex(r, "restore_project_without_metric_series")].Satisfied = false
		}, `row "restore_project_without_metric_series" must be SATISFIED`},
		{"a row by design unsatisfied turns satisfied", true, func(r *evReport) { r.rows[evIndex(r, "profile_real_capture_or_sdk")].Satisfied = true }, `NOT SATISFIED by design here but came out satisfied`},
		{"a mapped frame without a usable sandbox", false, func(r *evReport) { r.rows[evIndex(r, "frame_real_mapping")].Satisfied = true }, `satisfied exactly when the sandbox is usable`},
		{"an unmapped frame with a usable sandbox", true, func(r *evReport) { r.rows[evIndex(r, "frame_real_mapping")].Satisfied = false }, `satisfied exactly when the sandbox is usable`},
		{"a row never added", true, func(r *evReport) {
			r.rows = append(r.rows[:evIndex(r, "trace_view_and_link")], r.rows[evIndex(r, "trace_view_and_link")+1:]...)
		}, `row "trace_view_and_link" was never added`},
		{"a row added twice", true, func(r *evReport) { r.add("trace_view_and_link", true, true, "again") }, `row "trace_view_and_link" was added 2 times`},
		{"a row nobody wrote down", true, func(r *evReport) { r.add("a_new_row", true, true, "new") }, `row "a_new_row" is not in evExpected`},
		{"an optional row", true, func(r *evReport) { r.rows[evIndex(r, "backup_before_deletion")].Required = false }, `row "backup_before_deletion" is optional`},
		{"a row without a reason", true, func(r *evReport) { r.rows[evIndex(r, "release_registry_view")].Reason = "" }, `row "release_registry_view" carries no reason`},
	}
	for _, c := range cases {
		r := goodEvidenceReport(c.usable)
		c.mutate(r)
		p := r.problems(c.usable)
		if len(p) == 0 || !strings.Contains(strings.Join(p, "\n"), c.contain) {
			t.Fatalf("%s: problems = %v, want one containing %q", c.name, p, c.contain)
		}
	}
	if p := (&evReport{}).problems(true); len(p) != len(evExpected) {
		t.Fatalf("an empty report must name every expected row as never added: %d problems for %d rows", len(p), len(evExpected))
	}
}

func evIndex(r *evReport, id string) int {
	for i, row := range r.rows {
		if row.ID == id {
			return i
		}
	}
	panic("no row " + id)
}
