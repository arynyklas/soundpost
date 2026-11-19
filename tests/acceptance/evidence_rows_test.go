// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package acceptance

import (
	"strings"
	"testing"
)

// goodEvidenceReport is a report whose every row comes to what evExpected says for the host given.
func goodEvidenceReport(host evHost) *evReport {
	r := &evReport{}
	for id, want := range evExpected {
		ok := want == evSatisfied || want == evNeedsSandbox && host.SandboxUsable || want == evNeedsCapture && host.CaptureUsable
		r.add(id, true, ok, "observed")
	}
	return r
}

var evHosts = []evHost{{true, true}, {true, false}, {false, true}, {false, false}}

// The in-process acceptance run is a verdict: problems names every row that is missing, repeated, unknown, optional, reasonless or that comes
// out other than evExpected says. Each case below changes one thing in an otherwise good report.
func TestEvidenceReportProblemsFailsEveryDeviation(t *testing.T) {
	for _, host := range evHosts {
		if p := goodEvidenceReport(host).problems(host); len(p) != 0 {
			t.Fatalf("a report that comes to evExpected has problems (host %+v): %v", host, p)
		}
	}
	both, noSandbox, noCapture := evHost{true, true}, evHost{false, true}, evHost{true, false}
	cases := []struct {
		name    string
		host    evHost
		mutate  func(r *evReport)
		contain string
	}{
		{"a required row unsatisfied", both, func(r *evReport) { r.rows[evIndex(r, "canary_storage_scan")].Satisfied = false }, `row "canary_storage_scan" must be SATISFIED`},
		{"an inconclusive probe is not acceptance", both, func(r *evReport) {
			r.rows[evIndex(r, "restore_project_without_metric_series")].Satisfied = false
		}, `row "restore_project_without_metric_series" must be SATISFIED`},
		{"constructed events do not satisfy the real capture row on a host that can capture", both, func(r *evReport) { r.rows[evIndex(r, "profile_real_capture_or_sdk")].Satisfied = false }, `satisfied exactly when a real native CPU capture is possible`},
		{"a real capture row satisfied on a host that cannot capture", noCapture, func(r *evReport) { r.rows[evIndex(r, "profile_real_capture_or_sdk")].Satisfied = true }, `satisfied exactly when a real native CPU capture is possible`},
		{"a mapped frame without a usable sandbox", noSandbox, func(r *evReport) { r.rows[evIndex(r, "frame_real_mapping")].Satisfied = true }, `satisfied exactly when the sandbox is usable`},
		{"an unmapped frame with a usable sandbox", both, func(r *evReport) { r.rows[evIndex(r, "frame_real_mapping")].Satisfied = false }, `satisfied exactly when the sandbox is usable`},
		{"a row never added", both, func(r *evReport) {
			r.rows = append(r.rows[:evIndex(r, "trace_view_and_link")], r.rows[evIndex(r, "trace_view_and_link")+1:]...)
		}, `row "trace_view_and_link" was never added`},
		{"a row added twice", both, func(r *evReport) { r.add("trace_view_and_link", true, true, "again") }, `row "trace_view_and_link" was added 2 times`},
		{"a row nobody wrote down", both, func(r *evReport) { r.add("a_new_row", true, true, "new") }, `row "a_new_row" is not in evExpected`},
		{"an optional row", both, func(r *evReport) { r.rows[evIndex(r, "backup_before_deletion")].Required = false }, `row "backup_before_deletion" is optional`},
		{"a row without a reason", both, func(r *evReport) { r.rows[evIndex(r, "release_registry_view")].Reason = "" }, `row "release_registry_view" carries no reason`},
	}
	for _, c := range cases {
		r := goodEvidenceReport(c.host)
		c.mutate(r)
		p := r.problems(c.host)
		if len(p) == 0 || !strings.Contains(strings.Join(p, "\n"), c.contain) {
			t.Fatalf("%s: problems = %v, want one containing %q", c.name, p, c.contain)
		}
	}
	if p := (&evReport{}).problems(both); len(p) != len(evExpected) {
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
