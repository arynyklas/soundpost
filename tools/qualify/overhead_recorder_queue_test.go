// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func queueRun(raw string) *sdkOverheadRun {
	res := &sdkOverhead{}
	res.Rows.RecorderQueue = json.RawMessage(raw)
	return &sdkOverheadRun{Result: res, Raw: []byte(`{}`), Command: "node overhead.mjs --only recorder_queue"}
}

func runQueueRow(t *testing.T, run *sdkOverheadRun) Row {
	t.Helper()
	rc := overheadCtx(t)
	rc.cache["sdk-overhead-recorder-queue:node"] = run
	spec := RowSpec{ID: "overhead.x", Suite: SuiteOverhead, Build: "node"}
	row := runOverheadRecorderQueue(rc, spec)
	row.ID, row.Suite, row.Required, row.Subject = spec.ID, spec.Suite, true, rc.subject(spec)
	if err := ValidateRow(row); err != nil {
		t.Fatalf("recorder queue runner produced an invalid row: %v", err)
	}
	return row
}

func queueJSON(maxBytes, refusals string) string {
	return `{"steps":20000,"budget_bytes":1,"max_queue_bytes":` + maxBytes + `,"max_queue_records":1024,"end_queue_bytes":` + maxBytes +
		`,"queue_full_refusals":` + refusals + `,"first_refusal_step":900,"bun_exit_code":0,"verdict":{"queue_bytes":"within_budget"}}`
}

// The bound is judged here from the raw maximum: exactly 2 MiB is within, one byte more is a measured failure, and the harness's own
// budget_bytes and verdict (both lying in every fixture) are never trusted.
func TestOverheadRecorderQueueIsJudgedOnTheObservedMaximum(t *testing.T) {
	ok := runQueueRow(t, queueRun(queueJSON("2097152", "5")))
	if ok.Outcome != OutcomePassed || len(ok.Budgets) != 1 || !ok.Budgets[0].Within || ok.Budgets[0].Limit != 2097152 || ok.Budgets[0].Observed != 2097152 {
		t.Fatalf("exactly 2 MiB is within the budget: %+v", ok)
	}
	bad := runQueueRow(t, queueRun(queueJSON("2097153", "5")))
	if bad.Outcome != OutcomeFailed || bad.Budgets[0].Within || bad.Budgets[0].Observed != 2097153 {
		t.Fatalf("one byte over 2 MiB is a measured failure with the budget untouched: %+v", bad.Budgets)
	}
	rep := SuiteReport{Rows: []Row{bad}}
	rep.Verdict()
	if rep.ExitCode != ExitFail {
		t.Errorf("a missed recorder queue bound must block the claim, exit %d", rep.ExitCode)
	}
}

func TestOverheadRecorderQueueSaysWhenTheBoundWasNotExercised(t *testing.T) {
	row := runQueueRow(t, queueRun(queueJSON("1000", "0")))
	if row.Outcome != OutcomePassed || !strings.Contains(strings.Join(row.Limits, " "), "not exercised") {
		t.Errorf("a flood without a single refusal is observed, not exercised: %+v", row.Limits)
	}
	if exercised := runQueueRow(t, queueRun(queueJSON("1000", "3"))); strings.Contains(strings.Join(exercised.Limits, " "), "not exercised") {
		t.Errorf("a flood that made the queue refuse must not carry the not-exercised limit: %+v", exercised.Limits)
	}
}

func TestOverheadRecorderQueueRefusesWhatWasNotMeasured(t *testing.T) {
	if row := runQueueRow(t, queueRun(`{"not_measured":"the queue-bound runner printed no report"}`)); row.State != StateNotExercised || !strings.Contains(row.Reason, "queue-bound") {
		t.Errorf("a harness not_measured statement is not a pass: %+v", row)
	}
	if row := runQueueRow(t, queueRun(``)); row.State != StateNotExercised {
		t.Errorf("a result without the queue row is not exercised: %+v", row)
	}
	if row := runQueueRow(t, queueRun(`{"steps":0,"max_queue_bytes":0}`)); row.Outcome != OutcomeFailed {
		t.Errorf("a flood that queued nothing must not pass: %+v", row)
	}
	if row := runQueueRow(t, queueRun(`[1]`)); row.Outcome != OutcomeFailed {
		t.Errorf("an undecodable row must fail: %+v", row)
	}
	if row := runQueueRow(t, &sdkOverheadRun{Failure: "harness exited 1", Command: "node overhead.mjs", Exit: 1}); row.Outcome != OutcomeFailed || row.State != StateExercised {
		t.Errorf("a failed harness is a failed row: %+v", row)
	}
}

// M6: the queue row has its own harness run. A browser recorder run that failed or timed out (the shared run the batch row uses)
// neither fails nor hides it.
func TestOverheadRecorderQueueRowIsIndependentOfTheBrowserRecorderRun(t *testing.T) {
	rc := overheadCtx(t)
	rc.cache["sdk-overhead-recorder:node"] = &sdkOverheadRun{Failure: "the browser spec timed out", Exit: 124, Command: "node overhead.mjs --only recorder"}
	rc.cache["sdk-overhead-recorder-queue:node"] = queueRun(queueJSON("1000", "3"))
	row := runOverheadRecorderQueue(rc, RowSpec{ID: "overhead.x", Suite: SuiteOverhead, Build: "node"})
	if row.State != StateExercised || row.Outcome != OutcomePassed {
		t.Fatalf("the queue row followed the browser run: %+v", row)
	}
}

// M1: the queue bound is measured by Bun with a scripted page, no browser. Its row is built on the Bun build that runs it, not on a
// Chrome 142 that never takes part, and it needs the Node build that runs the harness.
func TestMatrixQueueBoundRowIsBuiltOnBunNotOnAChromeItNeverRuns(t *testing.T) {
	m, err := LoadMatrix(filepath.Join(repoRoot(t), "qualification", "matrix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range m.Rows {
		if r.ID != "overhead.browser.recorder_queue_bound" {
			continue
		}
		if r.Runner != "overhead_recorder_queue" || r.Build != "bun-1.3.14-linux-amd64" || !slices.Contains(r.Needs, "node-22-linux-amd64") || slices.ContainsFunc(r.Needs, func(n string) bool { return strings.HasPrefix(n, "chrome") }) {
			t.Fatalf("queue-bound row: runner %s build %s needs %v", r.Runner, r.Build, r.Needs)
		}
		return
	}
	t.Fatal("no overhead.browser.recorder_queue_bound row")
}
