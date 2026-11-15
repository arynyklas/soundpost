// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"encoding/json"
	"strings"
	"testing"
)

// runtimeRun returns a harness result whose Bun and Python delivered-mode rows are the given JSON texts.
func runtimeRun(bunJSON, pythonJSON string) *sdkOverheadRun {
	res := &sdkOverhead{}
	res.Rows.BunHTTP = json.RawMessage(bunJSON)
	res.Rows.PythonHTTP = json.RawMessage(pythonJSON)
	return &sdkOverheadRun{Result: res, Raw: []byte(`{}`), Command: "node overhead.mjs --only bun"}
}

func rowsJSON(t *testing.T, rows ...sdkHTTPRow) string {
	t.Helper()
	b, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func runRuntimeRow(t *testing.T, run *sdkOverheadRun, runtime, hashes string) Row {
	t.Helper()
	rc := overheadCtx(t)
	rc.cache["sdk-overhead-"+runtime+":node"] = run
	spec := RowSpec{ID: "overhead.x", Suite: SuiteOverhead, Build: "node", Params: map[string]string{"runtime": runtime, "handler_hashes": hashes}}
	row := runOverheadRuntimeServer(rc, spec)
	row.ID, row.Suite, row.Required, row.Subject = spec.ID, spec.Suite, true, rc.subject(spec)
	if err := ValidateRow(row); err != nil {
		t.Fatalf("runtime overhead runner produced an invalid row: %v", err)
	}
	return row
}

// The Bun and Python rows are judged on their own runtime's delivered-mode series, against the same pinned budgets as Node.
func TestOverheadRuntimeServerJudgesTheNamedRuntime(t *testing.T) {
	cheap := httpRow(3, []float64{1.0}, []float64{1.04}, []float64{100}, []float64{104})
	dear := httpRow(3, []float64{1.0}, []float64{1.30}, []float64{100}, []float64{160})
	run := runtimeRun(rowsJSON(t, cheap), rowsJSON(t, dear))
	if row := runRuntimeRow(t, run, "bun", "3"); row.Outcome != OutcomePassed || len(row.Budgets) != 2 || !row.Budgets[0].Within || !row.Budgets[1].Within {
		t.Errorf("bun is +4%% on both series, within the budgets: %+v", row)
	}
	py := runRuntimeRow(t, run, "python", "3")
	if py.Outcome != OutcomeFailed || py.Budgets[0].Within || py.Budgets[1].Within || py.Budgets[0].Observed != 30 || py.Budgets[1].Observed != 60 {
		t.Errorf("python is +30%% p95 and +60%% CPU: a measured failure with the budget untouched: %+v", py.Budgets)
	}
	rep := SuiteReport{Rows: []Row{py}}
	rep.Verdict()
	if rep.ExitCode != ExitFail {
		t.Errorf("a missed Python budget must block the claim, exit %d", rep.ExitCode)
	}
}

func TestOverheadRuntimeServerRefusesWhatWasNotMeasured(t *testing.T) {
	cheap := rowsJSON(t, httpRow(3, []float64{1.0}, []float64{1.01}, []float64{100}, []float64{101}))
	if row := runRuntimeRow(t, runtimeRun(`{"not_measured":"--only did not include bun"}`, cheap), "bun", "3"); row.State != StateNotExercised || !strings.Contains(row.Reason, "did not include bun") {
		t.Errorf("a harness not_measured statement is not a pass: %+v", row)
	}
	if row := runRuntimeRow(t, runtimeRun(``, cheap), "bun", "3"); row.State != StateNotExercised {
		t.Errorf("a result without the runtime's row is not exercised: %+v", row)
	}
	if row := runRuntimeRow(t, runtimeRun(`"junk"`, cheap), "bun", "3"); row.State != StateNotExercised {
		t.Errorf("an undecodable runtime row is not exercised: %+v", row)
	}
	if row := runRuntimeRow(t, runtimeRun(cheap, cheap), "python", "100"); row.Outcome != OutcomeFailed || row.State != StateExercised {
		t.Errorf("no handler_hashes=100 row: a measured failure, not a pass: %+v", row)
	}
	dropping := httpRow(3, []float64{1.0}, []float64{1.01}, []float64{100}, []float64{101})
	dropping.QueueFull = []float64{0, 7}
	if row := runRuntimeRow(t, runtimeRun(rowsJSON(t, dropping), cheap), "bun", "3"); row.Outcome != OutcomeFailed || !strings.Contains(strings.Join(row.Failures, " "), "queue_full") {
		t.Errorf("a run that kept up by dropping spans passed: %+v", row)
	}
	if row := runRuntimeRow(t, &sdkOverheadRun{Failure: "harness exited 1", Command: "node overhead.mjs", Exit: 1}, "bun", "3"); row.Outcome != OutcomeFailed || row.State != StateExercised {
		t.Errorf("a failed harness is a failed row: %+v", row)
	}
}

func recorderRun(raw string) *sdkOverheadRun {
	res := &sdkOverhead{}
	res.Rows.Recorder = json.RawMessage(raw)
	return &sdkOverheadRun{Result: res, Raw: []byte(`{}`), Command: "node overhead.mjs --only recorder"}
}

func runRecorderRow(t *testing.T, run *sdkOverheadRun) Row {
	t.Helper()
	rc := overheadCtx(t)
	rc.cache["sdk-overhead-recorder:node"] = run
	spec := RowSpec{ID: "overhead.x", Suite: SuiteOverhead, Build: "node"}
	row := runOverheadRecorderBatch(rc, spec)
	row.ID, row.Suite, row.Required, row.Subject = spec.ID, spec.Suite, true, rc.subject(spec)
	if err := ValidateRow(row); err != nil {
		t.Fatalf("recorder overhead runner produced an invalid row: %v", err)
	}
	return row
}

func batchRows(p10, p100, p400 string) string {
	return `{"browser":"142.0.7444.59","playwright_exit_code":0,"worst_p95_ms":0.1,"rows":[` +
		`{"burst_nodes":10,"batches":60,"p50_ms":1,"p95_ms":` + p10 + `,"p99_ms":9,"max_ms":9},` +
		`{"burst_nodes":100,"batches":60,"p50_ms":1,"p95_ms":` + p100 + `,"p99_ms":9,"max_ms":9},` +
		`{"burst_nodes":400,"batches":60,"p50_ms":1,"p95_ms":` + p400 + `,"p99_ms":9,"max_ms":9}]}`
}

// The recorder budget is judged here from the raw per-burst p95 values: the worst burst decides, exactly 5 ms is within, and the
// harness's own worst_p95_ms figure (which says 0.1 in every fixture) is never trusted.
func TestOverheadRecorderBatchIsJudgedOnTheWorstBurst(t *testing.T) {
	ok := runRecorderRow(t, recorderRun(batchRows("3.1", "4.9", "5")))
	if ok.Outcome != OutcomePassed || len(ok.Budgets) != 1 || !ok.Budgets[0].Within || ok.Budgets[0].Observed != 5 || ok.Budgets[0].Limit != 5 || len(ok.Series) != 3 {
		t.Fatalf("worst burst exactly 5 ms is within the budget: %+v", ok)
	}
	bad := runRecorderRow(t, recorderRun(batchRows("3.1", "6.6", "4.0")))
	if bad.Outcome != OutcomeFailed || bad.Budgets[0].Within || bad.Budgets[0].Observed != 6.6 {
		t.Fatalf("a 100-node burst at 6.6 ms p95 is a measured failure with the budget untouched: %+v", bad.Budgets)
	}
	rep := SuiteReport{Rows: []Row{bad}}
	rep.Verdict()
	if rep.ExitCode != ExitFail {
		t.Errorf("a missed recorder budget must block the claim, exit %d", rep.ExitCode)
	}
}

func TestOverheadRecorderBatchRefusesWhatWasNotMeasured(t *testing.T) {
	if row := runRecorderRow(t, recorderRun(`{"not_measured":"Playwright printed no parseable report"}`)); row.State != StateNotExercised || !strings.Contains(row.Reason, "Playwright") {
		t.Errorf("a harness not_measured statement is not a pass: %+v", row)
	}
	if row := runRecorderRow(t, recorderRun(``)); row.State != StateNotExercised {
		t.Errorf("a result without the recorder row is not exercised: %+v", row)
	}
	if row := runRecorderRow(t, recorderRun(`{"browser":"x","rows":[]}`)); row.Outcome != OutcomeFailed {
		t.Errorf("a report without bursts must not pass: %+v", row)
	}
	if row := runRecorderRow(t, recorderRun(`[1]`)); row.Outcome != OutcomeFailed {
		t.Errorf("an undecodable recorder row must fail: %+v", row)
	}
	if row := runRecorderRow(t, &sdkOverheadRun{Failure: "harness exited 1", Command: "node overhead.mjs", Exit: 1}); row.Outcome != OutcomeFailed || row.State != StateExercised {
		t.Errorf("a failed harness is a failed row: %+v", row)
	}
}
