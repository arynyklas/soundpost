// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	return `{"engine":"chromium","browser":"142.0.7444.59","playwright_exit_code":0,"worst_p95_ms":0.1,"rows":[` +
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

// firefoxBatchRows is a recorder report as the spec prints it for the stock Firefox run.
func firefoxBatchRows(engine, p400 string) string {
	return `{"engine":"` + engine + `","browser":"144.0.2","playwright_exit_code":0,"worst_p95_ms":0.1,"rows":[` +
		`{"burst_nodes":10,"batches":60,"p50_ms":0.3,"p95_ms":0.9,"p99_ms":2,"max_ms":2},` +
		`{"burst_nodes":100,"batches":60,"p50_ms":0.7,"p95_ms":1,"p99_ms":3,"max_ms":3},` +
		`{"burst_nodes":400,"batches":60,"p50_ms":1.9,"p95_ms":` + p400 + `,"p99_ms":11,"max_ms":11}]}`
}

func runRecorderRowOnFamily(t *testing.T, family string, run *sdkOverheadRun) Row {
	t.Helper()
	rc := overheadCtx(t)
	rc.probes["node"].Build.Family = family
	spec0 := rc.matrix.Builds["node"]
	spec0.Family = family
	rc.matrix.Builds["node"] = spec0
	rc.cache["sdk-overhead-recorder:node"] = run
	spec := RowSpec{ID: "overhead.x", Suite: SuiteOverhead, Build: "node"}
	row := runOverheadRecorderBatch(rc, spec)
	row.ID, row.Suite, row.Required, row.Subject = spec.ID, spec.Suite, true, rc.subject(spec)
	if err := ValidateRow(row); err != nil {
		t.Fatalf("recorder overhead runner produced an invalid row: %v", err)
	}
	return row
}

// A Firefox row is judged on the same 5 ms budget and only by a report that says Firefox ran: Chromium's numbers can never satisfy it, nor Firefox's a Chromium row.
func TestOverheadRecorderBatchFirefoxRowNeedsAFirefoxReport(t *testing.T) {
	if row := runRecorderRowOnFamily(t, "firefox", recorderRun(firefoxBatchRows("firefox", "4.2"))); row.Outcome != OutcomePassed || row.Budgets[0].Observed != 4.2 || len(row.Series) != 3 {
		t.Errorf("a Firefox report within the budget passes the Firefox row: %+v", row)
	}
	if row := runRecorderRowOnFamily(t, "firefox", recorderRun(firefoxBatchRows("firefox", "7.9"))); row.Outcome != OutcomeFailed || row.Budgets[0].Within || row.Budgets[0].Observed != 7.9 {
		t.Errorf("a 400-node burst at 7.9 ms p95 on Firefox is a measured failure with the budget untouched: %+v", row)
	}
	if row := runRecorderRowOnFamily(t, "firefox", recorderRun(firefoxBatchRows("chromium", "1"))); row.Outcome != OutcomeFailed || !strings.Contains(strings.Join(row.Failures, " "), `needs "firefox"`) {
		t.Errorf("a Chromium report must not satisfy the Firefox row: %+v", row)
	}
	if row := runRecorderRowOnFamily(t, "chrome", recorderRun(firefoxBatchRows("firefox", "1"))); row.Outcome != OutcomeFailed || !strings.Contains(strings.Join(row.Failures, " "), `needs "chromium"`) {
		t.Errorf("a Firefox report must not satisfy the Chrome row: %+v", row)
	}
	if row := runRecorderRowOnFamily(t, "firefox", recorderRun(`{"browser":"144.0.2","rows":[{"burst_nodes":10,"batches":60,"p95_ms":1}]}`)); row.Outcome != OutcomeFailed {
		t.Errorf("a report that names no engine proves nothing: %+v", row)
	}
}

func TestRecorderBrowserEnvNamesTheRowsOwnBrowserOnly(t *testing.T) {
	root := t.TempDir()
	launcher := filepath.Join(root, "fixtures", "sdk", "firefox", "firefox-bidi")
	if err := os.MkdirAll(filepath.Dir(launcher), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcher, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ff, why := recorderBrowserEnv(root, "/x/bun", &probeResult{Path: "/x/firefox", Build: Build{Family: "firefox"}})
	if why != "" {
		t.Fatal(why)
	}
	if got := strings.Join(ff, " "); got != "SOUNDPOST_BUN=/x/bun SOUNDPOST_RECORDER_BROWSER=firefox SOUNDPOST_FIREFOX=/x/firefox SOUNDPOST_CHROME=" {
		t.Errorf("Firefox row environment: %q", got)
	}
	cr, why := recorderBrowserEnv(root, "/x/bun", &probeResult{Path: "/x/chrome", Build: Build{Family: "chrome"}})
	if why != "" {
		t.Fatal(why)
	}
	if got := strings.Join(cr, " "); got != "SOUNDPOST_BUN=/x/bun SOUNDPOST_CHROME=/x/chrome SOUNDPOST_FIREFOX=" {
		t.Errorf("Chrome row environment (an inherited SOUNDPOST_FIREFOX must be emptied): %q", got)
	}
	if _, why := recorderBrowserEnv(t.TempDir(), "/x/bun", &probeResult{Path: "/x/firefox", Build: Build{Family: "firefox"}}); why == "" {
		t.Error("a Firefox row without the BiDi launcher cannot run: the reason must be reported, not a Chromium run")
	}
}
