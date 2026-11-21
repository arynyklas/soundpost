// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// D54: the server overhead budget is judged on the warm steady state of a harness run that used a fixed discarded warm-up, a steady window of
// at least 30 s and at least 5 alternating runs. A row without that statement, or one the harness marks as shortened, is a failure and never a pass.
func TestOverheadServerRowsAreOnlyJudgedWhenMeasuredUnderD54(t *testing.T) {
	cheap := httpRow(3, []float64{1.0}, []float64{1.01}, []float64{100}, []float64{101})
	if cheap.Measurement == nil || !cheap.Measurement.Conforms {
		t.Fatalf("the test helper must produce a D54-conforming row: %+v", cheap.Measurement)
	}
	if row := runServerRow(t, sdkRun(cheap), "3"); row.Outcome != OutcomePassed {
		t.Fatalf("a conforming cheap row passes: %+v", row)
	}
	for name, mutate := range map[string]func(r *sdkHTTPRow){
		"no measurement block (an older harness)": func(r *sdkHTTPRow) { r.Measurement = nil },
		"shortened protocol": func(r *sdkHTTPRow) {
			r.Measurement = &sdkMeasurement{Protocol: "shortened diagnostic window, not D54", GatedWindow: "warm", NotConform: []string{"steady-state window 3 s < 30 s"}}
		},
		"the cold window gated": func(r *sdkHTTPRow) {
			r.Measurement = &sdkMeasurement{Protocol: "D54", Conforms: true, GatedWindow: "cold"}
		},
	} {
		row := cheap
		mutate(&row)
		for label, run := range map[string]*sdkOverheadRun{"node": sdkRun(row)} {
			got := runServerRow(t, run, "3")
			if got.Outcome != OutcomeFailed || len(got.Failures) == 0 || len(got.Budgets) != 0 {
				t.Errorf("%s (%s): must fail without a budget claim, got %s %v %v", name, label, got.Outcome, got.Failures, got.Budgets)
			}
		}
	}
	if row := runServerRow(t, sdkRun(func() sdkHTTPRow {
		r := cheap
		r.Measurement = &sdkMeasurement{Protocol: "shortened diagnostic window, not D54", GatedWindow: "warm", NotConform: []string{"steady-state window 3 s < 30 s", "2 repetitions < 5"}}
		return r
	}()), "3"); !strings.Contains(strings.Join(row.Failures, " "), "2 repetitions < 5") {
		t.Errorf("the harness's reasons must reach the failure: %v", row.Failures)
	}
}

func TestOverheadHarnessCommandLineIsD54(t *testing.T) {
	w, err := LoadWorkloads(filepath.Join(repoRoot(t), "qualification", "workloads.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s := w.SDKServer
	if s.WarmupS < 10 || s.SteadyS < 30 || s.Runs < 5 {
		t.Errorf("workloads.yaml must pin at least the D54 protocol (warm-up 10 s, steady 30 s, 5 runs): %+v", s)
	}
	args := overheadArgs(s.RPS, s.WarmupS, s.SteadyS, s.Runs, "--only", "bun")
	if slices.Contains(args, "--duration-s") {
		t.Errorf("--duration-s is gone from the harness (D54): %v", args)
	}
	for flag, want := range map[string]string{"--requests-per-second": "1000", "--warmup-s": "10", "--steady-s": "30", "--runs": "5", "--only": "bun"} {
		i := slices.Index(args, flag)
		if i < 0 || i+1 >= len(args) || args[i+1] != want {
			t.Errorf("%s must be %s in %v", flag, want, args)
		}
	}
}
