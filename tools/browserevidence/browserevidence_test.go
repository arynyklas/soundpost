// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package browserevidence

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/releaseevidence"
)

const commit = "0123456789abcdef0123456789abcdef01234567"

// pwTestJSON is one Playwright test entry of a given project.
func pwTestJSON(project, expected, status string, results ...string) string {
	var rs []string
	for _, r := range results {
		e := ""
		if r == "failed" {
			e = `,"error":{"message":"expect(received).toBe(expected)\n  Expected: 1"}`
		}
		rs = append(rs, fmt.Sprintf(`{"status":%q%s}`, r, e))
	}
	return fmt.Sprintf(`{"projectName":%q,"expectedStatus":%q,"status":%q,"results":[%s]}`, project, expected, status, strings.Join(rs, ","))
}

// pwReportJSON builds a report with one file holding a top-level spec and a describe block.
func pwReportJSON(top, nested []string, errs string) string {
	spec := func(title, tests string) string {
		return fmt.Sprintf(`{"title":%q,"file":"auth.spec.ts","tests":[%s]}`, title, tests)
	}
	var topSpecs, nestedSpecs []string
	for i, t := range top {
		topSpecs = append(topSpecs, spec(fmt.Sprintf("top %d", i), t))
	}
	for i, t := range nested {
		nestedSpecs = append(nestedSpecs, spec(fmt.Sprintf("nested %d", i), t))
	}
	return fmt.Sprintf(`{"config":{},"suites":[{"title":"auth.spec.ts","file":"auth.spec.ts","specs":[%s],"suites":[{"title":"login","file":"auth.spec.ts","specs":[%s]}]}],"errors":[%s]}`,
		strings.Join(topSpecs, ","), strings.Join(nestedSpecs, ","), errs)
}

func listJSON() string {
	return pwReportJSON([]string{`{"projectName":"chromium","expectedStatus":"passed","status":"expected","results":[]},{"projectName":"firefox","expectedStatus":"passed","status":"expected","results":[]}`},
		[]string{`{"projectName":"chromium","expectedStatus":"passed","status":"expected","results":[]}`}, "")
}

func smokeJSON(key string, rows map[string][3]any) string {
	var parts []string
	for id, v := range rows {
		parts = append(parts, fmt.Sprintf(`{%q:%q,"required":%v,"satisfied":%v,"reason":%q,"detail":"d"}`, key, id, v[0], v[1], v[2]))
	}
	return fmt.Sprintf(`{"rows":[%s]}`, strings.Join(parts, ","))
}

func allSmokeRows(ids []string, key string, override map[string][3]any) string {
	rows := map[string][3]any{}
	for _, id := range ids {
		rows[id] = [3]any{true, true, "ok"}
	}
	for id, v := range override {
		rows[id] = v
	}
	return smokeJSON(key, rows)
}

func rowMap(rep releaseevidence.Report) map[string]releaseevidence.Row {
	m := map[string]releaseevidence.Row{}
	for _, r := range rep.Rows {
		m[r.ID] = r
	}
	return m
}

func TestExportKeepsEveryBrowserRowVerdict(t *testing.T) {
	results := pwReportJSON(
		[]string{`{"projectName":"chromium","expectedStatus":"passed","status":"expected","results":[{"status":"passed"}]}`},
		[]string{pwTestJSON("chromium", "passed", "unexpected", "failed")}, "")
	rep, err := Export(Inputs{
		PlaywrightList:    []byte(listJSON()),
		PlaywrightResults: []byte(results),
		Journeys:          []byte(allSmokeRows(JourneyRowIDs, "name", map[string][3]any{"actual_ids_equal_expected": {true, false, "ids_differ"}})),
		Evidence:          []byte(allSmokeRows(EvidenceRowIDs, "id", nil)),
	}, commit)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Kind != releaseevidence.KindBrowser {
		t.Fatalf("kind %s", rep.Kind)
	}
	if len(rep.Missing()) != 0 {
		t.Fatalf("missing %v", rep.Missing())
	}
	rows := rowMap(rep)
	if rows["playwright/run"].Status != releaseevidence.StatusPassed {
		t.Errorf("run row %+v", rows["playwright/run"])
	}
	if r := rows["playwright/auth.spec.ts > top 0"]; r.Status != releaseevidence.StatusPassed {
		t.Errorf("passing e2e test: %+v", r)
	}
	if r := rows["playwright/auth.spec.ts > login > nested 0"]; r.Status != releaseevidence.StatusFailed || !strings.Contains(r.Detail, "expect(received).toBe(expected)") {
		t.Errorf("failing e2e test must stay failed with its error line: %+v", r)
	}
	if r := rows["journeys/actual_ids_equal_expected"]; r.Status != releaseevidence.StatusFailed || !strings.Contains(r.Detail, "ids_differ") {
		t.Errorf("unsatisfied journey row: %+v", r)
	}
	if r := rows["journeys/gateway_dependency_child_span"]; r.Status != releaseevidence.StatusPassed {
		t.Errorf("satisfied journey row: %+v", r)
	}
	if r := rows["evidence/frame_real_mapping"]; r.Status != releaseevidence.StatusPassed {
		t.Errorf("evidence row: %+v", r)
	}
	for id := range rows {
		if strings.Contains(id, "firefox") {
			t.Errorf("a row of another project leaked in: %s", id)
		}
	}
	if want := 1 + 2 + len(JourneyRowIDs) + len(EvidenceRowIDs); len(rep.Expected) != want {
		t.Errorf("expected rows %d, want %d", len(rep.Expected), want)
	}
}

func TestExportNamesMissingResults(t *testing.T) {
	// No results, no smokes: every expected row is missing, none is invented.
	rep, err := Export(Inputs{PlaywrightList: []byte(listJSON())}, commit)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Rows) != 0 || len(rep.Missing()) != len(rep.Expected) {
		t.Fatalf("rows %d, missing %d of %d", len(rep.Rows), len(rep.Missing()), len(rep.Expected))
	}
	// A smoke that aborted early: its later rows are missing, the reported row stays failed.
	rep, err = Export(Inputs{
		PlaywrightList: []byte(listJSON()),
		Evidence:       []byte(smokeJSON("id", map[string][3]any{"serve_https_ready": {true, true, "ok"}, "bootstrap": {true, false, "refused"}})),
	}, commit)
	if err != nil {
		t.Fatal(err)
	}
	rows := rowMap(rep)
	if rows["evidence/bootstrap"].Status != releaseevidence.StatusFailed {
		t.Errorf("an early-abort failure row must be exported: %+v", rows["evidence/bootstrap"])
	}
	missing := strings.Join(rep.Missing(), " ")
	if !strings.Contains(missing, "evidence/frame_real_mapping") || strings.Contains(missing, "evidence/serve_https_ready") {
		t.Errorf("missing %s", missing)
	}
	// One e2e test of the list absent from the run is missing.
	partial := pwReportJSON([]string{`{"projectName":"chromium","expectedStatus":"passed","status":"expected","results":[{"status":"passed"}]}`}, nil, "")
	rep, err = Export(Inputs{PlaywrightList: []byte(listJSON()), PlaywrightResults: []byte(partial)}, commit)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(rep.Missing(), " "), "login > nested 0") {
		t.Errorf("a listed test with no result must be missing: %v", rep.Missing())
	}
}

func TestPlaywrightStatusesAreNeverPromoted(t *testing.T) {
	for name, c := range map[string]struct {
		test string
		want string
	}{
		"expected pass":  {pwTestJSON("chromium", "passed", "expected", "passed"), releaseevidence.StatusPassed},
		"unexpected":     {pwTestJSON("chromium", "passed", "unexpected", "failed"), releaseevidence.StatusFailed},
		"skipped":        {pwTestJSON("chromium", "skipped", "skipped", "skipped"), "skipped"},
		"flaky":          {pwTestJSON("chromium", "passed", "flaky", "failed", "passed"), "flaky"},
		"expected fail":  {pwTestJSON("chromium", "failed", "expected", "failed"), "expected_failure"},
		"never ran":      {pwTestJSON("chromium", "passed", "expected"), releaseevidence.StatusNotRun},
		"unknown status": {pwTestJSON("chromium", "passed", "weird", "passed"), releaseevidence.StatusNotRun},
	} {
		results := pwReportJSON([]string{c.test}, nil, "")
		list := pwReportJSON([]string{`{"projectName":"chromium","expectedStatus":"passed","status":"expected","results":[]}`}, nil, "")
		rep, err := Export(Inputs{PlaywrightList: []byte(list), PlaywrightResults: []byte(results)}, commit)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := rowMap(rep)["playwright/auth.spec.ts > top 0"].Status; got != c.want {
			t.Errorf("%s: status %q, want %q", name, got, c.want)
		}
	}
	// Runner errors fail the run row.
	results := pwReportJSON([]string{pwTestJSON("chromium", "passed", "expected", "passed")}, nil, `{"message":"Error: global setup failed\n at x"}`)
	list := pwReportJSON([]string{`{"projectName":"chromium","expectedStatus":"passed","status":"expected","results":[]}`}, nil, "")
	rep, err := Export(Inputs{PlaywrightList: []byte(list), PlaywrightResults: []byte(results)}, commit)
	if err != nil {
		t.Fatal(err)
	}
	if r := rowMap(rep)["playwright/run"]; r.Status != releaseevidence.StatusFailed || !strings.Contains(r.Detail, "global setup failed") {
		t.Errorf("run row %+v", r)
	}
}

func TestSmokeRowsAreStrictAboutTheirShape(t *testing.T) {
	list := []byte(listJSON())
	for name, in := range map[string]Inputs{
		"journeys without rows":   {PlaywrightList: list, Journeys: []byte(`{"observation":{}}`)},
		"journeys row no name":    {PlaywrightList: list, Journeys: []byte(`{"rows":[{"required":true,"satisfied":true}]}`)},
		"evidence row no verdict": {PlaywrightList: list, Evidence: []byte(`{"rows":[{"id":"x","required":true}]}`)},
		"not json":                {PlaywrightList: list, Evidence: []byte(`ok`)},
		"list is not playwright":  {PlaywrightList: []byte(`{"rows":[]}`)},
		"no list":                 {},
	} {
		if _, err := Export(in, commit); err == nil {
			t.Errorf("%s: exported", name)
		}
	}
	// Optional rows do not block the producer and are not exported; contradictions keep the worst outcome.
	rep, err := Export(Inputs{PlaywrightList: list, Evidence: []byte(`{"rows":[
	  {"id":"a","required":false,"satisfied":false,"reason":"limit"},
	  {"id":"b","required":true,"satisfied":true,"reason":"ok"},
	  {"id":"b","required":true,"satisfied":false,"reason":"later_failure"}]}`)}, commit)
	if err != nil {
		t.Fatal(err)
	}
	rows := rowMap(rep)
	if _, ok := rows["evidence/a"]; ok {
		t.Error("optional row exported")
	}
	if r := rows["evidence/b"]; r.Status != releaseevidence.StatusFailed || !strings.Contains(r.Detail, "later_failure") {
		t.Errorf("duplicate row must keep the worst outcome: %+v", r)
	}
}

func TestEnvelopeIsWhatTheGateDecodes(t *testing.T) {
	rep, err := Export(Inputs{PlaywrightList: []byte(listJSON())}, commit)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := rep.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]json.RawMessage
	if err = json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema", "kind", "commit", "expected_rows", "rows"} {
		if _, ok := back[k]; !ok {
			t.Errorf("envelope lacks %q", k)
		}
	}
	if len(back) != 5 {
		t.Errorf("envelope has extra fields: %v", back)
	}
	if _, err := Export(Inputs{PlaywrightList: []byte(listJSON())}, "main"); err == nil {
		t.Error("a symbolic commit was accepted")
	}
}
