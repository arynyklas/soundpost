// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package browserevidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/releaseevidence"
)

const commit = "0123456789abcdef0123456789abcdef01234567"
const browserSource = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

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
	return fmt.Sprintf(`{"config":{"metadata":{"source_sha256":%q}},"suites":[{"title":"auth.spec.ts","file":"auth.spec.ts","specs":[%s],"suites":[{"title":"login","file":"auth.spec.ts","specs":[%s]}]}],"errors":[%s]}`,
		browserSource, strings.Join(topSpecs, ","), strings.Join(nestedSpecs, ","), errs)
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
	return fmt.Sprintf(`{"source_sha256":%q,"rows":[%s]}`, browserSource, strings.Join(parts, ","))
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
	if want := 1 + 2 + len(BrowserViews) + len(JourneyRowIDs) + len(EvidenceRowIDs); len(rep.Expected) != want {
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
		test  string
		want  string
		class releaseevidence.FailureClass
	}{
		"expected pass":  {pwTestJSON("chromium", "passed", "expected", "passed"), releaseevidence.StatusPassed, ""},
		"unexpected":     {pwTestJSON("chromium", "passed", "unexpected", "failed"), releaseevidence.StatusFailed, releaseevidence.FailureAssertion},
		"skipped":        {pwTestJSON("chromium", "skipped", "skipped", "skipped"), "skipped", releaseevidence.FailureNotRun},
		"flaky":          {pwTestJSON("chromium", "passed", "flaky", "failed", "passed"), "flaky", releaseevidence.FailureAssertion},
		"expected fail":  {pwTestJSON("chromium", "failed", "expected", "failed"), "expected_failure", releaseevidence.FailureAssertion},
		"never ran":      {pwTestJSON("chromium", "passed", "expected"), releaseevidence.StatusNotRun, releaseevidence.FailureNotRun},
		"unknown status": {pwTestJSON("chromium", "passed", "weird", "passed"), releaseevidence.StatusNotRun, releaseevidence.FailureNotRun},
	} {
		results := pwReportJSON([]string{c.test}, nil, "")
		list := pwReportJSON([]string{`{"projectName":"chromium","expectedStatus":"passed","status":"expected","results":[]}`}, nil, "")
		rep, err := Export(Inputs{PlaywrightList: []byte(list), PlaywrightResults: []byte(results)}, commit)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := rowMap(rep)["playwright/auth.spec.ts > top 0"]; got.Status != c.want || got.FailureClass != c.class {
			t.Errorf("%s: status %q class %q, want %q %q", name, got.Status, got.FailureClass, c.want, c.class)
		}
	}
	// Runner errors fail the run row.
	results := pwReportJSON([]string{pwTestJSON("chromium", "passed", "expected", "passed")}, nil, `{"message":"Error: global setup failed\n at x"}`)
	list := pwReportJSON([]string{`{"projectName":"chromium","expectedStatus":"passed","status":"expected","results":[]}`}, nil, "")
	rep, err := Export(Inputs{PlaywrightList: []byte(list), PlaywrightResults: []byte(results)}, commit)
	if err != nil {
		t.Fatal(err)
	}
	if r := rowMap(rep)["playwright/run"]; r.Status != releaseevidence.StatusFailed || r.FailureClass != releaseevidence.FailureHarness || !strings.Contains(r.Detail, "global setup failed") {
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
	rep, err := Export(Inputs{PlaywrightList: list, Evidence: []byte(`{"source_sha256":"` + browserSource + `","rows":[
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

func unstamp(doc string) string {
	return strings.Replace(doc, `"source_sha256"`, `"unrelated"`, 1)
}

func restamp(doc string) string {
	return strings.Replace(doc, browserSource, strings.Repeat("1", 64), 1)
}

// Every present input must carry the stamp and all stamps must be equal; an absent optional input
// contributes none; the envelope carries the shared stamp.
func TestExportRequiresOneSharedSourceStamp(t *testing.T) {
	list := listJSON()
	results := pwReportJSON([]string{pwTestJSON("chromium", "passed", "expected", "passed")}, nil, "")
	journeys := allSmokeRows(JourneyRowIDs, "name", nil)
	evidence := allSmokeRows(EvidenceRowIDs, "id", nil)
	full := func() Inputs {
		return Inputs{PlaywrightList: []byte(list), PlaywrightResults: []byte(results), Journeys: []byte(journeys), Evidence: []byte(evidence)}
	}
	rep, err := Export(full(), commit)
	if err != nil || rep.SourceSHA256 != browserSource {
		t.Fatalf("equal stamps: %v %q", err, rep.SourceSHA256)
	}
	if rep, err = Export(Inputs{PlaywrightList: []byte(list)}, commit); err != nil || rep.SourceSHA256 != browserSource {
		t.Fatalf("list only: %v %q", err, rep.SourceSHA256)
	}
	for name, c := range map[string]struct {
		mut  func(*Inputs)
		want string
	}{
		"list unstamped":         {func(in *Inputs) { in.PlaywrightList = []byte(unstamp(list)) }, "playwright list"},
		"results unstamped":      {func(in *Inputs) { in.PlaywrightResults = []byte(unstamp(results)) }, "playwright results"},
		"journeys unstamped":     {func(in *Inputs) { in.Journeys = []byte(unstamp(journeys)) }, "journeys report"},
		"evidence unstamped":     {func(in *Inputs) { in.Evidence = []byte(unstamp(evidence)) }, "evidence smoke report"},
		"results differ":         {func(in *Inputs) { in.PlaywrightResults = []byte(restamp(results)) }, "playwright results"},
		"journeys differ":        {func(in *Inputs) { in.Journeys = []byte(restamp(journeys)) }, "journeys report"},
		"evidence differs":       {func(in *Inputs) { in.Evidence = []byte(restamp(evidence)) }, "evidence smoke report"},
		"list differs from rest": {func(in *Inputs) { in.PlaywrightList = []byte(restamp(list)) }, "playwright results"},
	} {
		in := full()
		c.mut(&in)
		if _, err := Export(in, commit); err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), strings.Repeat("1", 64)) {
			t.Errorf("%s: error %v, want it to name %q", name, err, c.want)
		}
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
	for _, k := range []string{"schema", "kind", "commit", "source_sha256", "expected_rows", "rows"} {
		if _, ok := back[k]; !ok {
			t.Errorf("envelope lacks %q", k)
		}
	}
	if len(back) != 6 {
		t.Errorf("envelope has extra fields: %v", back)
	}
	if _, err := Export(Inputs{PlaywrightList: []byte(listJSON())}, "main"); err == nil {
		t.Error("a symbolic commit was accepted")
	}
}

// viewReport builds a one-project Playwright report holding exactly the tests the BrowserViews name (plus the given extras),
// each with status; drop removes the first named test of the list.
func viewReport(status string, drop string) string {
	var specs []string
	for _, v := range BrowserViews {
		for _, want := range v.Tests {
			if want == drop {
				continue
			}
			i := strings.Index(want, " > ")
			res := `[{"status":"passed"}]`
			st, exp := "expected", "passed"
			if status == "failed" {
				res, st = `[{"status":"failed","error":{"message":"boom"}}]`, "unexpected"
			}
			if status == "list" {
				res = `[]`
			}
			specs = append(specs, fmt.Sprintf(`{"title":%q,"file":%q,"tests":[{"projectName":"chromium","expectedStatus":%q,"status":%q,"results":%s}]}`, want[i+3:]+" and more", want[:i], exp, st, res))
		}
	}
	return `{"config":{"metadata":{"source_sha256":"` + browserSource + `"}},"suites":[{"title":"x","file":"x","specs":[` + strings.Join(specs, ",") + `]}],"errors":[]}`
}

func TestBrowserViewRowsNeedEveryNamedTest(t *testing.T) {
	run := func(list, results string) map[string]releaseevidence.Row {
		rep, err := Export(Inputs{PlaywrightList: []byte(list), PlaywrightResults: []byte(results)}, commit)
		if err != nil {
			t.Fatal(err)
		}
		return rowMap(rep)
	}
	rows := run(viewReport("list", ""), viewReport("passed", ""))
	for _, v := range BrowserViews {
		if r := rows[v.ID]; r.Status != releaseevidence.StatusPassed {
			t.Errorf("%s with every named test passed: %+v", v.ID, r)
		}
	}
	rows = run(viewReport("list", ""), viewReport("failed", ""))
	for _, v := range BrowserViews {
		if r := rows[v.ID]; r.Status != releaseevidence.StatusFailed || !strings.Contains(r.Detail, "failed") {
			t.Errorf("%s with failing tests: %+v", v.ID, r)
		}
	}
	gone := BrowserViews[1].Tests[1]
	rows = run(viewReport("list", gone), viewReport("passed", gone))
	if r := rows[BrowserViews[1].ID]; r.Status != releaseevidence.StatusFailed || !strings.Contains(r.Detail, "not in the Playwright list") {
		t.Errorf("a renamed or dropped named test must fail its view: %+v", r)
	}
	if r := rows[BrowserViews[0].ID]; r.Status != releaseevidence.StatusPassed {
		t.Errorf("an unrelated view must not be affected: %+v", r)
	}
	// No run results: the view rows stay missing.
	rep, err := Export(Inputs{PlaywrightList: []byte(viewReport("list", ""))}, commit)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(rep.Missing(), " "), "browser/mapped_frame") {
		t.Errorf("missing %v", rep.Missing())
	}
}

// Every test a BrowserViews row names exists, by title prefix, in the spec file it names: a rename in web/e2e fails here,
// not only at release time.
func TestBrowserViewsNameRealSpecTests(t *testing.T) {
	for _, v := range BrowserViews {
		for _, want := range v.Tests {
			i := strings.Index(want, " > ")
			raw, err := os.ReadFile(filepath.Join("..", "..", "web", "e2e", want[:i]))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), "test('"+want[i+3:]) {
				t.Errorf("%s: no test starting %q in %s", v.ID, want[i+3:], want[:i])
			}
		}
	}
}
