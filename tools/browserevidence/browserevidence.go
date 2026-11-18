// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package browserevidence converts the results of the actual-browser acceptance into the
// "browser" release evidence (soundpost-release-evidence/1): the Playwright end-to-end specs run
// in real Chrome, the `tools/smoke journeys` rows and the `tools/smoke evidence` rows. It reads
// result files the producers wrote and decides nothing: a row is "passed" only when the producer's
// own result says so, and every expected row that has no result stays visible as missing.
package browserevidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/arynyklas/soundpost/internal/releaseevidence"
)

// JourneyRowIDs are the rows `tools/smoke journeys` must report (all required), in assertion order.
// tools/smoke checks this list against its own assessJourneys.
var JourneyRowIDs = []string{
	"gateway_dependency_child_span",
	"frontend_request_api_db_chain",
	"error_admitted_with_known_build",
	"error_linked_to_request_trace",
	"build_source_map_uploaded",
	"mapped_frame_at_known_location",
	"job_failed_attempt_retained_then_success",
	"same_trace_in_wrong_org_denied",
	"canaries_absent_everywhere",
	"db_span_safe_operation_only",
	"replay_masked_interaction_real_recorder",
	"profile_linkage_with_capability_truth",
	"runtime_profile_delivered_stored_linked",
	"actual_ids_equal_expected",
	"actual_versions_recorded",
}

// EvidenceRowIDs are the rows `tools/smoke evidence` reports on a complete journey (all required).
// The rows `bootstrap` and `tenants` exist only as failure rows of an early abort and are exported
// when present. tools/smoke checks this list against the identifiers in tools/smoke/evidence.go.
var EvidenceRowIDs = []string{
	"serve_https_ready",
	"artifact_upload_read_policy",
	"error_occurrence_ingest",
	"issue_evidence_of_ingested_error",
	"frame_real_mapping",
	"replay_closed_format_ingest",
	"replay_stream_readable_with_gap",
	"replay_real_recorder_chunks",
	"replay_admission_enforces_closed_format",
	"profile_real_view",
	"isolation_same_ids_other_org",
	"lifecycle_midstream_halt_typed_revoke",
	"lifecycle_grant_revoke_denies_reads",
	"lifecycle_deletion_saga_halts_stream",
	"restore_keeps_current_deletion_authority",
	"canary_responses_logs",
}

// BrowserViews are the console views whose real-browser acceptance is a named release row of its own: a row passes only
// when every Playwright test it names is in the list AND passed in the run (a renamed or dropped test fails the row,
// it cannot silently leave the view unverified). Each test is `<spec file> > <title prefix>`.
var BrowserViews = []struct {
	ID    string
	Tests []string
}{
	{"browser/mapped_frame", []string{
		"investigation-journeys.spec.ts > trace to source: frontend, API and database in one trace",
	}},
	{"browser/masked_replay_viewer", []string{
		"investigation-journeys.spec.ts > replay: the keyboard opens the masked replay",
		"replay-profile.spec.ts > masked text, opaque regions, policy revision and recording loss are labelled in words",
		"replay-profile.spec.ts > a replay recorded by the real browser SDK recorder in a real page",
	}},
	{"browser/profile_view", []string{
		"investigation-journeys.spec.ts > profile: the keyboard opens the native profile",
		"replay-profile.spec.ts > a native CPU profile keeps OS on-CPU samples",
		"replay-profile.spec.ts > a profile produced by the real Python SDK",
	}},
}

// Row id prefixes of the three producers.
const (
	PlaywrightPrefix = "playwright/"
	JourneysPrefix   = "journeys/"
	EvidencePrefix   = "evidence/"
	// PlaywrightRunRow carries the runner-level errors of a Playwright run (load errors, global setup).
	PlaywrightRunRow = PlaywrightPrefix + "run"
)

// Inputs are the producers' result files.
type Inputs struct {
	// Project is the Playwright project that ran in real Chrome (default chromium).
	Project string
	// PlaywrightList is `playwright test --list --reporter=json` of the same project and files:
	// the set of tests that must have run, independent of what the run reported.
	PlaywrightList []byte
	// PlaywrightResults is `playwright test --reporter=json` of the run.
	PlaywrightResults []byte
	// Journeys is observed.json of `tools/smoke journeys`.
	Journeys []byte
	// Evidence is evidence-summary.json of `tools/smoke evidence`.
	Evidence []byte
}

// Export builds the browser report. Absent inputs (nil) are not an error: their expected rows then
// have no result. The Playwright list is required, because without it nothing says which tests must run.
func Export(in Inputs, commit string) (releaseevidence.Report, error) {
	project := in.Project
	if project == "" {
		project = "chromium"
	}
	if len(in.PlaywrightList) == 0 {
		return releaseevidence.Report{}, errors.New("the Playwright --list output is required: it names the tests that must run")
	}
	listed, err := playwrightTests(in.PlaywrightList, project)
	if err != nil {
		return releaseevidence.Report{}, fmt.Errorf("playwright list: %w", err)
	}
	if len(listed) == 0 {
		return releaseevidence.Report{}, fmt.Errorf("the Playwright list holds no test for project %q", project)
	}
	expected := []string{PlaywrightRunRow}
	for _, t := range listed {
		expected = append(expected, PlaywrightPrefix+t.id)
	}
	for _, v := range BrowserViews {
		expected = append(expected, v.ID)
	}
	for _, id := range JourneyRowIDs {
		expected = append(expected, JourneysPrefix+id)
	}
	for _, id := range EvidenceRowIDs {
		expected = append(expected, EvidencePrefix+id)
	}
	var rows []releaseevidence.Row
	listStamp, err := playwrightStamp(in.PlaywrightList)
	if err != nil {
		return releaseevidence.Report{}, fmt.Errorf("playwright list: %w", err)
	}
	stamps := []releaseevidence.Stamp{{Name: "playwright list", Source: listStamp}}
	if len(in.PlaywrightResults) > 0 {
		r, err := playwrightRows(in.PlaywrightResults, project)
		if err != nil {
			return releaseevidence.Report{}, fmt.Errorf("playwright results: %w", err)
		}
		stamp, err := playwrightStamp(in.PlaywrightResults)
		if err != nil {
			return releaseevidence.Report{}, fmt.Errorf("playwright results: %w", err)
		}
		stamps = append(stamps, releaseevidence.Stamp{Name: "playwright results", Source: stamp})
		rows = append(rows, r...)
	}
	if len(in.Journeys) > 0 {
		r, err := smokeRows(in.Journeys, JourneysPrefix, "name")
		if err != nil {
			return releaseevidence.Report{}, fmt.Errorf("journeys: %w", err)
		}
		stamp, err := smokeStamp(in.Journeys)
		if err != nil {
			return releaseevidence.Report{}, fmt.Errorf("journeys: %w", err)
		}
		stamps = append(stamps, releaseevidence.Stamp{Name: "journeys report", Source: stamp})
		rows = append(rows, r...)
	}
	if len(in.Evidence) > 0 {
		r, err := smokeRows(in.Evidence, EvidencePrefix, "id")
		if err != nil {
			return releaseevidence.Report{}, fmt.Errorf("evidence smoke: %w", err)
		}
		stamp, err := smokeStamp(in.Evidence)
		if err != nil {
			return releaseevidence.Report{}, fmt.Errorf("evidence smoke: %w", err)
		}
		stamps = append(stamps, releaseevidence.Stamp{Name: "evidence smoke report", Source: stamp})
		rows = append(rows, r...)
	}
	rows = mergeDuplicates(rows)
	rows = append(rows, viewRows(listed, rows)...)
	source, err := releaseevidence.AgreedSource(stamps)
	if err != nil {
		return releaseevidence.Report{}, err
	}
	return releaseevidence.New(releaseevidence.KindBrowser, commit, source, expected, rows)
}

// viewRows derives the BrowserViews rows from the Playwright rows. Without any Playwright result the view rows stay
// missing; with results, a named test that is not in the list or has no passed row fails its view.
func viewRows(listed []pwEntry, rows []releaseevidence.Row) []releaseevidence.Row {
	status := map[string]string{}
	have := false
	for _, r := range rows {
		if strings.HasPrefix(r.ID, PlaywrightPrefix) {
			status[strings.TrimPrefix(r.ID, PlaywrightPrefix)] = r.Status
			have = true
		}
	}
	if !have {
		return nil
	}
	var out []releaseevidence.Row
	for _, v := range BrowserViews {
		row := releaseevidence.Row{ID: v.ID, Status: releaseevidence.StatusPassed}
		var bad []string
		n := 0
		for _, want := range v.Tests {
			found := false
			for _, e := range listed {
				if !strings.HasPrefix(e.id, want) {
					continue
				}
				found = true
				n++
				if st := status[e.id]; st != releaseevidence.StatusPassed {
					bad = append(bad, fmt.Sprintf("%s: %q", e.id, st))
				}
			}
			if !found {
				bad = append(bad, "not in the Playwright list: "+want)
			}
		}
		if len(bad) > 0 {
			row.Status = releaseevidence.StatusFailed
			row.Detail = releaseevidence.Detail(bad...)
		} else {
			row.Detail = fmt.Sprintf("%d named test(s) passed", n)
		}
		out = append(out, row)
	}
	return out
}

// mergeDuplicates keeps one row per id. A producer that reported one id twice with different
// outcomes is contradicting itself, so any non-passing report wins and the details are joined.
func mergeDuplicates(rows []releaseevidence.Row) []releaseevidence.Row {
	at := map[string]int{}
	var out []releaseevidence.Row
	for _, r := range rows {
		i, dup := at[r.ID]
		if !dup {
			at[r.ID] = len(out)
			out = append(out, r)
			continue
		}
		prev := out[i]
		if prev.Status == releaseevidence.StatusPassed && r.Status != releaseevidence.StatusPassed {
			prev.Status = r.Status
		}
		prev.Detail = releaseevidence.Detail(prev.Detail, "reported twice: "+r.Detail)
		out[i] = prev
	}
	return out
}

// ReadFile reads an optional input: a path that does not exist is nil (its rows are missing).
func ReadFile(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return raw, err
}

// ---- Playwright ----

type pwReport struct {
	Config struct {
		Metadata struct {
			SourceSHA256 string `json:"source_sha256"`
		} `json:"metadata"`
	} `json:"config"`
	Suites []pwSuite `json:"suites"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type pwSuite struct {
	Title  string    `json:"title"`
	File   string    `json:"file"`
	Specs  []pwSpec  `json:"specs"`
	Suites []pwSuite `json:"suites"`
}

type pwSpec struct {
	Title string   `json:"title"`
	File  string   `json:"file"`
	Tests []pwTest `json:"tests"`
}

type pwTest struct {
	ProjectName    string `json:"projectName"`
	ExpectedStatus string `json:"expectedStatus"`
	Status         string `json:"status"`
	Results        []struct {
		Status string `json:"status"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	} `json:"results"`
}

type pwEntry struct {
	id   string
	test pwTest
}

// playwrightTests flattens a Playwright JSON report to the tests of one project. A test id is
// <file> > <describe titles> > <title>; two tests with the same id are an error.
func playwrightTests(raw []byte, project string) ([]pwEntry, error) {
	rep, err := decodePlaywright(raw)
	if err != nil {
		return nil, err
	}
	var out []pwEntry
	seen := map[string]bool{}
	var walk func(s pwSuite, path []string, file string) error
	walk = func(s pwSuite, path []string, file string) error {
		for _, sp := range s.Specs {
			f := sp.File
			if f == "" {
				f = file
			}
			for _, t := range sp.Tests {
				if t.ProjectName != project {
					continue
				}
				id := strings.Join(append(append([]string{f}, path...), sp.Title), " > ")
				if seen[id] {
					return fmt.Errorf("two tests share the id %q", id)
				}
				seen[id] = true
				out = append(out, pwEntry{id: id, test: t})
			}
		}
		for _, c := range s.Suites {
			if err := walk(c, append(append([]string{}, path...), c.Title), file); err != nil {
				return err
			}
		}
		return nil
	}
	for _, top := range rep.Suites {
		// A top-level suite is the file; its title is not part of the path.
		if err := walk(top, nil, top.File); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out, nil
}

func decodePlaywright(raw []byte) (pwReport, error) {
	var rep pwReport
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&rep); err != nil {
		return rep, err
	}
	if rep.Suites == nil {
		return rep, errors.New("not a Playwright JSON report: no suites")
	}
	return rep, nil
}

// playwrightRows maps each test of the run to one row. Only a test that was expected to pass,
// ended as expected and whose last result is passed is "passed"; skipped, flaky, unexpected and
// expected-failure tests keep their own names.
func playwrightRows(raw []byte, project string) ([]releaseevidence.Row, error) {
	rep, err := decodePlaywright(raw)
	if err != nil {
		return nil, err
	}
	tests, err := playwrightTests(raw, project)
	if err != nil {
		return nil, err
	}
	var rows []releaseevidence.Row
	var runErrors []string
	for _, e := range rep.Errors {
		runErrors = append(runErrors, firstLine(e.Message))
	}
	run := releaseevidence.Row{ID: PlaywrightRunRow, Status: releaseevidence.StatusPassed, Detail: fmt.Sprintf("%d %s tests reported", len(tests), project)}
	if len(runErrors) > 0 {
		run.Status = releaseevidence.StatusFailed
		run.Detail = releaseevidence.Detail(append([]string{"runner errors"}, runErrors...)...)
	}
	rows = append(rows, run)
	for _, e := range tests {
		row := releaseevidence.Row{ID: PlaywrightPrefix + e.id}
		last := ""
		var msg string
		if n := len(e.test.Results); n > 0 {
			last = e.test.Results[n-1].Status
			if er := e.test.Results[n-1].Error; er != nil {
				msg = firstLine(er.Message)
			}
		}
		switch {
		case e.test.Status == "expected" && e.test.ExpectedStatus == "passed" && last == "passed":
			row.Status = releaseevidence.StatusPassed
			row.Detail = fmt.Sprintf("%s: passed in %d attempt(s)", project, len(e.test.Results))
		case e.test.Status == "expected" && e.test.ExpectedStatus == "passed":
			row.Status = releaseevidence.StatusNotRun
			row.Detail = fmt.Sprintf("no passed result (last result %q)", last)
		case e.test.Status == "expected":
			row.Status = "expected_failure"
			row.Detail = fmt.Sprintf("expected status %q, last result %q", e.test.ExpectedStatus, last)
		case e.test.Status == "unexpected":
			row.Status = releaseevidence.StatusFailed
			row.Detail = releaseevidence.Detail("last result "+last, msg)
		case e.test.Status == "skipped":
			row.Status = "skipped"
		case e.test.Status == "flaky":
			row.Status = "flaky"
		default:
			row.Status = releaseevidence.StatusNotRun
			row.Detail = fmt.Sprintf("test status %q", e.test.Status)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// ---- smokes ----

// smokeRow is a row of observed.json (key "name") or evidence-summary.json (key "id").
type smokeRow struct {
	Name      *string `json:"name"`
	ID        *string `json:"id"`
	Required  *bool   `json:"required"`
	Satisfied *bool   `json:"satisfied"`
	Reason    string  `json:"reason"`
	Detail    string  `json:"detail"`
}

// smokeRows reads {"rows":[{<name|id>, required, satisfied, reason, detail}]}. The producers exit
// non-zero exactly when a required row is unsatisfied, so required rows are exported; a row the
// producer marks optional does not block it and is not exported.
func smokeRows(raw []byte, prefix, key string) ([]releaseevidence.Row, error) {
	var top struct {
		Rows *[]smokeRow `json:"rows"`
	}
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&top); err != nil {
		return nil, err
	}
	if top.Rows == nil {
		return nil, errors.New("no rows field")
	}
	var rows []releaseevidence.Row
	for i, r := range *top.Rows {
		id := r.Name
		if key == "id" {
			id = r.ID
		}
		if id == nil || *id == "" || r.Required == nil || r.Satisfied == nil {
			return nil, fmt.Errorf("row %d lacks %s, required or satisfied", i, key)
		}
		if !*r.Required {
			continue
		}
		row := releaseevidence.Row{ID: prefix + *id}
		if *r.Satisfied {
			row.Status = releaseevidence.StatusPassed
			row.Detail = releaseevidence.Detail(r.Detail)
		} else {
			row.Status = releaseevidence.StatusFailed
			row.Detail = releaseevidence.Detail(r.Reason, r.Detail)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// smokeStamp reads the source_sha256 a smoke producer stamped on its own result file ("" when absent).
func smokeStamp(raw []byte) (string, error) {
	var top struct {
		Source string `json:"source_sha256"`
	}
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&top); err != nil {
		return "", err
	}
	return top.Source, nil
}

// playwrightStamp reads config.metadata.source_sha256 of a Playwright JSON report ("" when absent).
func playwrightStamp(raw []byte) (string, error) {
	rep, err := decodePlaywright(raw)
	if err != nil {
		return "", err
	}
	return rep.Config.Metadata.SourceSHA256, nil
}
