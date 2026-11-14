// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/releaseevidence"
)

const evidenceCommit = "0123456789abcdef0123456789abcdef01234567"

func statusOf(rep releaseevidence.Report) map[string]string {
	m := map[string]string{}
	for _, r := range rep.Rows {
		m[r.ID] = r.Status
	}
	return m
}

func wantStatus(t *testing.T, rep releaseevidence.Report, id, status string) {
	t.Helper()
	if got, ok := statusOf(rep)[id]; !ok || got != status {
		t.Errorf("row %s: status %q (present %v), want %q", id, got, ok, status)
	}
}

// campaignFixture is a campaign report in which every required row of the real matrix is
// verified, built from the matrix itself so the fixture follows the locked policy.
func campaignFixture(t *testing.T) (QueryMatrix, CampaignReport) {
	t.Helper()
	m := realMatrix(t)
	specs, err := campaignSpecs(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 8 {
		t.Fatalf("the locked policy and matrix require %d campaign rows, the fixture assumes 8", len(specs))
	}
	rep := CampaignReport{Schema: campaignSchema, Missing: []string{}, Failures: []string{}, Verified: true}
	for _, s := range specs {
		rep.Rows = append(rep.Rows, RowResult{ID: "matrix-" + s.id, Kind: s.kind, Profile: s.profile, Seed: s.seed, Layout: s.layout,
			Report: s.kind + ".json", ReportSHA256: "abc", Verified: true})
	}
	return m, rep
}

func TestQueryCampaignEvidenceKeepsEveryRowVerdict(t *testing.T) {
	m, rep := campaignFixture(t)

	pass, err := QueryCampaignEvidence(m, rep, evidenceCommit)
	if err != nil {
		t.Fatal(err)
	}
	if len(pass.Expected) != 9 || len(pass.Rows) != 9 || len(pass.Missing()) != 0 {
		t.Fatalf("passing campaign: %d expected, %d rows, missing %v", len(pass.Expected), len(pass.Rows), pass.Missing())
	}
	for _, r := range pass.Rows {
		if r.Status != releaseevidence.StatusPassed {
			t.Errorf("verified campaign row %s exported as %s", r.ID, r.Status)
		}
	}
	if pass.Kind != releaseevidence.KindLanguage || pass.Commit != evidenceCommit {
		t.Fatalf("kind/commit: %+v", pass)
	}

	// A failing row stays failed and carries the producer's own failure text.
	failing := rep
	failing.Rows = append([]RowResult(nil), rep.Rows...)
	failing.Rows[0].Verified = false
	failing.Rows[0].Failures = []string{"obligations: 0 bound of 785, unbound 785"}
	failing.Verified = false
	bad, err := QueryCampaignEvidence(m, failing, evidenceCommit)
	if err != nil {
		t.Fatal(err)
	}
	first := failing.Rows[0]
	wantStatus(t, bad, ReleaseRowID(first.Profile, first.Seed), releaseevidence.StatusFailed)
	for _, r := range bad.Rows {
		if r.ID == ReleaseRowID(first.Profile, first.Seed) && !strings.Contains(r.Detail, "unbound 785") {
			t.Errorf("failure text lost: %q", r.Detail)
		}
	}
	passed := 0
	for _, r := range bad.Rows {
		if r.Status == releaseevidence.StatusPassed {
			passed++
		}
	}
	if passed != 8 {
		t.Errorf("one failing row must not change the other verdicts: %d passed", passed)
	}

	// A row the campaign never produced is absent from the rows, so the gate names it.
	missing := rep
	missing.Rows = rep.Rows[1:]
	gone, err := QueryCampaignEvidence(m, missing, evidenceCommit)
	if err != nil {
		t.Fatal(err)
	}
	if got := gone.Missing(); len(got) != 1 || got[0] != ReleaseRowID(rep.Rows[0].Profile, rep.Rows[0].Seed) {
		t.Errorf("missing rows %v", got)
	}
	if len(gone.Rows) != 8 {
		t.Errorf("a missing row must not be invented: %d rows", len(gone.Rows))
	}
}

func TestQueryCampaignEvidenceCarriesTheMatrixVerdict(t *testing.T) {
	m, rep := campaignFixture(t)
	for name, mutate := range map[string]func(*CampaignReport){
		"missing item":   func(r *CampaignReport) { r.Missing = []string{"profile x has no entry"} },
		"failure":        func(r *CampaignReport) { r.Failures = []string{"release policy names no profiles"} },
		"execution fail": func(r *CampaignReport) { r.Failures = []string{"smoke distributed: exec: not found"} },
	} {
		r := rep
		mutate(&r)
		env, err := QueryCampaignEvidence(m, r, evidenceCommit)
		if err != nil {
			t.Fatal(err)
		}
		wantStatus(t, env, CampaignMatrixRowID, releaseevidence.StatusFailed)
		for _, row := range env.Rows {
			if row.ID == CampaignMatrixRowID && row.Detail == "" {
				t.Errorf("%s: matrix verdict row carries no detail", name)
			}
		}
	}
	// The producer's own Verified flag is not read as a pass: clean lists and verified rows are what pass.
	env, err := QueryCampaignEvidence(m, rep, evidenceCommit)
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, env, CampaignMatrixRowID, releaseevidence.StatusPassed)
}

func TestQueryCampaignEvidenceRefusesAForeignReport(t *testing.T) {
	m, rep := campaignFixture(t)
	rep.Schema = "soundpost-smoke-report/1"
	if _, err := QueryCampaignEvidence(m, rep, evidenceCommit); err == nil {
		t.Fatal("a report of another schema was exported")
	}
	rep.Schema = campaignSchema
	if _, err := QueryCampaignEvidence(m, rep, "HEAD"); err == nil {
		t.Fatal("a symbolic commit was accepted")
	}
}

func TestReadCampaignReportIsStrict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "campaign-report.json")
	if err := os.WriteFile(path, []byte(`{"schema":"soundpost-query-campaign/1","rows":[],"counts":{},"missing_evidence":[],"failures":[],"verified":true,"passed":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCampaignReport(path); err == nil {
		t.Fatal("a campaign report with an unknown field was accepted")
	}
}

const evidenceMatrixYAML = `schema: soundpost-qualification-matrix/1
root: .
workloads: workloads.yaml
builds:
  node22: {family: node, version: "22", os: linux, arch: amd64, absent: not installed}
rows:
  - {id: runtime.pass, suite: runtime, required: true, runner: r, build: node22}
  - {id: runtime.fail, suite: runtime, required: true, runner: r, build: node22}
  - {id: runtime.unexercised, suite: runtime, required: true, runner: r, build: node22}
  - {id: runtime.unsupported, suite: runtime, required: true, runner: r, build: node22}
  - {id: runtime.denied, suite: runtime, required: true, runner: r, build: node22}
  - {id: runtime.absent, suite: runtime, required: true, runner: r, build: node22}
  - {id: runtime.optional, suite: runtime, required: false, runner: r, build: node22}
  - {id: runtime.optional-fail, suite: runtime, required: false, runner: r, build: node22}
  - {id: overhead.pass, suite: overhead, required: true, runner: r, build: node22}
  - {id: privacy.pass, suite: privacy, required: true, runner: r, build: node22}
`

func suiteRowFixture(id string, suite Suite, required bool, state State, outcome Outcome) Row {
	row := Row{ID: id, Suite: suite, Required: required, Subject: Subject{Family: "node", Version: "22", OS: "linux", Arch: "amd64"}, State: state, Outcome: outcome}
	switch state {
	case StateExercised:
		row.Build = &Build{Family: "node", Version: "22.23.4", OS: "linux", Arch: "amd64", ID: "b1"}
		row.Command = &CommandRun{Command: "fixture"}
		row.Evidence = []string{"fixture.json"}
		if outcome == OutcomeFailed {
			row.Failures = []string{"p95 over budget"}
			row.Budgets = []BudgetResult{{Name: "p95", Source: "design", Unit: "%", Limit: 5, Observed: 69, Within: false}}
		}
	case StateNotExercised:
		row.Reason = "no arm64 runner"
	case StateUnsupported, StateDenied:
		row.Reason = "capability absent"
		row.Evidence = []string{"probe"}
	}
	return row
}

func evidenceMatrixFile(t *testing.T) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "matrix.yaml")
	if err := os.WriteFile(path, []byte(evidenceMatrixYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(evidenceMatrixYAML))
	return path, hex.EncodeToString(sum[:])
}

func TestSuiteEvidenceKeepsEveryRowVerdict(t *testing.T) {
	path, sum := evidenceMatrixFile(t)
	runtimeRep := SuiteReport{Suite: SuiteRuntime, MatrixSHA: sum, Rows: []Row{
		suiteRowFixture("runtime.pass", SuiteRuntime, true, StateExercised, OutcomePassed),
		suiteRowFixture("runtime.fail", SuiteRuntime, true, StateExercised, OutcomeFailed),
		suiteRowFixture("runtime.unexercised", SuiteRuntime, true, StateNotExercised, ""),
		suiteRowFixture("runtime.unsupported", SuiteRuntime, true, StateUnsupported, ""),
		suiteRowFixture("runtime.denied", SuiteRuntime, true, StateDenied, ""),
		// runtime.absent was never produced.
		suiteRowFixture("runtime.optional", SuiteRuntime, false, StateNotExercised, ""),
		suiteRowFixture("runtime.optional-fail", SuiteRuntime, false, StateExercised, OutcomeFailed),
	}}
	overheadRep := SuiteReport{Suite: SuiteOverhead, MatrixSHA: sum, Rows: []Row{suiteRowFixture("overhead.pass", SuiteOverhead, true, StateExercised, OutcomePassed)}}

	env, err := SuiteEvidence(releaseevidence.KindRuntime, path, []SuiteReport{runtimeRep, overheadRep}, evidenceCommit)
	if err != nil {
		t.Fatal(err)
	}
	if env.Kind != releaseevidence.KindRuntime {
		t.Fatalf("kind %s", env.Kind)
	}
	wantExpected := "overhead.pass runtime.absent runtime.denied runtime.fail runtime.pass runtime.unexercised runtime.unsupported"
	if got := strings.Join(env.Expected, " "); got != wantExpected {
		t.Errorf("expected rows come from the matrix's required rows:\n got %s\nwant %s", got, wantExpected)
	}
	wantStatus(t, env, "runtime.pass", releaseevidence.StatusPassed)
	wantStatus(t, env, "overhead.pass", releaseevidence.StatusPassed)
	wantStatus(t, env, "runtime.fail", releaseevidence.StatusFailed)
	wantStatus(t, env, "runtime.unexercised", "not_exercised")
	wantStatus(t, env, "runtime.unsupported", "unsupported")
	wantStatus(t, env, "runtime.denied", "denied")
	wantStatus(t, env, "runtime.optional-fail", releaseevidence.StatusFailed) // the producer counts a failed exercise, required or not
	if _, ok := statusOf(env)["runtime.optional"]; ok {
		t.Error("a non-required row that is not a failure does not block the producer and is not exported")
	}
	if got := env.Missing(); len(got) != 1 || got[0] != "runtime.absent" {
		t.Errorf("missing %v", got)
	}
	for _, r := range env.Rows {
		if r.ID == "runtime.fail" && !strings.Contains(r.Detail, "p95 over budget") {
			t.Errorf("failure detail lost: %q", r.Detail)
		}
		if r.ID == "runtime.unexercised" && r.Detail != "no arm64 runner" {
			t.Errorf("reason lost: %q", r.Detail)
		}
	}
}

func TestSuiteEvidenceRefusesReportsThatDoNotBelong(t *testing.T) {
	path, sum := evidenceMatrixFile(t)
	good := func() SuiteReport {
		return SuiteReport{Suite: SuiteRuntime, MatrixSHA: sum, Rows: []Row{suiteRowFixture("runtime.pass", SuiteRuntime, true, StateExercised, OutcomePassed)}}
	}
	other := good()
	other.MatrixSHA = strings.Repeat("0", 64)
	privacy := SuiteReport{Suite: SuitePrivacy, MatrixSHA: sum}
	crossed := good()
	crossed.Rows[0].Suite = SuitePrivacy
	for name, c := range map[string]struct {
		kind    string
		reports []SuiteReport
		want    string
	}{
		"other matrix":       {releaseevidence.KindRuntime, []SuiteReport{other}, "different matrix"},
		"wrong suite":        {releaseevidence.KindRuntime, []SuiteReport{privacy}, "does not belong"},
		"duplicate suite":    {releaseevidence.KindRuntime, []SuiteReport{good(), good()}, "two runtime"},
		"row of other suite": {releaseevidence.KindRuntime, []SuiteReport{crossed}, "belongs to suite"},
		"language kind":      {releaseevidence.KindLanguage, []SuiteReport{good()}, "no qualification suites"},
	} {
		if _, err := SuiteEvidence(c.kind, path, c.reports, evidenceCommit); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v, want %q", name, err, c.want)
		}
	}
	// Privacy reports are exported on their own.
	env, err := SuiteEvidence(releaseevidence.KindPrivacy, path, []SuiteReport{{Suite: SuitePrivacy, MatrixSHA: sum, Rows: []Row{suiteRowFixture("privacy.pass", SuiteRuntime, true, StateExercised, OutcomePassed)}}}, evidenceCommit)
	if err == nil {
		t.Fatalf("a runtime-suite row inside a privacy report was exported: %+v", env)
	}
}

func TestReadSuiteReportRejectsATamperedRow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime-report.json")
	if err := os.WriteFile(path, []byte(`{"suite":"runtime","matrix":"m","matrix_sha256":"x","recorded_at":"t","host":{"os":"linux","arch":"amd64","class":"linux","logical_cpus":1},"rows":[{"id":"r","suite":"runtime","required":true,"subject":{"family":"f","version":"1","os":"linux","arch":"amd64"},"state":"exercised"}],"unqualified_required_rows":null,"measured_failures":null,"exit_code":0}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSuiteReport(path); err == nil {
		t.Fatal("an exercised row without build, evidence or outcome was read as valid")
	}
}
