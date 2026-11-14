// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	q "github.com/arynyklas/soundpost/internal/conformance/query"
)

// The campaign runs the REAL soundpost-querycheck release and smoke commands
// once; every other test tampers with copies of the real report files.
var (
	campaignOnce   sync.Once
	campaignDir    string
	campaignReport CampaignReport
	campaignErr    error
	campaignSetup  error
	campaignRoot   string
)

func repoRoot(t testing.TB) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func realMatrix(t testing.TB) QueryMatrix {
	t.Helper()
	m, err := LoadQueryMatrix(filepath.Join(repoRoot(t), "qualification", "query-matrix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	m.Tool = []string{filepath.Join(campaignDir, "soundpost-querycheck")}
	return m
}

func realCampaign(t testing.TB) {
	t.Helper()
	campaignOnce.Do(func() {
		campaignRoot = repoRoot(t)
		dir, err := os.MkdirTemp("", "query-campaign-")
		if err != nil {
			campaignSetup = err
			return
		}
		campaignDir = dir
		build := exec.Command("go", "build", "-o", filepath.Join(dir, "soundpost-querycheck"), "./cmd/soundpost-querycheck")
		build.Dir = campaignRoot
		if out, err := build.CombinedOutput(); err != nil {
			campaignSetup = errors.New("building soundpost-querycheck: " + err.Error() + ": " + string(out))
			return
		}
		m, err := LoadQueryMatrix(filepath.Join(campaignRoot, "qualification", "query-matrix.yaml"))
		if err != nil {
			campaignSetup = err
			return
		}
		m.Tool = []string{filepath.Join(dir, "soundpost-querycheck")}
		campaignReport, campaignErr = RunQueryConformance(context.Background(), m, dir)
	})
	if campaignSetup != nil {
		t.Fatal(campaignSetup)
	}
}

func TestMain(m *testing.M) {
	code := m.Run()
	if campaignDir != "" {
		os.RemoveAll(campaignDir)
	}
	os.Exit(code)
}

// copyArtifacts copies the real report files so a test can damage them.
func copyArtifacts(t *testing.T) string {
	t.Helper()
	realCampaign(t)
	dst := t.TempDir()
	entries, err := os.ReadDir(campaignDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || e.Name() == "campaign-report.json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(campaignDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dst, e.Name()), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func mustContain(t *testing.T, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("message lacks %q:\n%s", w, got)
		}
	}
}

func verifyErr(t *testing.T, m QueryMatrix, dir string) (CampaignReport, string) {
	t.Helper()
	rep, err := VerifyQueryEvidence(m, dir)
	if err == nil || rep.Verified {
		t.Fatalf("campaign accepted damaged evidence: %+v", rep.Counts)
	}
	if !errors.Is(err, ErrCampaignRejected) {
		t.Fatalf("error does not wrap ErrCampaignRejected: %v", err)
	}
	return rep, err.Error()
}

func TestMatrixRequiresEveryProfileFeatureSetAndArtifact(t *testing.T) {
	dir := copyArtifacts(t)
	const seed = "20261110"

	dropRow := func(m QueryMatrix, id string) QueryMatrix {
		var rows []MatrixRow
		for _, r := range m.Rows {
			if r.ID != id {
				rows = append(rows, r)
			}
		}
		m.Rows = rows
		return m
	}
	clone := func() QueryMatrix { return realMatrix(t) }

	t.Run("missing profile row", func(t *testing.T) {
		id := "release/promql-prometheus-3.13.5/seed/" + seed
		_, msg := verifyErr(t, dropRow(clone(), id), dir)
		mustContain(t, msg, "MISSING row "+id, `profile "promql-prometheus-3.13.5"`, "seed "+seed)
	})
	t.Run("missing second seed row", func(t *testing.T) {
		id := "release/logql-loki-3.5.2/seed/20270101"
		_, msg := verifyErr(t, dropRow(clone(), id), dir)
		mustContain(t, msg, "MISSING row "+id)
	})
	t.Run("missing layout row", func(t *testing.T) {
		_, msg := verifyErr(t, dropRow(clone(), "smoke/distributed"), dir)
		mustContain(t, msg, `MISSING row smoke/distributed`, `layout "distributed"`)
	})
	t.Run("missing profile entry", func(t *testing.T) {
		mm := clone()
		var keep []MatrixProfile
		for _, p := range mm.Profiles {
			if p.ID != "logql-loki-3.5.2" {
				keep = append(keep, p)
			}
		}
		mm.Profiles = keep
		_, msg := verifyErr(t, mm, dir)
		mustContain(t, msg, "profile logql-loki-3.5.2 has no entry")
	})
	t.Run("missing config pin", func(t *testing.T) {
		mm := clone()
		mm.Profiles[0].ConfigSHA256 = ""
		_, msg := verifyErr(t, mm, dir)
		mustContain(t, msg, "profile "+mm.Profiles[0].ID+" oracle configuration digest mismatch: matrix , report ")
	})
	t.Run("missing FeatureSet", func(t *testing.T) {
		mm := clone()
		omitted := mm.Profiles[1].FeatureSetIDs[3]
		mm.Profiles[1].FeatureSetIDs = append(append([]string{}, mm.Profiles[1].FeatureSetIDs[:3]...), mm.Profiles[1].FeatureSetIDs[4:]...)
		_, msg := verifyErr(t, mm, dir)
		mustContain(t, msg, "profile "+mm.Profiles[1].ID+" FeatureSet "+omitted+" is registered in the manifest but absent from the matrix",
			"profile "+mm.Profiles[1].ID+" FeatureSet count: matrix 127, report 128")
	})
	t.Run("mismatched oracle configuration digest", func(t *testing.T) {
		mm := clone()
		real := mm.Profiles[2].ConfigSHA256
		bad := strings.Repeat("0", 64)
		mm.Profiles[2].ConfigSHA256 = bad
		_, msg := verifyErr(t, mm, dir)
		mustContain(t, msg, "profile "+mm.Profiles[2].ID+" oracle configuration digest mismatch: matrix "+bad+", report "+real)
	})
	t.Run("mismatched report digest", func(t *testing.T) {
		mm := clone()
		bad := strings.Repeat("f", 64)
		for i := range mm.Rows {
			if mm.Rows[i].ID == "smoke/single" {
				mm.Rows[i].ReportSHA256 = bad
			}
		}
		raw, _ := os.ReadFile(filepath.Join(dir, "smoke-single.json"))
		_, msg := verifyErr(t, mm, dir)
		mustContain(t, msg, "report digest mismatch for smoke-single.json: matrix "+bad+", actual "+sha(raw))
	})
	t.Run("mismatched commit and normalization identity", func(t *testing.T) {
		mm := clone()
		mm.Profiles[0].Commit = "deadbeef"
		mm.InputNormalizationIdentity = "abc"
		_, msg := verifyErr(t, mm, dir)
		mustContain(t, msg, "commit pin \"deadbeef\" differs from manifest", "input-normalization identity: matrix abc, report ")
	})
	t.Run("matrix names no seeds", func(t *testing.T) {
		mm := clone()
		mm.Seeds = nil
		_, msg := verifyErr(t, mm, dir)
		mustContain(t, msg, "no seeds in the matrix")
	})
}

func TestReportFilesAreEvidenceNotAssumptions(t *testing.T) {
	m := realMatrix(t)
	t.Run("absent report", func(t *testing.T) {
		dir := copyArtifacts(t)
		if err := os.Remove(filepath.Join(dir, "release-seed-20261110.json")); err != nil {
			t.Fatal(err)
		}
		_, msg := verifyErr(t, m, dir)
		mustContain(t, msg, "release/logql-loki-3.5.2/seed/20261110: report file release-seed-20261110.json absent or unreadable")
	})
	t.Run("unparsable report", func(t *testing.T) {
		dir := copyArtifacts(t)
		if err := os.WriteFile(filepath.Join(dir, "release-seed-20270101.json"), []byte("{not json"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "smoke-distributed.json"), []byte("[]"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, msg := verifyErr(t, m, dir)
		mustContain(t, msg, "report release-seed-20270101.json is not a parsable release report", "report smoke-distributed.json is not a parsable smoke report")
	})
	t.Run("duplicate row", func(t *testing.T) {
		dir := copyArtifacts(t)
		mm := realMatrix(t)
		dup := mm.Rows[0]
		dup.ID = "again"
		mm.Rows = append(mm.Rows, dup)
		mm.Rows = append(mm.Rows, mm.Rows[0])
		_, msg := verifyErr(t, mm, dir)
		mustContain(t, msg, `duplicate row "again" for `+mm.Rows[0].ID, `duplicate row "`+mm.Rows[0].ID+`"`)
	})
	t.Run("unknown row", func(t *testing.T) {
		dir := copyArtifacts(t)
		mm := realMatrix(t)
		mm.Rows = append(mm.Rows, MatrixRow{ID: "release/other/seed/1", Kind: "release", Profile: "other", Seed: 1, Report: "release-seed-20261110.json"})
		_, msg := verifyErr(t, mm, dir)
		mustContain(t, msg, `row "release/other/seed/1"`, "is not a required row")
	})
	t.Run("row bound to a report from a different profile", func(t *testing.T) {
		dir := copyArtifacts(t)
		var rep q.Report
		path := filepath.Join(dir, "release-seed-20261110.json")
		readJSON(t, path, &rep)
		delete(rep.Profiles, "promql-prometheus-3.1.0")
		delete(rep.Configs, "promql-prometheus-3.1.0")
		writeJSON(t, path, rep)
		_, msg := verifyErr(t, m, dir)
		mustContain(t, msg, "release/promql-prometheus-3.1.0/seed/20261110: report release-seed-20261110.json has no profile promql-prometheus-3.1.0")
	})
	t.Run("profile identity swapped inside the report", func(t *testing.T) {
		dir := copyArtifacts(t)
		var rep q.Report
		path := filepath.Join(dir, "release-seed-20261110.json")
		readJSON(t, path, &rep)
		rep.Profiles["promql-prometheus-3.1.0"], rep.Profiles["promql-prometheus-3.13.5"] = rep.Profiles["promql-prometheus-3.13.5"], rep.Profiles["promql-prometheus-3.1.0"]
		writeJSON(t, path, rep)
		_, msg := verifyErr(t, m, dir)
		mustContain(t, msg, "profile promql-prometheus-3.1.0 commit: matrix "+m.Profiles[0].Commit)
	})
	t.Run("row bound to a smoke report instead of a release report", func(t *testing.T) {
		dir := copyArtifacts(t)
		mm := realMatrix(t)
		for i := range mm.Rows {
			if mm.Rows[i].ID == "release/logql-loki-3.5.2/seed/20270101" {
				mm.Rows[i].Report = "smoke-single.json"
			}
		}
		_, msg := verifyErr(t, mm, dir)
		mustContain(t, msg, "report smoke-single.json carries no profiles: not a release report")
	})
	t.Run("one report bound to different seeds", func(t *testing.T) {
		dir := copyArtifacts(t)
		mm := realMatrix(t)
		for i := range mm.Rows {
			if mm.Rows[i].ID == "release/logql-loki-3.5.2/seed/20270101" {
				mm.Rows[i].Report = "release-seed-20261110.json"
			}
		}
		_, msg := verifyErr(t, mm, dir)
		mustContain(t, msg, "is already bound to a different kind/seed/layout")
	})
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// cleanRelease rewrites the real release report into one whose counts are all
// satisfied, so each count can be flipped alone.
func cleanRelease(rep *q.Report) {
	rep.BoundCount, rep.UnboundCount = rep.ObligationCount, 0
	rep.MatchedCaseCount, rep.UnrunCases = rep.RequiredCaseCount, []string{}
	rep.OracleRuns, rep.OracleUnavailable, rep.OracleUnverified = rep.RequiredCaseCount, 0, 0
	rep.Mismatches, rep.SkippedCount, rep.NormalizationLoss, rep.UnobservedTests = []q.MismatchRecord{}, 0, 0, 0
	rep.ProvenanceRejected, rep.ScenarioFailures, rep.UnresolvedCount, rep.Failures = 0, 0, 0, []string{}
	rep.InteractionCovered = rep.InteractionRequired
}

func TestUnrunSkippedAndUnboundCountsPropagateAsFailure(t *testing.T) {
	m := realMatrix(t)
	releaseRows := func(rep CampaignReport) []RowResult {
		var out []RowResult
		for _, r := range rep.Rows {
			if r.Kind == "release" {
				out = append(out, r)
			}
		}
		return out
	}
	// Positive control: the five release counts clean (other seed untouched).
	dir := copyArtifacts(t)
	path := filepath.Join(dir, "release-seed-20261110.json")
	var base q.Report
	readJSON(t, path, &base)
	cleanRelease(&base)
	writeJSON(t, path, base)
	rep, _ := VerifyQueryEvidence(m, dir)
	for _, r := range releaseRows(rep) {
		if r.Seed == 20261110 && !r.Verified {
			t.Fatalf("clean release report was rejected: %v", r.Failures)
		}
	}
	cases := []struct {
		name   string
		mutate func(*q.Report)
		want   string
	}{
		{"unbound", func(r *q.Report) { r.UnboundCount, r.BoundCount = 3, r.ObligationCount-3 }, "unbound 3"},
		{"unrun listed", func(r *q.Report) { r.UnrunCases = []string{"a/b", "c/d"} }, "cases: 2 unrun"},
		{"unrun by count", func(r *q.Report) { r.MatchedCaseCount-- }, "cases: 1 unrun"},
		{"skipped", func(r *q.Report) { r.SkippedCount = 4 }, "skipped 4"},
		{"mismatch", func(r *q.Report) { r.Mismatches = []q.MismatchRecord{{}} }, "mismatches 1"},
		{"normalization loss", func(r *q.Report) { r.NormalizationLoss = 2 }, "normalization loss 2"},
		{"oracle never ran", func(r *q.Report) { r.OracleRuns = 0 }, "oracle observation: runs 0"},
		{"oracle unavailable", func(r *q.Report) { r.OracleUnavailable = 1 }, "unavailable 1"},
		{"unobserved tests", func(r *q.Report) { r.UnobservedTests = 5 }, "unobserved Go tests 5"},
		{"provenance", func(r *q.Report) { r.ProvenanceRejected = 1 }, "provenance rejected 1"},
		{"scenario", func(r *q.Report) { r.ScenarioFailures = 1 }, "scenario failures 1"},
		{"interactions", func(r *q.Report) { r.InteractionCovered-- }, "interactions:"},
		{"unresolved only", func(r *q.Report) { r.UnresolvedCount = 7 }, "unresolved 7"},
		{"gate failure text", func(r *q.Report) { r.Failures = []string{"xyz"} }, "gate failure: xyz"},
		{"empty evidence", func(r *q.Report) {
			r.RequiredCaseCount, r.MatchedCaseCount, r.ObligationCount, r.BoundCount = 0, 0, 0, 0
		}, "empty evidence"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := copyArtifacts(t)
			path := filepath.Join(dir, "release-seed-20261110.json")
			rep := base
			c.mutate(&rep)
			writeJSON(t, path, rep)
			got, _ := verifyErr(t, m, dir)
			for _, r := range got.Rows {
				if r.Kind == "release" && r.Seed == 20261110 {
					if r.Verified {
						t.Fatalf("row %s verified despite %s", r.ID, c.name)
					}
					mustContain(t, strings.Join(r.Failures, "\n"), c.want)
				}
			}
			// Aggregates carry the damage forward.
			if got.Counts.Unresolved == 0 && c.name == "unresolved only" {
				t.Fatal("unresolved count was not propagated")
			}
		})
	}
	t.Run("smoke distributed counted not run", func(t *testing.T) {
		dir := copyArtifacts(t)
		path := filepath.Join(dir, "smoke-distributed.json")
		var s q.SmokeReport
		readJSON(t, path, &s)
		// The real distributed run passes; a report that says the layout was not
		// run (the state this campaign used to record) must still be counted.
		s.Modes = nil
		s.ModesNotRun = []string{"distributed"}
		s.NotSatisfied = append(s.NotSatisfied, "distributed mode: not run")
		writeJSON(t, path, s)
		got, msg := verifyErr(t, m, dir)
		mustContain(t, msg, "layout distributed did not run", "layout distributed recorded as not run")
		if got.Counts.ModesNotRun < 1 || got.Counts.NotSatisfied < len(s.NotSatisfied) {
			t.Fatalf("counts %+v do not carry smoke report (%d not satisfied)", got.Counts, len(s.NotSatisfied))
		}
	})
	t.Run("smoke failing step", func(t *testing.T) {
		dir := copyArtifacts(t)
		path := filepath.Join(dir, "smoke-single.json")
		var s q.SmokeReport
		readJSON(t, path, &s)
		s.Steps[0].Passed = false
		writeJSON(t, path, s)
		got, msg := verifyErr(t, m, dir)
		mustContain(t, msg, "failing smoke steps")
		if got.Counts.FailingSteps < 1 {
			t.Fatal("failing step not counted")
		}
	})
	t.Run("smoke missing persistence stage and case file", func(t *testing.T) {
		dir := copyArtifacts(t)
		path := filepath.Join(dir, "smoke-single.json")
		var s q.SmokeReport
		readJSON(t, path, &s)
		s.Persistence, s.CaseFiles = nil, s.CaseFiles[1:]
		s.Isolation = append([]q.ScenarioOutcome{}, s.Isolation...)
		s.Isolation[0].Passed = false
		writeJSON(t, path, s)
		_, msg := verifyErr(t, m, dir)
		mustContain(t, msg, "persistence scenario hot-read absent", "was not run", "isolation scenario "+s.Isolation[0].Name+" failed")
	})
	t.Run("smoke with a mock storage", func(t *testing.T) {
		dir := copyArtifacts(t)
		path := filepath.Join(dir, "smoke-single.json")
		var s q.SmokeReport
		readJSON(t, path, &s)
		s.Storage = "fake"
		writeJSON(t, path, s)
		_, msg := verifyErr(t, m, dir)
		mustContain(t, msg, `storage "fake"`)
	})
	t.Run("exit code is checked when the run is known", func(t *testing.T) {
		dir := copyArtifacts(t)
		path := filepath.Join(dir, "release-seed-20261110.json")
		writeJSON(t, path, base)
		rep := verify(m, dir, map[string]int{"release/seed/20261110": 1})
		found := false
		for _, r := range rep.Rows {
			for _, f := range r.Failures {
				found = found || strings.Contains(f, "release exited 1")
			}
		}
		if !found {
			t.Fatal("a nonzero exit code with a clean-looking report was accepted")
		}
	})
}

// This test pins the honest state of THIS tree: the locked release gate has 4
// unbound obligations (781 bound; the scrape-configuration facts of both PromQL
// profiles cannot be observed by any query) and 12 unrun cases (2343 matched
// against the pinned oracles), and both smoke layouts (single, three-voter distributed) run
// and pass. It must be updated, never relaxed, when the tree changes.
func TestCampaignReportsTheRealGateFaithfully(t *testing.T) {
	realCampaign(t)
	if campaignErr == nil || campaignReport.Verified {
		t.Fatal("the campaign passed on a tree whose release gate is rejected")
	}
	if !errors.Is(campaignErr, ErrCampaignRejected) {
		t.Fatalf("not an ErrCampaignRejected: %v", campaignErr)
	}
	byID := map[string]RowResult{}
	for _, r := range campaignReport.Rows {
		byID[r.ID] = r
		if r.ReportSHA256 == "" || r.Report == "" {
			t.Errorf("row %s lacks its bound report digest", r.ID)
		}
		if r.ExitCode == nil {
			t.Errorf("row %s has no recorded exit code", r.ID)
		} else if (*r.ExitCode == 0) != strings.HasPrefix(r.ID, "smoke/") {
			t.Errorf("row %s exit code %d: only the smoke rows may exit 0", r.ID, *r.ExitCode)
		}
	}
	if len(byID) != 8 {
		t.Fatalf("%d rows, want 3 profiles x 2 seeds + 2 layouts = 8", len(byID))
	}
	for id, r := range byID {
		if r.Verified != strings.HasPrefix(id, "smoke/") {
			t.Errorf("row %s verified=%v", id, r.Verified)
		}
	}
	rel := byID["release/promql-prometheus-3.1.0/seed/20261110"]
	mustContain(t, strings.Join(rel.Failures, "\n"), "obligations: 781 bound of 785, unbound 4", "cases: 12 unrun (2343 matched of 2355 required)", "unresolved 16")
	if strings.Contains(strings.Join(rel.Failures, "\n"), "oracle observation") || strings.Contains(strings.Join(rel.Failures, "\n"), "provenance rejected") {
		t.Errorf("the oracle was not run or provenance was rejected: %v", rel.Failures)
	}
	if rel.ProfileCommit == "" || rel.OracleConfigSHA256 == "" || rel.InputNormalizationID == "" || rel.Build == "" || rel.FeatureSets != 4 {
		t.Errorf("row digests not carried: %+v", rel)
	}
	if byID["release/promql-prometheus-3.13.5/seed/20261110"].FeatureSets != 128 || byID["release/logql-loki-3.5.2/seed/20270101"].FeatureSets != 64 {
		t.Error("feature-set counts were not carried per profile")
	}
	c := campaignReport.Counts
	// two release reports (one per seed): counts are summed over distinct reports.
	if c.Unbound != 2*4 || c.Unrun != 2*12 || c.Unresolved != 2*16 || c.Skipped != 0 || c.Mismatches != 0 || c.NormalizationLoss != 0 || c.OracleUnavailable != 0 || c.ProvenanceRefused != 0 {
		t.Errorf("aggregate counts %+v", c)
	}
	mustContain(t, campaignErr.Error(), "TOTAL unbound 8, unrun 24")
	// smoke: both layouts run and pass every step and every requirement.
	for _, id := range []string{"smoke/single", "smoke/distributed"} {
		if row := byID[id]; len(row.Failures) != 0 || !row.Verified {
			t.Errorf("%s failures: %v", id, row.Failures)
		}
	}
	if c.FailingSteps != 0 || c.NotSatisfied != 0 || c.ModesNotRun != 0 {
		t.Errorf("failing steps %d not satisfied %d modes not run %d", c.FailingSteps, c.NotSatisfied, c.ModesNotRun)
	}
	// The report on disk equals what was returned.
	var disk CampaignReport
	readJSON(t, filepath.Join(campaignDir, "campaign-report.json"), &disk)
	if disk.Verified || len(disk.Rows) != 8 || disk.Counts != c {
		t.Errorf("campaign-report.json differs from the returned report")
	}
}

func TestMatrixFileIsStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.yaml")
	if err := os.WriteFile(path, []byte("schema: x\nsurprise: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadQueryMatrix(path); err == nil {
		t.Fatal("an unknown matrix key was accepted")
	}
}
