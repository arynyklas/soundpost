// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

// Release evidence exporters (soundpost-release-evidence/1). Each function converts the rows a
// producer already wrote into the gate's envelope. Nothing here decides a verdict: a row is
// "passed" only when the producer's own row says so, every other producer state maps to one
// non-passing status, and the expected row ids come from the producer's declarative matrix or
// policy, never from the rows being exported, so a dropped row stays visible as missing.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	q "github.com/arynyklas/soundpost/internal/conformance/query"
	"github.com/arynyklas/soundpost/internal/releaseevidence"
)

const campaignSchema = "soundpost-query-campaign/1"

// CampaignMatrixRowID is the envelope row that carries the matrix-level verdict of the campaign:
// the release policy, profile pins, FeatureSet registration, duplicate and unknown rows, and any
// execution error. It passes only when the report lists no missing item and no failure.
const CampaignMatrixRowID = "campaign/matrix"

// ReleaseRowID names the campaign row of one profile and seed.
func ReleaseRowID(profile string, seed uint64) string {
	return fmt.Sprintf("release/%s/seed/%d", profile, seed)
}

// SmokeRowID names the campaign row of one persisted layout.
func SmokeRowID(layout string) string { return "smoke/" + layout }

// ReadCampaignReport decodes a campaign-report.json strictly.
func ReadCampaignReport(path string) (CampaignReport, error) {
	var rep CampaignReport
	raw, err := os.ReadFile(path)
	if err != nil {
		return rep, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&rep); err != nil {
		return CampaignReport{}, fmt.Errorf("%s: %w", path, err)
	}
	if rep.Schema != campaignSchema {
		return CampaignReport{}, fmt.Errorf("%s: schema %q, want %q", path, rep.Schema, campaignSchema)
	}
	return rep, nil
}

type campaignSpec struct {
	id, kind, profile, layout string
	seed                      uint64
}

// campaignSpecs lists the rows the campaign must deliver: one per release profile of the locked
// policy and matrix seed, and one per required layout.
func campaignSpecs(m QueryMatrix) ([]campaignSpec, error) {
	var policy policyFile
	if err := q.ReadJSON(filepath.Join(m.Root, filepath.FromSlash(m.Policy)), &policy); err != nil {
		return nil, fmt.Errorf("release policy unreadable: %w", err)
	}
	var specs []campaignSpec
	for _, seed := range m.Seeds {
		for _, p := range policy.AllProfiles {
			specs = append(specs, campaignSpec{id: ReleaseRowID(p, seed), kind: "release", profile: p, seed: seed})
		}
	}
	for _, l := range RequiredLayouts {
		specs = append(specs, campaignSpec{id: SmokeRowID(l), kind: "smoke", layout: l})
	}
	return specs, nil
}

// RequiredCampaignRows lists the envelope row ids the campaign must deliver: the campaign rows
// of campaignSpecs and the matrix verdict.
func RequiredCampaignRows(m QueryMatrix) ([]string, error) {
	specs, err := campaignSpecs(m)
	if err != nil {
		return nil, err
	}
	ids := []string{CampaignMatrixRowID}
	for _, s := range specs {
		ids = append(ids, s.id)
	}
	return dedupe(ids), nil
}

// QueryCampaignEvidence exports the 07.05 campaign result as the "language" report. A campaign
// row is bound to its envelope row by profile, seed and layout, not by its matrix-chosen id.
func QueryCampaignEvidence(m QueryMatrix, rep CampaignReport, commit string) (releaseevidence.Report, error) {
	if rep.Schema != campaignSchema {
		return releaseevidence.Report{}, fmt.Errorf("campaign report schema %q, want %q", rep.Schema, campaignSchema)
	}
	specs, err := campaignSpecs(m)
	if err != nil {
		return releaseevidence.Report{}, err
	}
	expected, err := RequiredCampaignRows(m)
	if err != nil {
		return releaseevidence.Report{}, err
	}
	matrixOK := len(rep.Missing) == 0 && len(rep.Failures) == 0
	detail := ""
	if !matrixOK {
		var parts []string
		for _, s := range rep.Missing {
			parts = append(parts, "missing: "+s)
		}
		for _, s := range rep.Failures {
			parts = append(parts, "failure: "+s)
		}
		detail = releaseevidence.Detail(parts...)
	}
	rows := []releaseevidence.Row{row(CampaignMatrixRowID, matrixOK, detail)}
	byKey := map[string]RowResult{}
	for _, r := range rep.Rows {
		byKey[campaignKey(r.Kind, r.Profile, r.Layout, r.Seed)] = r
	}
	for _, s := range specs {
		r, ok := byKey[campaignKey(s.kind, s.profile, s.layout, s.seed)]
		if !ok {
			continue // no campaign row: the gate reports the expected id as having no result
		}
		d := releaseevidence.Detail(append([]string{"report " + r.Report + " sha256 " + r.ReportSHA256}, r.Failures...)...)
		rows = append(rows, row(s.id, r.Verified, d))
	}
	source, err := releaseevidence.AgreedSource([]releaseevidence.Stamp{{Name: "campaign report", Source: rep.SourceSHA256}})
	if err != nil {
		return releaseevidence.Report{}, err
	}
	return releaseevidence.New(releaseevidence.KindLanguage, commit, source, expected, rows)
}

func campaignKey(kind, profile, layout string, seed uint64) string {
	return fmt.Sprintf("%s|%s|%s|%d", kind, profile, layout, seed)
}

func row(id string, passed bool, detail string) releaseevidence.Row {
	if passed {
		return releaseevidence.Row{ID: id, Status: releaseevidence.StatusPassed, Detail: detail}
	}
	// A campaign row fails when a comparison of the owned engine with the pinned oracle failed or a required report is missing.
	return releaseevidence.Row{ID: id, Status: releaseevidence.StatusFailed, FailureClass: releaseevidence.FailureAssertion, Detail: detail}
}

// EvidenceSuites names the qualification suites whose rows make up a report kind: the runtime
// report carries the runtime and overhead suites, the privacy report the privacy suite.
func EvidenceSuites(kind string) ([]Suite, error) {
	switch kind {
	case releaseevidence.KindRuntime:
		return []Suite{SuiteRuntime, SuiteOverhead}, nil
	case releaseevidence.KindPrivacy:
		return []Suite{SuitePrivacy}, nil
	}
	return nil, fmt.Errorf("kind %q has no qualification suites (runtime or privacy)", kind)
}

// ReadSuiteReport reads and validates a <suite>-report.json (every row is re-validated).
func ReadSuiteReport(path string) (SuiteReport, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return SuiteReport{}, err
	}
	rep, err := ParseSuiteReport(raw)
	if err != nil {
		return SuiteReport{}, fmt.Errorf("%s: %w", path, err)
	}
	return rep, nil
}

// SuiteEvidence exports qualification suite reports as the "runtime" or "privacy" report.
//
// Expected rows are the required rows of the matrix for the kind's suites. Exported rows are the
// report rows the producer itself counts: every required row, and every exercised row that
// failed (the producer's Verdict treats a failed non-required row as a measured failure). A
// required row is "passed" only when it is exercised and its own outcome is passed; not_exercised,
// unsupported and denied keep their own names so the reason stays visible. Non-required rows that
// are not failures do not block the producer and are not exported.
func SuiteEvidence(kind, matrixPath string, reports []SuiteReport, commit string) (releaseevidence.Report, error) {
	suites, err := EvidenceSuites(kind)
	if err != nil {
		return releaseevidence.Report{}, err
	}
	m, err := LoadMatrix(matrixPath)
	if err != nil {
		return releaseevidence.Report{}, err
	}
	rawMatrix, err := os.ReadFile(matrixPath)
	if err != nil {
		return releaseevidence.Report{}, err
	}
	sum := sha256.Sum256(rawMatrix)
	matrixSHA := hex.EncodeToString(sum[:])
	inKind := map[Suite]bool{}
	for _, s := range suites {
		inKind[s] = true
	}
	var expected []string
	for _, spec := range m.Rows {
		if spec.Required && inKind[spec.Suite] {
			expected = append(expected, spec.ID)
		}
	}
	var rows []releaseevidence.Row
	seenSuite := map[Suite]bool{}
	for _, rep := range reports {
		if !inKind[rep.Suite] {
			return releaseevidence.Report{}, fmt.Errorf("a %s suite report does not belong in a %s report", rep.Suite, kind)
		}
		if seenSuite[rep.Suite] {
			return releaseevidence.Report{}, fmt.Errorf("two %s suite reports given", rep.Suite)
		}
		seenSuite[rep.Suite] = true
		if rep.MatrixSHA != matrixSHA {
			return releaseevidence.Report{}, fmt.Errorf("%s report was produced from a different matrix (report %s, %s is %s)", rep.Suite, rep.MatrixSHA, matrixPath, matrixSHA)
		}
		for _, r := range rep.Rows {
			if r.Suite != rep.Suite {
				return releaseevidence.Report{}, fmt.Errorf("row %s belongs to suite %s inside a %s report", r.ID, r.Suite, rep.Suite)
			}
			failedExercise := r.State == StateExercised && r.Outcome == OutcomeFailed
			if !r.Required && !failedExercise {
				continue
			}
			rows = append(rows, suiteRow(r))
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	var stamps []releaseevidence.Stamp
	for _, rep := range reports {
		stamps = append(stamps, releaseevidence.Stamp{Name: string(rep.Suite) + " suite report", Source: rep.SourceSHA256})
	}
	source, err := releaseevidence.AgreedSource(stamps)
	if err != nil {
		return releaseevidence.Report{}, err
	}
	return releaseevidence.New(kind, commit, source, expected, rows)
}

// exportedFailureClass is the failure class of an exercised row that did not pass. It is derived from the row's
// structure and never from its text: a runner's explicit class (harness, dropped_records, assertion) wins; otherwise a
// row with any failure text is a harness failure (privacy suite rows: an assertion, a canary check failed), and only a
// row that carries no failure text and has a measured budget that was not met is a budget_miss. ValidateRow already
// refuses a failed row with neither.
func exportedFailureClass(r Row) releaseevidence.FailureClass {
	if r.FailureClass != "" {
		return r.FailureClass
	}
	if len(r.Failures) > 0 {
		if r.Suite == SuitePrivacy {
			return releaseevidence.FailureAssertion
		}
		return releaseevidence.FailureHarness
	}
	for _, b := range r.Budgets {
		if !b.Within {
			return releaseevidence.FailureBudgetMiss
		}
	}
	return releaseevidence.FailureHarness
}

func suiteRow(r Row) releaseevidence.Row {
	out := releaseevidence.Row{ID: r.ID}
	switch r.State {
	case StateExercised:
		if r.Outcome == OutcomePassed {
			out.Status = releaseevidence.StatusPassed
			out.Detail = releaseevidence.Detail(r.Build.Family+" "+r.Build.Version+" "+r.Build.OS+"/"+r.Build.Arch+" build "+r.Build.ID, strings.Join(r.Evidence, ", "))
			return out
		}
		out.Status = releaseevidence.StatusFailed
		out.FailureClass = exportedFailureClass(r)
		parts := append([]string{}, r.Failures...)
		for _, b := range r.Budgets {
			if !b.Within {
				parts = append(parts, fmt.Sprintf("%s observed %.4g %s > limit %.4g", b.Name, b.Observed, b.Unit, b.Limit))
			}
		}
		out.Detail = releaseevidence.Detail(parts...)
	case StateNotExercised:
		out.Status = string(r.State)
		out.FailureClass = releaseevidence.FailureNotRun
		out.Detail = releaseevidence.Detail(r.Reason)
	case StateUnsupported:
		out.Status = string(r.State)
		out.FailureClass = releaseevidence.FailureUnsupported
		out.Detail = releaseevidence.Detail(r.Reason)
	case StateDenied:
		out.Status = string(r.State)
		out.FailureClass = releaseevidence.FailureDenied
		out.Detail = releaseevidence.Detail(r.Reason)
	case StateOutOfReleaseScope:
		out.Status = releaseevidence.StatusOutOfReleaseScope
		out.FailureClass = releaseevidence.FailureOutOfScope
		out.Platform = r.Subject.OS + "/" + r.Subject.Arch
		out.Detail = releaseevidence.Detail(r.Reason)
	default:
		out.Status = releaseevidence.StatusFailed
		out.FailureClass = releaseevidence.FailureHarness
		out.Detail = fmt.Sprintf("unknown state %q", r.State)
	}
	return out
}
