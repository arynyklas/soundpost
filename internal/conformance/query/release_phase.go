// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// ReleaseCaseManifest is conformance/query/release-cases.json: the content-locked
// authored case files whose rows carry the ledger's positive/negative/interaction
// case IDs. Each file is run by the same differential phase runner that qualified
// it (owned engine against the pinned reference), never by a second comparator.
type ReleaseCaseManifest struct {
	Schema string             `json:"schema"`
	Files  []ReleasePhaseFile `json:"files"`
}

// ReleasePhaseFile names one locked case file. Language is promql or logql; Phase
// is the runner phase: syntax or evaluation for PromQL; syntax, pipeline,
// syntax,pipeline, logql-template or logql-metric for LogQL.
type ReleasePhaseFile struct {
	Path     string `json:"path"`
	Language string `json:"language"`
	Phase    string `json:"phase"`
}

// PhaseOutcome is what a differential phase run observed for one (profile, case).
type PhaseOutcome struct {
	Phase    string
	Identity *OracleIdentity
	Problems []string
}

// PhaseResults are keyed by PhaseKey(profile, case ID).
type PhaseResults map[string]PhaseOutcome

func PhaseKey(profile, id string) string { return profile + "\x00" + id }

// LoadReleaseCaseManifest reads and validates the manifest.
func LoadReleaseCaseManifest(path string) (ReleaseCaseManifest, error) {
	var m ReleaseCaseManifest
	if err := ReadJSON(path, &m); err != nil {
		return m, err
	}
	if m.Schema != "soundpost-query-release-cases/1" || len(m.Files) == 0 {
		return m, fmt.Errorf("invalid release case manifest %s", path)
	}
	for _, f := range m.Files {
		switch {
		case f.Language == "promql" && (f.Phase == "syntax" || f.Phase == "evaluation"):
		case f.Language == "logql" && (f.Phase == "syntax" || f.Phase == "pipeline" || f.Phase == "syntax,pipeline" || f.Phase == "logql-template" || f.Phase == "logql-metric"):
		default:
			return m, fmt.Errorf("release case file %s: unsupported language/phase %s/%s", f.Path, f.Language, f.Phase)
		}
	}
	return m, nil
}

func releasePhaseTag(f ReleasePhaseFile) string { return f.Language + ":" + f.Phase }

type phaseRow struct{ profile, id string }

// ReleaseCasesFromManifest turns every row of every locked case file into one
// ReleaseCase. The expectation of a differential row is "no disagreement": the
// phase runner's own authored-expectation and owned/reference comparisons.
func ReleaseCasesFromManifest(lock SourceLock, queryDir string, m ReleaseCaseManifest) ([]ReleaseCase, error) {
	var out []ReleaseCase
	for _, f := range m.Files {
		path := filepath.Join(queryDir, filepath.FromSlash(f.Path))
		var ids []phaseRow
		switch {
		case f.Language == "promql" && f.Phase == "syntax":
			cases, err := readLockedSyntaxCases(lock, path)
			if err != nil {
				return nil, err
			}
			for _, c := range cases {
				for _, p := range c.Profiles {
					ids = append(ids, phaseRow{p, c.ID})
				}
			}
		case f.Language == "promql":
			cases, err := readEvaluationCases(lock, []string{path})
			if err != nil {
				return nil, err
			}
			for _, c := range cases {
				for _, p := range c.Profiles {
					ids = append(ids, phaseRow{p, c.ID})
				}
			}
		default:
			cases, err := readLogQLCases(lock, path, f.Phase)
			if err != nil {
				return nil, err
			}
			for _, c := range cases {
				for _, p := range c.Profiles {
					ids = append(ids, phaseRow{p, c.ID})
				}
			}
		}
		raw, _ := json.Marshal(struct {
			File  string `json:"file"`
			Phase string `json:"phase"`
		}{f.Path, releasePhaseTag(f)})
		for _, k := range ids {
			out = append(out, ReleaseCase{ID: k.id, Profile: k.profile, Input: raw, Expected: SemanticResult{Kind: "phase-case", Type: releasePhaseTag(f)}})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Profile != out[j].Profile {
			return out[i].Profile < out[j].Profile
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// RunReleasePhases runs every manifest file through its differential phase runner
// and collects one outcome per (profile, case). A runner failure that still
// produced per-case comparisons keeps those comparisons: their mismatches are the
// evidence. A runner that observed nothing returns its error.
func RunReleasePhases(ctx context.Context, lock SourceLock, queryDir, profilesDir, runtime string, m ReleaseCaseManifest) (PhaseResults, error) {
	results := PhaseResults{}
	var failures []string
	for _, f := range m.Files {
		path := filepath.Join(queryDir, filepath.FromSlash(f.Path))
		tag := releasePhaseTag(f)
		switch {
		case f.Language == "promql" && f.Phase == "syntax":
			rep, err := RunSyntaxPhase(ctx, lock, path, profilesDir, runtime)
			for _, c := range rep.Cases {
				results[PhaseKey(c.Profile, c.ID)] = PhaseOutcome{Phase: tag, Identity: c.Identity, Problems: c.Mismatches}
			}
			if err != nil && len(rep.Cases) == 0 {
				failures = append(failures, fmt.Sprintf("%s: %v", f.Path, err))
			}
		case f.Language == "promql":
			rep, err := RunEvaluationPhase(ctx, lock, []string{path}, profilesDir, runtime)
			for _, c := range rep.Cases {
				var problems []string
				for _, mm := range c.Mismatches {
					problems = append(problems, fmt.Sprintf("%s: reference %v, owned %v", mm.Field, mm.Want, mm.Got))
				}
				results[PhaseKey(c.Profile, c.ID)] = PhaseOutcome{Phase: tag, Identity: c.Oracle, Problems: problems}
			}
			if err != nil && len(rep.Cases) == 0 {
				failures = append(failures, fmt.Sprintf("%s: %v", f.Path, err))
			}
		default:
			rep, err := RunLogQLPhase(ctx, lock, path, profilesDir, runtime, f.Phase)
			for _, c := range rep.Cases {
				var problems []string
				for _, mm := range c.Mismatches {
					problems = append(problems, fmt.Sprintf("%s: reference %v, owned %v", mm.Field, mm.Want, mm.Got))
				}
				results[PhaseKey(logQLProfile, c.ID)] = PhaseOutcome{Phase: tag, Identity: c.Oracle, Problems: problems}
			}
			if err != nil && len(rep.Cases) == 0 {
				failures = append(failures, fmt.Sprintf("%s: %v", f.Path, err))
			}
		}
	}
	if len(failures) > 0 {
		return results, fmt.Errorf("phase runs observed nothing: %s", strings.Join(failures, "; "))
	}
	return results, nil
}

// PhaseOracle serves the reference side of the gate from the phase runs: the
// observation exists only if the pinned oracle was actually run for that row.
func (r PhaseResults) PhaseOracle() OracleFunc {
	return func(_ context.Context, p SourceProfile, c ReleaseCase) (SemanticResult, error) {
		o, ok := r[PhaseKey(p.ID, c.ID)]
		if !ok || o.Identity == nil {
			return SemanticResult{}, fmt.Errorf("the pinned oracle did not observe %s", c.ID)
		}
		id := *o.Identity
		return SemanticResult{Kind: "phase-case", Type: o.Phase, Oracle: &id}, nil
	}
}

// PhaseOwn serves the owned side: any disagreement the runner found (against the
// reference or against the authored row) is an owned mismatch carrying its text.
func (r PhaseResults) PhaseOwn() OwnFunc {
	return func(_ context.Context, c ReleaseCase) (SemanticResult, error) {
		o, ok := r[PhaseKey(c.Profile, c.ID)]
		if !ok {
			return SemanticResult{}, fmt.Errorf("the owned engine was not run for %s", c.ID)
		}
		if len(o.Problems) > 0 {
			return SemanticResult{}, fmt.Errorf("%s", strings.Join(o.Problems, "; "))
		}
		return SemanticResult{Kind: "phase-case", Type: o.Phase}, nil
	}
}
