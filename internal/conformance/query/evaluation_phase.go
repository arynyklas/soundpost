// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"soundpost/internal/query/profile"
)

type EvaluationCaseComparison struct {
	ID                    string                `json:"id"`
	Profile               string                `json:"profile"`
	ProfileIdentity       string                `json:"profile_identity"`
	FeatureSet            string                `json:"feature_set"`
	ConfigurationHash     string                `json:"configuration_hash"`
	ReferenceCompiler     string                `json:"reference_compiler"`
	ReferenceSourceSHA256 string                `json:"reference_source_sha256"`
	Oracle                *OracleIdentity       `json:"oracle"`
	Owned                 EvaluationObservation `json:"owned"`
	Reference             EvaluationObservation `json:"reference"`
	Mismatches            []Mismatch            `json:"mismatches"`
}
type EvaluationPhaseReport struct {
	Phase                          string                     `json:"phase"`
	Cases                          []EvaluationCaseComparison `json:"cases"`
	Compared                       int                        `json:"compared"`
	Failed                         int                        `json:"failed"`
	Normalization                  []string                   `json:"normalization"`
	Qualification                  string                     `json:"qualification"`
	ReferenceStartTimestampExposed bool                       `json:"reference_start_timestamp_exposed"`
}
type evaluationGroup struct {
	p      profile.Profile
	source SourceProfile
	cases  []EvaluationCase
}

func checkEvaluationProfileHash(lock SourceLock, id string, raw []byte) error {
	sum := sha256.Sum256(raw)
	if lock.ProfileFiles["profiles/query/"+id+".json"] != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("consumed evaluation profile content is not locked: %s", id)
	}
	return nil
}
func prepareEvaluationGroups(cases []EvaluationCase, profilesPath string, sources map[string]SourceProfile) ([]evaluationGroup, error) {
	// A zero-row or one-profile report is not a qualification of the requested pair.
	applicable := map[string]bool{}
	seen := map[string]bool{}
	for _, c := range cases {
		if err := validateEvaluationCase(c); err != nil {
			return nil, err
		}
		for _, id := range c.Profiles {
			if id != "promql-prometheus-3.1.0" && id != "promql-prometheus-3.13.5" {
				return nil, fmt.Errorf("unsupported evaluation profile %s", id)
			}
			key := id + "\x00" + c.ID
			if seen[key] {
				return nil, fmt.Errorf("duplicate evaluation case %s/%s", id, c.ID)
			}
			seen[key] = true
			applicable[id] = true
		}
	}
	if len(applicable) != 2 {
		return nil, fmt.Errorf("evaluation comparison requires applicable cases for both exact PromQL profiles")
	}
	registry, err := profile.Load(os.DirFS(profilesPath))
	if err != nil {
		return nil, err
	}
	groups := map[string]*evaluationGroup{}
	for _, c := range cases {
		enabled := append([]string(nil), c.Enabled...)
		sort.Strings(enabled)
		for i, g := range enabled {
			if i > 0 && enabled[i-1] == g {
				return nil, fmt.Errorf("duplicate evaluation feature %s", g)
			}
		}
		for _, id := range c.Profiles {
			key := id + "\x00" + strings.Join(enabled, "\x00")
			group := groups[key]
			if group == nil {
				var manifest profile.Profile
				if err = ReadJSON(filepath.Join(profilesPath, id+".json"), &manifest); err != nil {
					return nil, err
				}
				featureID := ""
				for _, set := range manifest.FeatureSets {
					candidate := append([]string(nil), set.Enabled...)
					sort.Strings(candidate)
					if strings.Join(candidate, "\x00") == strings.Join(enabled, "\x00") {
						if featureID != "" {
							return nil, fmt.Errorf("ambiguous evaluation feature combination")
						}
						featureID = set.ID
					}
				}
				if featureID == "" {
					return nil, fmt.Errorf("unregistered evaluation feature combination %s", key)
				}
				selected, e := registry.Resolve(id, featureID)
				if e != nil {
					return nil, e
				}
				source, ok := sources[id]
				if !ok {
					return nil, fmt.Errorf("missing evaluation oracle artifact profile %s", id)
				}
				group = &evaluationGroup{p: selected, source: source}
				groups[key] = group
			}
			group.cases = append(group.cases, c)
		}
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]evaluationGroup, 0, len(keys))
	for _, key := range keys {
		out = append(out, *groups[key])
	}
	return out, nil
}
func evaluationDuration(p profile.Profile, key string) (int64, error) {
	var text string
	if err := json.Unmarshal(p.Configuration[key], &text); err != nil {
		return 0, fmt.Errorf("missing resolved evaluation configuration %s", key)
	}
	duration, err := strconv.ParseInt(text, 10, 64)
	if err != nil || duration <= 0 || strconv.FormatInt(duration, 10) != text {
		return 0, fmt.Errorf("invalid resolved evaluation configuration %s", key)
	}
	return duration, nil
}

// RunEvaluationPhase executes every requested applicable row once against both
// real implementations. Inventory and consumed-case/profile locks precede any
// owned evaluation or external process, and no missing observation is skipped.
func RunEvaluationPhase(ctx context.Context, lock SourceLock, casesPaths []string, profilesPath, runtime string) (EvaluationPhaseReport, error) {
	report := EvaluationPhaseReport{Phase: "evaluation", Normalization: []string{
		"Reference timestamps use its native millisecond domain (promql/engine.go durationMilliseconds and model/timestamp.FromTime in each exact pin); output is checked integer milliseconds * 1000000. Owned timestamps are never rounded or replaced.",
		"Reference annotations are a map in util/annotations/annotations.go in both exact pins. Comparison canonicalizes only exported annotation identity, severity and exact position; raw reference text and raw owned safe text/order are retained. No vector/matrix/label/histogram/float reordering or tolerance is permitted.",
		"Optional start_timestamp_ns is exact hash-bound input/C05 metadata; native 3.13 AtST observes its declared millisecond conversion, absent maps only to the upstream zero sentinel. PromQL result Sample has no ST field: reference_start_timestamp_exposed is false, owned raw scan_input_start_timestamps are retained separately, and actual gated function consequences are compared exactly. Observed time is never substituted for start metadata.",
		"Histogram spans/buckets/custom-bound slices with length zero project nil and allocated-empty forms only. Raw own/reference observations remain unchanged; nonempty layouts, variants, flavor/hints, integer counts/deltas and every FloatBits field remain exact. No union nil/non-nil normalization occurs.",
		"Native ParseErrors exposes a joint parser/checkAST error class, not an independent syntax/type stage; category_exposed is false there. Stable source-proven semantic families are compared with owned typed LanguageError.Code, raw texts retained without prose parity. Unknown family is a hard mismatch; every valid native start/end range remains exact.",
	}, Qualification: "This report qualifies only the observed cases and selected registered feature sets. It is not complete runtime binding, feature cross-product, storage authorization or full-profile conformance acceptance."}
	if err := ValidateSourceLock(lock); err != nil {
		return report, err
	}
	if _, err := Inventory(ctx, lock); err != nil {
		return report, err
	}
	cases, err := readEvaluationCases(lock, casesPaths)
	if err != nil {
		return report, err
	}
	sources := map[string]SourceProfile{}
	for _, p := range lock.Profiles {
		sources[p.ID] = p
	}
	snapshot, cleanup, err := snapshotEvaluationProfiles(lock, profilesPath)
	if err != nil {
		return report, err
	}
	defer cleanup()
	groups, err := prepareEvaluationGroups(cases, snapshot, sources)
	if err != nil {
		return report, err
	}
	expected := 0
	for _, g := range groups {
		expected += len(g.cases)
	}
	for _, group := range groups {
		if err = ctx.Err(); err != nil {
			return report, err
		}
		configuration, e := os.ReadFile(group.source.ConfigurationPath)
		if e != nil {
			return report, e
		}
		lookback, e := evaluationDuration(group.p, "lookback_delta_ns")
		if e != nil {
			return report, e
		}
		subquery, e := evaluationDuration(group.p, "default_subquery_step_ns")
		if e != nil {
			return report, e
		}
		input := evaluationInput{Profile: group.p.ID, Commit: group.p.Commit, ProfileIdentity: group.p.Identity, FeatureSet: group.p.ActiveFeatureSet.ID, ConfigurationHash: group.p.ConfigurationHash, Enabled: group.p.ActiveFeatureSet.Enabled, Lookback: lookback, SubqueryStep: subquery, Cases: group.cases, Configuration: group.p.Configuration, ManifestVersion: group.p.ManifestVersion}
		payload, e := json.Marshal(adapterInput{Phase: "evaluation", EnabledFeatures: group.p.ActiveFeatureSet.Enabled, Evaluation: &input})
		if e != nil {
			return report, e
		}
		runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		actual, e := RunOracle(runCtx, OracleRun{Profile: group.source, Input: payload, Configuration: configuration, Runtime: runtime})
		cancel()
		if e != nil {
			return report, e
		}
		if actual.Kind != "evaluation" || actual.Evaluation == nil {
			return report, fmt.Errorf("missing native evaluation oracle batch; rebuild locked reference wrapper")
		}
		if e = validateEvaluationBatch(*actual.Evaluation, group.p, group.cases); e != nil {
			return report, e
		}
		if actual.Evaluation.SourceSHA256 != group.source.SourceSHA256 {
			return report, fmt.Errorf("native evaluation source archive identity mismatch")
		}
		for i, c := range group.cases {
			owned, e := observeOwnedEvaluation(ctx, c, group.p)
			if e != nil {
				return report, fmt.Errorf("%s/%s: %w", group.p.ID, c.ID, e)
			}
			reference := actual.Evaluation.Observations[i]
			comparison := EvaluationCaseComparison{ID: c.ID, Profile: group.p.ID, ProfileIdentity: group.p.Identity, FeatureSet: group.p.ActiveFeatureSet.ID, ConfigurationHash: group.p.ConfigurationHash, ReferenceCompiler: actual.Evaluation.Compiler, ReferenceSourceSHA256: actual.Evaluation.SourceSHA256, Oracle: actual.Oracle, Owned: owned, Reference: reference, Mismatches: CompareEvaluation(reference, owned)}
			report.Compared++
			if len(comparison.Mismatches) > 0 {
				report.Failed++
			}
			report.Cases = append(report.Cases, comparison)
		}
	}
	if report.Compared == 0 || report.Compared != expected {
		return report, fmt.Errorf("unobserved applicable evaluation cases")
	}
	if report.Failed > 0 {
		return report, fmt.Errorf("%d of %d evaluation comparisons failed", report.Failed, report.Compared)
	}
	return report, nil
}

// Registry.Load and feature resolution consume one private immutable snapshot of
// the exact bytes hashed here, not a second mutable profile-directory read.
func snapshotEvaluationProfiles(lock SourceLock, path string) (string, func(), error) {
	directory, err := os.MkdirTemp("", "soundpost-evaluation-profiles-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	for _, p := range lock.Profiles {
		raw, e := os.ReadFile(filepath.Join(path, p.ID+".json"))
		if e != nil {
			cleanup()
			return "", nil, e
		}
		if e = checkEvaluationProfileHash(lock, p.ID, raw); e != nil {
			cleanup()
			return "", nil, e
		}
		if e = os.WriteFile(filepath.Join(directory, p.ID+".json"), raw, 0600); e != nil {
			cleanup()
			return "", nil, e
		}
	}
	return directory, cleanup, nil
}
