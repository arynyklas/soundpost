// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/promql"
	syntax "soundpost/internal/query/syntax"
	"strings"
	"time"
)

type SyntaxCase struct {
	ID       string   `json:"id"`
	Profiles []string `json:"profiles"`
	Enabled  []string `json:"enabled_features"`
	Input    struct {
		Expression string `json:"expression"`
	} `json:"input"`
	Expected struct {
		Accepted bool   `json:"accepted"`
		Type     string `json:"type"`
		Category string `json:"category"`
	} `json:"expected"`
}
type OwnedSyntaxObservation struct {
	Accepted  bool   `json:"accepted"`
	Type      string `json:"type,omitempty"`
	Category  string `json:"category,omitempty"`
	StartByte int    `json:"start_byte"`
	EndByte   int    `json:"end_byte"`
	Formatted string `json:"formatted,omitempty"`
}
type SyntaxCaseComparison struct {
	ID         string                 `json:"id"`
	Profile    string                 `json:"profile"`
	FeatureSet string                 `json:"feature_set"`
	Identity   *OracleIdentity        `json:"oracle"`
	Owned      OwnedSyntaxObservation `json:"owned"`
	Reference  SyntaxObservation      `json:"reference"`
	Mismatches []string               `json:"mismatches"`
}
type SyntaxPhaseReport struct {
	Phase                        string                 `json:"phase"`
	Cases                        []SyntaxCaseComparison `json:"cases"`
	Compared                     int                    `json:"compared"`
	Failed                       int                    `json:"failed"`
	ReferenceEndPositionsExposed bool                   `json:"reference_end_positions_exposed"`
	PositionQualification        string                 `json:"position_qualification"`
}
type syntaxGroup struct {
	p      profile.Profile
	source SourceProfile
	cases  []SyntaxCase
	probes []SyntaxProbe
	owned  []OwnedSyntaxObservation
}

func observeOwnedSyntax(expression string, p profile.Profile) (OwnedSyntaxObservation, error) {
	var result OwnedSyntaxObservation
	tree, err := promql.Parse(expression, p)
	if err == nil {
		typed, _, e := promql.Check(tree, p)
		err = e
		if err == nil {
			result.Accepted = true
			result.Type = string(typed.Type)
			result.Formatted = promql.Format(tree)
			again, e := promql.Parse(result.Formatted, p)
			if e != nil {
				return result, fmt.Errorf("owned formatter emits invalid syntax: %w", e)
			}
			checked, _, e := promql.Check(again, p)
			if e != nil || checked.Type != typed.Type {
				return result, fmt.Errorf("owned formatter changes checked type")
			}
			return result, nil
		}
	}
	var language *syntax.LanguageError
	if !errors.As(err, &language) {
		return result, fmt.Errorf("unexpected owned parser failure: %w", err)
	}
	if language.Category == "profile" {
		return result, err
	}
	result.Category = language.Category
	result.StartByte = language.Range.StartByte
	result.EndByte = language.Range.EndByte
	return result, nil
}
func RunSyntaxPhase(ctx context.Context, lock SourceLock, casesPath, profilesPath, runtime string) (SyntaxPhaseReport, error) {
	report := SyntaxPhaseReport{Phase: "syntax", PositionQualification: "Reference HTTP exposes start line:byte-column only; end ranges are not claimed. Owned exact byte/rune and modifier-end position tests are independent mandatory unit evidence."}
	if err := ValidateSourceLock(lock); err != nil {
		return report, err
	}
	if _, err := Inventory(ctx, lock); err != nil {
		return report, err
	}
	cases, err := readLockedSyntaxCases(lock, casesPath)
	if err != nil {
		return report, err
	}
	registry, err := profile.Load(os.DirFS(profilesPath))
	if err != nil {
		return report, err
	}
	sources := map[string]SourceProfile{}
	for _, p := range lock.Profiles {
		sources[p.ID] = p
	}
	groups := map[string]*syntaxGroup{}
	seen := map[string]bool{}
	for _, c := range cases {
		if c.ID == "" || len(c.Profiles) == 0 {
			return report, fmt.Errorf("unscoped syntax case")
		}
		enabled := append([]string(nil), c.Enabled...)
		sort.Strings(enabled)
		for i, g := range enabled {
			if i > 0 && g == enabled[i-1] {
				return report, fmt.Errorf("duplicate case feature")
			}
		}
		for _, id := range c.Profiles {
			source, ok := sources[id]
			if !ok || !strings.HasPrefix(id, "promql-") {
				return report, fmt.Errorf("unsupported syntax case profile %s", id)
			}
			caseKey := id + "\x00" + c.ID
			if seen[caseKey] {
				return report, fmt.Errorf("duplicate syntax case %s", caseKey)
			}
			seen[caseKey] = true
			key := id + "\x00" + strings.Join(enabled, "\x00")
			group := groups[key]
			if group == nil {
				var manifest profile.Profile
				if err = ReadJSON(filepath.Join(profilesPath, id+".json"), &manifest); err != nil {
					return report, err
				}
				featureID := ""
				for _, set := range manifest.FeatureSets {
					candidate := append([]string(nil), set.Enabled...)
					sort.Strings(candidate)
					if strings.Join(candidate, "\x00") == strings.Join(enabled, "\x00") {
						featureID = set.ID
						break
					}
				}
				if featureID == "" {
					return report, fmt.Errorf("unregistered case feature combination %s", key)
				}
				selected, e := registry.Resolve(id, featureID)
				if e != nil {
					return report, e
				}
				group = &syntaxGroup{p: selected, source: source}
				groups[key] = group
			}
			owned, e := observeOwnedSyntax(c.Input.Expression, group.p)
			if e != nil {
				return report, fmt.Errorf("%s: %w", c.ID, e)
			}
			group.cases = append(group.cases, c)
			group.probes = append(group.probes, SyntaxProbe{ID: c.ID, Expression: c.Input.Expression, Formatted: owned.Formatted})
			group.owned = append(group.owned, owned)
		}
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		group := groups[key]
		configuration, e := os.ReadFile(group.source.ConfigurationPath)
		if e != nil {
			return report, e
		}
		input, e := json.Marshal(adapterInput{Phase: "syntax", EnabledFeatures: group.p.ActiveFeatureSet.Enabled, SyntaxCases: group.probes})
		if e != nil {
			return report, e
		}
		runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		actual, e := RunOracle(runCtx, OracleRun{Profile: group.source, Input: input, Configuration: configuration, Runtime: runtime})
		cancel()
		if e != nil {
			return report, e
		}
		if actual.Kind != "syntax" || len(actual.Syntax) != len(group.cases) {
			return report, fmt.Errorf("missing syntax oracle observations")
		}
		for i, c := range group.cases {
			reference := actual.Syntax[i]
			owned := group.owned[i]
			comparison := SyntaxCaseComparison{ID: c.ID, Profile: group.p.ID, FeatureSet: group.p.ActiveFeatureSet.ID, Identity: actual.Oracle, Owned: owned, Reference: reference}
			mismatch := func(text string) { comparison.Mismatches = append(comparison.Mismatches, text) }
			if reference.ID != c.ID {
				return report, fmt.Errorf("oracle case identity/order mismatch")
			}
			if owned.Accepted != reference.Accepted {
				mismatch("owned/reference acceptance differs")
			}
			if owned.Accepted != c.Expected.Accepted {
				mismatch("owned acceptance differs from authored case")
			}
			if reference.Accepted != c.Expected.Accepted {
				mismatch("reference acceptance differs from authored case")
			}
			if owned.Accepted && reference.Accepted {
				if owned.Type != reference.ValueType {
					mismatch("owned/reference type differs")
				}
				if c.Expected.Type != "" && owned.Type != c.Expected.Type {
					mismatch("owned type differs from authored case")
				}
				if c.Expected.Type != "" && reference.ValueType != c.Expected.Type {
					mismatch("reference type differs from authored case")
				}
				if !reference.FormatPreservedAST {
					mismatch("owned Format changes reference AST")
				}
			}
			if !owned.Accepted && !reference.Accepted {
				if c.Expected.Category != "" && owned.Category != c.Expected.Category {
					mismatch("owned error category differs from authored case")
				}
				if reference.ErrorCategory != "syntax-or-type" && owned.Category != reference.ErrorCategory {
					mismatch("owned/reference source-derived error category differs")
				}
				if reference.StartByte != nil && owned.StartByte != *reference.StartByte {
					mismatch("owned/reference exposed error start differs")
				}
			}
			report.Compared++
			if len(comparison.Mismatches) > 0 {
				report.Failed++
			}
			report.Cases = append(report.Cases, comparison)
		}
	}
	if report.Compared == 0 || report.Compared != len(seen) {
		return report, fmt.Errorf("unobserved applicable syntax cases")
	}
	if report.Failed > 0 {
		return report, fmt.Errorf("%d of %d syntax comparisons failed", report.Failed, report.Compared)
	}
	return report, nil
}

// Each additive corpus needs its own basename content lock. Identical bytes at
// another basename cannot borrow the original syntax corpus's authorization;
// alternate paths with the approved basename still require exact consumed bytes.
func readLockedSyntaxCases(lock SourceLock, casesPath string) ([]SyntaxCase, error) {
	var suite struct {
		Phase string       `json:"phase"`
		Cases []SyntaxCase `json:"cases"`
	}
	key := "cases/" + filepath.Base(casesPath)
	if err := ReadLockedJSON(lock, key, casesPath, &suite); err != nil {
		return nil, err
	}
	if suite.Phase != "syntax" || len(suite.Cases) == 0 {
		return nil, fmt.Errorf("missing syntax-phase cases")
	}
	applicable := map[string]bool{}
	for _, c := range suite.Cases {
		for _, id := range c.Profiles {
			if id != "promql-prometheus-3.1.0" && id != "promql-prometheus-3.13.5" {
				return nil, fmt.Errorf("unsupported syntax case profile %s", id)
			}
			applicable[id] = true
		}
	}
	if len(applicable) != 2 {
		return nil, fmt.Errorf("syntax comparison requires applicable cases for both exact PromQL profiles")
	}
	return suite.Cases, nil
}
