// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"soundpost/internal/query/profile"
)

// TestOwnedMatchesRecordedNativeEvaluationObservations replays recorded
// observations of the pinned Prometheus references (no container runtime needed)
// through the owned engine and demands zero comparator mismatches. Each row names
// the exact profile and enabled feature set it was observed under.
func TestOwnedMatchesRecordedNativeEvaluationObservations(t *testing.T) {
	raw, err := os.ReadFile("testdata/native-promql-observations.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Rows []struct {
			Profile   string                `json:"profile"`
			Enabled   []string              `json:"enabled_features"`
			Case      EvaluationCase        `json:"case"`
			Reference EvaluationObservation `json:"reference"`
		} `json:"rows"`
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	// A floor, not an exact count: recorded rows may be added, never silently lost.
	if len(f.Rows) < 4723 {
		t.Fatalf("recorded native evaluation observations shrank to %d rows", len(f.Rows))
	}
	registry, err := profile.Load(os.DirFS("../../../profiles/query"))
	if err != nil {
		t.Fatal(err)
	}
	resolved := map[string]profile.Profile{}
	resolve := func(id string, enabled []string) (profile.Profile, error) {
		sorted := append([]string(nil), enabled...)
		sort.Strings(sorted)
		key := id + "\x00" + strings.Join(sorted, "\x00")
		if p, ok := resolved[key]; ok {
			return p, nil
		}
		var manifest profile.Profile
		if err := ReadJSON("../../../profiles/query/"+id+".json", &manifest); err != nil {
			return profile.Profile{}, err
		}
		featureID := ""
		for _, set := range manifest.FeatureSets {
			candidate := append([]string(nil), set.Enabled...)
			sort.Strings(candidate)
			if strings.Join(candidate, "\x00") == strings.Join(sorted, "\x00") {
				featureID = set.ID
			}
		}
		if featureID == "" {
			return profile.Profile{}, fmt.Errorf("unregistered feature combination %v", enabled)
		}
		p, err := registry.Resolve(id, featureID)
		if err == nil {
			resolved[key] = p
		}
		return p, err
	}
	for _, row := range f.Rows {
		row := row
		t.Run(row.Profile[len("promql-prometheus-"):]+"/"+row.Case.ID, func(t *testing.T) {
			p, err := resolve(row.Profile, row.Enabled)
			if err != nil {
				t.Fatal(err)
			}
			owned, err := observeOwnedEvaluation(context.Background(), row.Case, p)
			if err != nil {
				t.Fatalf("owned observation failed: %v", err)
			}
			if diff := CompareEvaluation(row.Reference, owned); len(diff) != 0 {
				t.Fatalf("owned differs from recorded native observation: %#v\nquery: %s", diff, row.Case.Query)
			}
		})
	}
}
