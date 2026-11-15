// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/query/profile"
)

// TestOwnedMatchesRecordedNativeAnnotationAndNaNObservations replays the recorded
// observations of both pinned Prometheus references for annotation de-duplication
// across call sites (annotations keyed by rendered text) and for the NaN payload
// order of aggregations, range functions and binary operators, without a
// container runtime.
func TestOwnedMatchesRecordedNativeAnnotationAndNaNObservations(t *testing.T) {
	raw, err := os.ReadFile("testdata/native-promql-wave6-annotation-observations.json")
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
	if len(f.Rows) < 1264 {
		t.Fatalf("recorded annotation and NaN observations shrank to %d rows", len(f.Rows))
	}
	registry, err := profile.Load(os.DirFS("../../../profiles/query"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range f.Rows {
		row := row
		t.Run(row.Profile[len("promql-prometheus-"):]+"/"+row.Case.ID, func(t *testing.T) {
			var manifest profile.Profile
			if err := ReadJSON("../../../profiles/query/"+row.Profile+".json", &manifest); err != nil {
				t.Fatal(err)
			}
			sorted := append([]string(nil), row.Enabled...)
			sort.Strings(sorted)
			featureID := ""
			for _, set := range manifest.FeatureSets {
				candidate := append([]string(nil), set.Enabled...)
				sort.Strings(candidate)
				if strings.Join(candidate, "\x00") == strings.Join(sorted, "\x00") {
					featureID = set.ID
				}
			}
			p, err := registry.Resolve(row.Profile, featureID)
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
