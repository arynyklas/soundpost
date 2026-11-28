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
	if len(f.Rows) < 1440 {
		t.Fatalf("recorded annotation and NaN observations shrank to %d rows", len(f.Rows))
	}
	// The count_values rows over NaN-valued samples must stay: 88 rows per pin, none dropped.
	countValues := map[string]int{}
	for _, row := range f.Rows {
		if !strings.Contains(row.Case.Query, "count_values") {
			continue
		}
		countValues[row.Profile]++
		// A reference vector with two or more count_values groups has an unspecified order and the case
		// must say so; a single group, an empty result or a range result is compared exactly in order.
		wantMarker := row.Case.Kind == "instant" && len(row.Reference.Series) >= 2
		if row.Case.UnorderedVector != wantMarker {
			t.Errorf("%s: unordered_vector=%v, reference holds %d series (%s)", row.Case.ID, row.Case.UnorderedVector, len(row.Reference.Series), row.Case.Kind)
		}
	}
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		if countValues[id] < 88 {
			t.Fatalf("recorded count_values NaN rows for %s shrank to %d", id, countValues[id])
		}
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
			if err := validateUnorderedVector(row.Case, p); err != nil {
				t.Fatal(err)
			}
			owned, err := observeOwnedEvaluation(context.Background(), row.Case, p)
			if err != nil {
				t.Fatalf("owned observation failed: %v", err)
			}
			if diff := CompareEvaluationCase(row.Case, row.Reference, owned); len(diff) != 0 {
				t.Fatalf("owned differs from recorded native observation: %#v\nquery: %s", diff, row.Case.Query)
			}
		})
	}
}
