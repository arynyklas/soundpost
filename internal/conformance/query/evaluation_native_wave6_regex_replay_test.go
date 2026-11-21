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

// TestOwnedMatchesRecordedNativeRegexUTF8Observations replays the recorded
// observations of both pinned Prometheus references for selector regexes that are
// literal alternatives holding bytes that are not UTF-8 (the reference matches
// them by byte equality and never compiles them), without a container runtime.
func TestOwnedMatchesRecordedNativeRegexUTF8Observations(t *testing.T) {
	raw, err := os.ReadFile("testdata/native-promql-wave6-regex-observations.json")
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
	if len(f.Rows) < 34 {
		t.Fatalf("recorded regex observations shrank to %d rows", len(f.Rows))
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
