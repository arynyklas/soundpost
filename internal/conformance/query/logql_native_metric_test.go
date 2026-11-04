// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"soundpost/internal/query/profile"
)

// TestOwnedMatchesRecordedNativeMetricObservations replays recorded observations
// of the pinned Loki 3.5.2 reference (no container runtime needed) through the
// owned engine and demands zero comparator mismatches. An owned failure that is
// not a typed language error fails its row instead of aborting the replay.
func TestOwnedMatchesRecordedNativeMetricObservations(t *testing.T) {
	raw, err := os.ReadFile("testdata/native-metric-observations.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Rows []struct {
			Enabled   []string         `json:"enabled_features"`
			Case      LogQLCase        `json:"case"`
			Reference LogQLObservation `json:"reference"`
		} `json:"rows"`
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	// A floor, not an exact count: recorded rows may be added, never silently lost.
	if len(f.Rows) < 1704 {
		t.Fatalf("recorded native metric observations shrank to %d rows", len(f.Rows))
	}
	profiles := map[string]profile.Profile{}
	for _, row := range f.Rows {
		row := row
		t.Run(row.Case.ID, func(t *testing.T) {
			key := strings.Join(row.Enabled, "\x00")
			p, ok := profiles[key]
			if !ok {
				p, err = resolveLogQLProfile("../../../profiles/query", row.Enabled)
				if err != nil {
					t.Fatal(err)
				}
				profiles[key] = p
			}
			owned, err := observeOwnedLogQL(context.Background(), row.Case, p)
			if err != nil {
				t.Fatalf("owned observation failed: %v", err)
			}
			if diff := CompareLogQL(row.Reference, owned); len(diff) != 0 {
				t.Fatalf("owned differs from recorded native observation: %#v\nquery: %s", diff, row.Case.Query)
			}
		})
	}
}
