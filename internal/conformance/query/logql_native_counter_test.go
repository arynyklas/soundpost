// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/query/profile"
)

// TestOwnedMatchesRecordedNativeRateCounterObservations replays observations of
// the lock-pinned Loki 3.5.2 oracle image (no container runtime needed) for
// rate_counter beyond the 227 rows the engine was first fitted to: windows from
// 100ms to 1h (including non-integer ones), spacings from 1ms to 30s, both sides
// of the 1.1*spacing half-spacing threshold and of the zero-intercept cap,
// multiplicity at threshold crossings, negative values, multiple resets,
// non-finite values, empty/edge windows, offsets, two streams and range queries.
// The owned constants were confirmed, not refitted: every row agrees bit for bit.
func TestOwnedMatchesRecordedNativeRateCounterObservations(t *testing.T) {
	raw, err := os.ReadFile("testdata/native-logql-rate-counter-observations.json")
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
	if len(f.Rows) < 1432 {
		t.Fatalf("recorded rate_counter observations shrank to %d rows", len(f.Rows))
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
