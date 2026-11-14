// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/query/profile"
)

// TestOwnedMatchesRecordedNativeLogQLWave2Observations replays observations of
// the lock-pinned Loki 3.5.2 oracle image (no container runtime needed) for the
// five LogQL questions left open by wave 1: approx_topk's parameter grammar and
// heap size, group modifiers, bool on arithmetic and zero-length ranges. A row
// with sketch_heap overrides the resolved count_min_sketch_heap_size, which a
// registered feature set cannot vary, so those rows exist only here.
func TestOwnedMatchesRecordedNativeLogQLWave2Observations(t *testing.T) {
	raw, err := os.ReadFile("testdata/native-logql-wave2-observations.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Rows []struct {
			Enabled    []string         `json:"enabled_features"`
			SketchHeap *int             `json:"sketch_heap"`
			Case       LogQLCase        `json:"case"`
			Reference  LogQLObservation `json:"reference"`
		} `json:"rows"`
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	// A floor, not an exact count: recorded rows may be added, never silently lost.
	if len(f.Rows) < 555 {
		t.Fatalf("recorded wave-2 native observations shrank to %d rows", len(f.Rows))
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
			if row.SketchHeap != nil {
				cfg := make(map[string]json.RawMessage, len(p.Configuration))
				for name, value := range p.Configuration {
					cfg[name] = value
				}
				cfg["count_min_sketch_heap_size"] = json.RawMessage(strconv.Quote(strconv.Itoa(*row.SketchHeap)))
				p.Configuration = cfg
			}
			owned, err := observeOwnedLogQL(context.Background(), row.Case, p)
			if err != nil {
				t.Fatalf("owned observation failed: %v", err)
			}
			if diff := CompareLogQL(row.Reference, owned); len(diff) != 0 {
				t.Fatalf("owned differs from recorded native observation: %#v\nquery: %s%s", diff, row.Case.Query, row.Case.Input.Expression)
			}
		})
	}
}
