// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

import (
	"encoding/json"
	"testing"
)

// requireHistogramNormalization fails unless the persisted-path run produced, at every
// stage, the histogram half of the input normalization evidence the release gate requires
// (GR-21): for each native histogram feed of persisted-path.json the histograms it sent
// against the ones storage returned, in both forms (integer and float), non-empty and
// equal record for record. Without it the gate's histogram branch is fed by nothing.
func requireHistogramNormalization(t *testing.T, res PersistedResult, layout Layout) {
	t.Helper()
	stages := []string{"hot", "flush", "multi-segment", "compaction", "restart", "restart-after-compaction", "after-conflict"}
	feeds := []string{"direct-ingest", "remote-write-v1", "remote-write-v2"}
	byID := map[string]int{}
	for i, c := range res.Normalization {
		if _, dup := byID[c.ID]; dup {
			t.Errorf("normalization check %s is reported twice", c.ID)
		}
		byID[c.ID] = i
	}
	integer, float := false, false
	for _, stage := range stages {
		for _, feed := range feeds {
			id := normalizationID(layout, stage) + "/native/" + feed
			i, ok := byID[id]
			if !ok {
				t.Errorf("no histogram normalization check %s", id)
				continue
			}
			c := res.Normalization[i]
			if len(c.Source) == 0 || len(c.Source) != len(c.Normalized) {
				t.Errorf("%s: %d authored histograms, %d read back", id, len(c.Source), len(c.Normalized))
				continue
			}
			for j := range c.Source {
				a, err := json.Marshal(c.Source[j])
				if err != nil {
					t.Fatal(err)
				}
				b, err := json.Marshal(c.Normalized[j])
				if err != nil {
					t.Fatal(err)
				}
				if string(a) != string(b) {
					t.Errorf("%s record %d: authored %s, stored %s", id, j, a, b)
				}
				if c.Source[j].Kind != "histogram" || c.Source[j].Histogram == nil {
					t.Errorf("%s record %d is not a histogram: %+v", id, j, c.Source[j])
					continue
				}
				switch c.Source[j].Histogram.Kind {
				case "integer":
					integer = true
				case "float":
					float = true
				}
			}
		}
	}
	if !integer || !float {
		t.Errorf("the histogram evidence holds integer=%v float=%v, both are required", integer, float)
	}
}
