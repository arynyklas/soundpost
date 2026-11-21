// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// The pinned engines attach IncompatibleTypesInBinOpInfo to the whole binary
// expression, not to its operator token.
func TestIncompatibleTypesInBinOpInfoSpansTheWholeBinaryExpression(t *testing.T) {
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		p := featureProfile(t, id)
		fl := metricSeries("fl_total", nil, value.Sample{Time: 15_000_000_000, Float: model.FloatBits(math.Float64bits(2))})
		hs := metricSeries("hs_total", nil, value.Sample{Time: 15_000_000_000, Histogram: nativeTestHistogram(2)})
		const query = "fl_total + hs_total"
		_, notes, err := evalWith(t, p, query, instantAt(20_000), fl, hs)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, d := range notes {
			if d.Category != "IncompatibleTypesInBinOpInfo" {
				continue
			}
			found = true
			if d.Range.StartByte != 0 || d.Range.EndByte != len(query) {
				t.Fatalf("%s: annotation range %d..%d, want 0..%d", id, d.Range.StartByte, d.Range.EndByte, len(query))
			}
		}
		if !found {
			t.Fatalf("%s: no IncompatibleTypesInBinOpInfo annotation in %+v", id, notes)
		}
	}
}
