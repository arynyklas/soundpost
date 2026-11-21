// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"math"
	"testing"

	"github.com/arynyklas/soundpost/internal/query/value"
)

// count_values renders every sample value with strconv.FormatFloat(v, 'f', -1, 64) and counts equal label
// texts together (promql/engine.go aggregationCountValues in Prometheus 3.1.0 and 3.13.5): every NaN payload,
// positive or negative, is the text "NaN" and one group. The reference emits the groups in Go map-iteration
// order, so only the (label text, count) set is checked here; the recorded reference rows are
// conformance/query/cases/promql-wave6-annotations-nan.json (agg/count_values*).
func TestCountValuesGroupsEveryNaNPayloadUnderOneLabelText(t *testing.T) {
	nan := func(low uint64) float64 { return math.Float64frombits(0x7ff8000000000000 | low) }
	negNaN := math.Float64frombits(0xfff8000000000001)
	cases := []struct {
		name string
		in   []float64
		want map[string]float64
	}{
		{"payloads merge", []float64{nan(1), nan(2), nan(3), nan(4), negNaN}, map[string]float64{"NaN": 5}},
		{"mixed with finite", []float64{1, nan(1), 3, nan(2)}, map[string]float64{"1": 1, "NaN": 2, "3": 1}},
		{"infinities", []float64{math.Inf(1), math.Inf(-1), nan(1)}, map[string]float64{"+Inf": 1, "-Inf": 1, "NaN": 1}},
		{"signed zero and exponents", []float64{0, math.Copysign(0, -1), nan(1), 1e21, 1e-7}, map[string]float64{"0": 1, "-0": 1, "NaN": 1, "1000000000000000000000": 1, "0.0000001": 1}},
		{"single", []float64{nan(1)}, map[string]float64{"NaN": 1}},
	}
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		f := functionTestFrame(id)
		for _, c := range cases {
			t.Run(id+"/"+c.name, func(t *testing.T) {
				var series []value.Series
				for _, x := range c.in {
					series = append(series, functionTestSeries(x))
				}
				plan := AggregationPlan{Name: "count_values", Parameter: value.Result{Type: "string", String: "v"}}
				got, _, err := EvalAggregation(context.Background(), plan, value.Result{Type: "vector", Vector: series}, f)
				if err != nil {
					t.Fatal(err)
				}
				seen := map[string]float64{}
				for _, s := range got.Vector {
					if len(s.Labels) != 1 || s.Labels[0].Name != "v" {
						t.Fatalf("result labels %+v, want exactly the destination label", s.Labels)
					}
					if _, dup := seen[s.Labels[0].Value]; dup {
						t.Fatalf("label text %q emitted twice", s.Labels[0].Value)
					}
					seen[s.Labels[0].Value] = math.Float64frombits(uint64(s.Samples[0].Float))
				}
				if len(seen) != len(c.want) {
					t.Fatalf("got %v, want %v", seen, c.want)
				}
				for text, count := range c.want {
					if seen[text] != count {
						t.Fatalf("got %v, want %v", seen, c.want)
					}
				}
			})
		}
	}
}
