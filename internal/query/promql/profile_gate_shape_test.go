// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// Version-gated behavior is keyed on one shape: 3.13.5 behavior only for the
// 3.13.5 pin, 3.1.0 behavior for everything else. Before this was normalized
// the mean rule keyed on "== 3.13.5" while the histogram_fraction ceiling keyed
// on "!= 3.1.0", so a profile unknown to both would have got 3.1.0 means and
// 3.13.5 fractions.
func TestProfileGatesShareOneDirectionForUnregisteredProfiles(t *testing.T) {
	const unknown = "promql-prometheus-9.9.9"
	// Recorded in release data: these inputs separate the 3.1.0 and 3.13.5 mean rules.
	xs := []float64{math.MaxFloat64, math.MaxFloat64, -math.MaxFloat64, 1, 2, 3}
	old, current := functionMean(xs, "promql-prometheus-3.1.0", false), functionMean(xs, "promql-prometheus-3.13.5", false)
	if math.Float64bits(functionMean(xs, unknown, false)) != math.Float64bits(old) {
		t.Fatalf("mean for an unregistered profile must follow 3.1.0: %v vs %v (3.13.5 %v)", functionMean(xs, unknown, false), old, current)
	}
	// A histogram whose NaN sum means 1 observation is in no bucket: the 3.13.5
	// ceiling is the bucket population, the 3.1.0 ceiling the observation count.
	f := model.FloatHistogram{Flavor: "float", Schema: 0, ZeroThreshold: model.FloatBits(math.Float64bits(0.001)),
		Sum: model.FloatBits(math.Float64bits(math.NaN())), Count: model.FloatBits(math.Float64bits(4)), ZeroCount: model.FloatBits(math.Float64bits(0)),
		PositiveSpans: []model.HistogramSpan{{Offset: 1, Length: 1}}, PositiveBuckets: []model.FloatBits{model.FloatBits(math.Float64bits(3))}}
	fraction := func(id string) float64 {
		v, _ := histogramExponentialFraction(0.5, math.Inf(1), f, 4, id)
		return v
	}
	if fraction("promql-prometheus-3.1.0") == fraction("promql-prometheus-3.13.5") {
		t.Fatal("fixture no longer separates the two profiles")
	}
	if fraction(unknown) != fraction("promql-prometheus-3.1.0") {
		t.Fatalf("fraction ceiling for an unregistered profile must follow 3.1.0: %v vs %v", fraction(unknown), fraction("promql-prometheus-3.1.0"))
	}
}
