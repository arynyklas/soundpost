// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"
	"soundpost/internal/model"
	"soundpost/internal/query/value"
	"testing"
)

// deriv regresses against the first sample of the window (native Prometheus),
// not the evaluation time; predict_linear keeps the evaluation time. With
// dyadic offsets from the first sample every sum is exact, so an exactly linear
// series must give slope exactly 0.5 only for the first-sample reference.
func TestDerivRegressesAgainstFirstSampleTimestamp(t *testing.T) {
	const base = int64(1700000000123000000)
	offsets := []float64{0, 1.5, 4.25, 9.75}
	var samples []value.Sample
	for _, o := range offsets {
		samples = append(samples, sample(base+int64(o*1e9), 0.5*o+3))
	}
	src := seriesSource{{Labels: model.Labels{{Name: "__name__", Value: "m"}}, Samples: samples}}
	at := base + 10300000000
	r, e := executeExpr(t, "deriv(m[11s])", value.Evaluation{Instant: true, Time: model.UnixNano(at)}, src)
	if e != nil || len(r.Vector) != 1 {
		t.Fatalf("%+v %v", r, e)
	}
	if got := r.Vector[0].Samples[0].Float; got != model.FloatBits(math.Float64bits(0.5)) {
		t.Fatalf("deriv = %v, want exactly 0.5", math.Float64frombits(uint64(got)))
	}
	r, e = executeExpr(t, "predict_linear(m[11s], 0)", value.Evaluation{Instant: true, Time: model.UnixNano(at)}, src)
	if e != nil || len(r.Vector) != 1 {
		t.Fatalf("%+v %v", r, e)
	}
	if got := math.Float64frombits(uint64(r.Vector[0].Samples[0].Float)); math.Abs(got-(0.5*10.3+3)) > 1e-9 {
		t.Fatalf("predict_linear at evaluation time = %v", got)
	}
}
