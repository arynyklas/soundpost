// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
)

func payloadNaN(low uint64) float64 { return math.Float64frombits(0x7ff8000000000000 | low) }

func assertNaNBits(t *testing.T, name string, got float64, want uint64) {
	t.Helper()
	if bits := math.Float64bits(got); bits != want {
		t.Errorf("%s = %#x, want %#x", name, bits, want)
	}
}

// The expectations below are the payloads the pinned Prometheus 3.1.0 and 3.13.5 references returned for
// the same inputs (conformance/query/cases/promql-wave6-annotations-nan.json, recorded in
// testdata/native-promql-wave6-annotation-observations.json): they are observations, not predictions.

// TestSumKeepsTheFirstNaNPayloadLikeTheReference: the reference's Kahan sum keeps the first NaN operand's
// payload for sum(), sum_over_time and the shared compensated step, whatever the group size.
func TestSumKeepsTheFirstNaNPayloadLikeTheReference(t *testing.T) {
	n1, n2, n3 := payloadNaN(1), payloadNaN(2), payloadNaN(3)
	assertNaNBits(t, "sum[N1,N2]", functionSum([]float64{n1, n2}), 0x7ff8000000000001)
	assertNaNBits(t, "sum[N1,N2,N3]", functionSum([]float64{n1, n2, n3}), 0x7ff8000000000001)
	assertNaNBits(t, "sum[N3,N2,N1]", functionSum([]float64{n3, n2, n1}), 0x7ff8000000000003)
	assertNaNBits(t, "sum[1,N1,3,N2]", functionSum([]float64{1, n1, 3, n2}), 0x7ff8000000000001)
	assertNaNBits(t, "sum[N2,1,3,N1]", functionSum([]float64{n2, 1, 3, n1}), 0x7ff8000000000002)
	// Inf + -Inf creates the default NaN; a later input NaN does not displace it (first operand wins).
	assertNaNBits(t, "sum[+Inf,-Inf,N1]", functionSum([]float64{math.Inf(1), math.Inf(-1), n1}), value.DefaultNaNBits)
}

// TestMeanNaNPayloadFollowsEachRelease: the aggregation avg keeps the first NaN on both releases; the
// 3.1.0 avg_over_time adds its compensation second and so keeps the last NaN of a pair; 3.13.5's
// avg_over_time keeps the first like its aggregation.
func TestMeanNaNPayloadFollowsEachRelease(t *testing.T) {
	n1, n2, n3 := payloadNaN(1), payloadNaN(2), payloadNaN(3)
	const p310, p3135 = "promql-prometheus-3.1.0", "promql-prometheus-3.13.5"
	assertNaNBits(t, "avg[N1,N2] 3.1.0", functionMean([]float64{n1, n2}, p310, false), 0x7ff8000000000001)
	assertNaNBits(t, "avg[N1,N2,N3] 3.13.5", functionMean([]float64{n1, n2, n3}, p3135, false), 0x7ff8000000000001)
	assertNaNBits(t, "avg_over_time[N1,N2] 3.1.0", functionMean([]float64{n1, n2}, p310, true), 0x7ff8000000000002)
	assertNaNBits(t, "avg_over_time[N1,N2,N3] 3.1.0", functionMean([]float64{n1, n2, n3}, p310, true), 0x7ff8000000000003)
	assertNaNBits(t, "avg_over_time[N2,N1] 3.1.0", functionMean([]float64{n2, n1}, p310, true), 0x7ff8000000000001)
	assertNaNBits(t, "avg_over_time[N1,N2] 3.13.5", functionMean([]float64{n1, n2}, p3135, true), 0x7ff8000000000001)
	assertNaNBits(t, "avg_over_time[N2,N1] 3.13.5", functionMean([]float64{n2, n1}, p3135, true), 0x7ff8000000000002)
}

// TestAggregationVarianceKeepsTheAddedTermNaNPayload: the reference's Welford update `m2 += delta*(x-mean)`
// returns the added term's payload when both sides are NaN, so the last NaN of the group survives.
func TestAggregationVarianceKeepsTheAddedTermNaNPayload(t *testing.T) {
	n1, n2, n3, n4 := payloadNaN(1), payloadNaN(2), payloadNaN(3), payloadNaN(4)
	assertNaNBits(t, "stdvar[N1,N2]", functionVariance([]float64{n1, n2}), 0x7ff8000000000002)
	assertNaNBits(t, "stdvar[N2,N1]", functionVariance([]float64{n2, n1}), 0x7ff8000000000001)
	assertNaNBits(t, "stdvar[N1,N2,N3]", functionVariance([]float64{n1, n2, n3}), 0x7ff8000000000003)
	assertNaNBits(t, "stdvar[N1,N2,N3,N4]", functionVariance([]float64{n1, n2, n3, n4}), 0x7ff8000000000004)
	assertNaNBits(t, "stdvar[1,N1,3,N2]", functionVariance([]float64{1, n1, 3, n2}), 0x7ff8000000000002)
	// A single NaN value seeds the sum of squares with the canonical Go NaN, then divides by the count.
	assertNaNBits(t, "stdvar[N2]", functionVariance([]float64{n2}), 0x7ff8000000000001)
}

// TestQuantileSortsNaNFirstAndKeepsTheUpperTermPayload: NaN is less than everything including another NaN, so
// the NaN payloads are reordered by the reference's sort, and the interpolation keeps the upper term's payload.
func TestQuantileSortsNaNFirstAndKeepsTheUpperTermPayload(t *testing.T) {
	n1, n2, n3 := payloadNaN(1), payloadNaN(2), payloadNaN(3)
	assertNaNBits(t, "quantile(.5,[N1,N2])", functionQuantile(.5, []float64{n1, n2}), 0x7ff8000000000001)
	assertNaNBits(t, "quantile(.5,[N2,N1])", functionQuantile(.5, []float64{n2, n1}), 0x7ff8000000000002)
	assertNaNBits(t, "quantile(.5,[N1,N2,N3])", functionQuantile(.5, []float64{n1, n2, n3}), 0x7ff8000000000001)
	assertNaNBits(t, "quantile(.5,[N3,N2,N1])", functionQuantile(.5, []float64{n3, n2, n1}), 0x7ff8000000000003)
	// Finite values still sort ascending behind the NaNs.
	if got := functionQuantile(.5, []float64{3, 1, 2}); got != 2 {
		t.Errorf("quantile(.5,[3,1,2]) = %v", got)
	}
}

// TestRegressionNaNPayloadFollowsTheReferenceOperandOrder: deriv keeps the first NaN operand of every step.
func TestRegressionNaNPayloadFollowsTheReferenceOperandOrder(t *testing.T) {
	n1, n2 := payloadNaN(1), payloadNaN(2)
	for _, tc := range []struct {
		name string
		ys   []float64
		want uint64
	}{
		{"[N1,N2]", []float64{n1, n2}, 0x7ff8000000000001},
		{"[N2,N1]", []float64{n2, n1}, 0x7ff8000000000002},
	} {
		samples := make([]value.Sample, len(tc.ys))
		for i, y := range tc.ys {
			samples[i] = functionSample(y, model.UnixNano(int64(i+1)*5e9))
		}
		slope, _ := functionRegression(samples, samples[0].Time)
		assertNaNBits(t, "deriv"+tc.name, slope, tc.want)
	}
}
