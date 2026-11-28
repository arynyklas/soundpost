// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// 02.04#15: with a NaN sum, 3.13.5 HistogramFraction (promql/quantile.go at the
// pinned commit) caps every rank at the visited bucket population and then
// divides by h.Count, whatever the population is relative to the count; the
// 3.1.0 function has no NaN branch and always caps at h.Count. The case with a
// population ABOVE the count cannot be produced by the pinned ingestion, so no
// oracle row exists; the expectation below is derived from the pinned source:
// histogram with Count 2, one bucket (1,2] holding 4, fraction(0, 2):
//
//	3.13.5: lowerRank 0 (set at the bucket's lower bound), upperRank unset -> population 4; (4-0)/2 = 2
//	3.1.0:  upperRank unset -> h.Count 2; (2-0)/2 = 1
func TestHistogramFractionNaNSumCeilingFollowsThePinnedReleases(t *testing.T) {
	nan := model.FloatBits(math.Float64bits(math.NaN()))
	number := func(f float64) model.FloatBits { return model.FloatBits(math.Float64bits(f)) }
	histogram := func(count, bucket float64) model.FloatHistogram {
		return model.FloatHistogram{Flavor: "counter", Schema: 0, Sum: nan, Count: number(count), ResetHint: "unknown",
			PositiveSpans: []model.HistogramSpan{{Offset: 1, Length: 1}}, PositiveBuckets: []model.FloatBits{number(bucket)}}
	}
	for _, c := range []struct {
		name           string
		count, bucket  float64
		p31, p313      float64
		info31, info13 bool
	}{
		{"population above the count", 2, 4, 1, 2, false, false},
		{"population below the count (a NaN observation)", 10, 6, 1, 0.6, true, true},
		{"population equals the count", 4, 4, 1, 1, false, false},
	} {
		h := histogram(c.count, c.bucket)
		got31, reason31 := histogramExponentialFraction(0, 2, h, c.count, relP31)
		got313, reason313 := histogramExponentialFraction(0, 2, h, c.count, relP313)
		if got31 != c.p31 || got313 != c.p313 {
			t.Errorf("%s: 3.1.0 %v (want %v), 3.13.5 %v (want %v)", c.name, got31, c.p31, got313, c.p313)
		}
		if (reason31 != "") != c.info31 || (reason313 != "") != c.info13 {
			t.Errorf("%s: info reasons %q %q", c.name, reason31, reason313)
		}
	}
}
