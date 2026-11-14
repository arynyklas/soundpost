// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// Hand-authored expectations for the numeric/semantic facts of the `numeric` release partition.
// Every expected value is derived here from the rule text of the obligation (arithmetic on the
// stated formula), not from an oracle or from this engine's output.

var nbProfiles = []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"}

func nbLabels(kv ...string) model.Labels {
	var out model.Labels
	for i := 0; i < len(kv); i += 2 {
		out = append(out, model.Label{Name: kv[i], Value: kv[i+1]})
	}
	return out
}

func nbHist(ms int64, count uint64) value.Sample {
	return value.Sample{Time: model.UnixNano(ms * 1_000_000), Histogram: nativeTestHistogram(count)}
}

func nbLanguageCode(err error) string {
	var language *syntax.LanguageError
	if errors.As(err, &language) {
		return language.Code
	}
	return ""
}

func nbFmt(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

// nbVec evaluates q and returns the vector keyed by the non-name label set (k=v,k=v), the float
// result of each series, and the sorted annotation categories.
func nbVec(t *testing.T, id string, enabled []string, q string, ev value.Evaluation, series ...value.Series) (map[string]float64, []string) {
	t.Helper()
	r, notes, err := evalWith(t, featureProfile(t, id, enabled...), q, ev, series...)
	if err != nil {
		t.Fatalf("%s %s: %v", id, q, err)
	}
	if r.Type != "vector" {
		t.Fatalf("%s %s: type %s", id, q, r.Type)
	}
	out := map[string]float64{}
	for _, s := range r.Vector {
		var parts []string
		for _, l := range s.Labels {
			if l.Name != "__name__" {
				parts = append(parts, l.Name+"="+l.Value)
			}
		}
		if s.Samples[0].Histogram != nil {
			t.Fatalf("%s %s: histogram result", id, q)
		}
		out[strings.Join(parts, ",")] = math.Float64frombits(uint64(s.Samples[0].Float))
	}
	var cats []string
	for _, n := range notes {
		cats = append(cats, n.Category)
	}
	sort.Strings(cats)
	return out, cats
}

func nbNear(t *testing.T, what string, got, want, rel float64) {
	t.Helper()
	if math.IsNaN(want) {
		if !math.IsNaN(got) {
			t.Errorf("%s = %v, want NaN", what, got)
		}
		return
	}
	if math.IsInf(want, 0) || want == 0 {
		if got != want {
			t.Errorf("%s = %v, want %v", what, got, want)
		}
		return
	}
	if math.Abs(got-want) > rel*math.Abs(want) {
		t.Errorf("%s = %.17g, want %.17g", what, got, want)
	}
}

func nbWantKeys(t *testing.T, what string, got map[string]float64, keys ...string) {
	t.Helper()
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	for k := range got {
		if !want[k] {
			t.Errorf("%s: unexpected series {%s}", what, k)
		}
	}
	for k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("%s: missing series {%s}", what, k)
		}
	}
}

func nbHasCategory(cats []string, want string) bool {
	for _, c := range cats {
		if c == want {
			return true
		}
	}
	return false
}

func TestReleaseNumericAbsentDerivedLabels(t *testing.T) {
	present := []value.Series{metricSeries("ad_m", nbLabels("job", "a"), msSample(15_000, 1)), metricSeries("ad_h", nbLabels("job", "a"), nbHist(15_000, 3))}
	for _, id := range nbProfiles {
		for _, c := range []struct {
			q    string
			want []string // expected series keys; nil = empty result
		}{
			{`absent(ad_none{job="a",instance="b"})`, []string{"instance=b,job=a"}},
			{`absent(ad_none{job="a",job="b"})`, []string{""}}, // duplicate equality matchers drop the label
			{`absent(ad_none{job=~"a.*",instance="b",env!="x"})`, []string{"instance=b"}},
			{`absent({__name__="ad_none",job="a"})`, []string{"job=a"}}, // the metric name is never a derived label
			{`absent(sum(ad_none))`, []string{""}},                      // non-selector input invents no labels
			{`absent(ad_m{job="zzz"})`, []string{"job=zzz"}},
			{`absent_over_time(ad_none{job="a"}[5m])`, []string{"job=a"}},
			{`absent(ad_m)`, nil},
			{`absent(ad_h)`, nil}, // a histogram-only series is present
			{`absent_over_time(ad_h[1m])`, nil},
			{`absent_over_time(ad_m[1m])`, nil},
		} {
			got, _ := nbVec(t, id, nil, c.q, instantAt(20_000), present...)
			nbWantKeys(t, id+" "+c.q, got, c.want...)
			for _, k := range c.want {
				if got[k] != 1 {
					t.Errorf("%s %s: value %v, want 1", id, c.q, got[k])
				}
			}
		}
	}
}

func TestReleaseNumericAggregationParameters(t *testing.T) {
	var m []value.Series
	for i, c := range []string{"a", "b", "c", "d"} {
		m = append(m, metricSeries("ap_m", nbLabels("case", c), msSample(5_000, float64(4-i))))
	}
	exp := []string{"promql-experimental-functions"}
	for _, id := range nbProfiles {
		for _, c := range []struct {
			q    string
			want []string
		}{
			{"topk(2, ap_m)", []string{"case=a", "case=b"}},
			{"topk(1.9, ap_m)", []string{"case=a"}}, // truncated to 1
			{"topk(0.9, ap_m)", nil},                // k < 1 is empty
			{"topk(0, ap_m)", nil},
			{"topk(-1, ap_m)", nil},
			{"bottomk(100, ap_m)", []string{"case=a", "case=b", "case=c", "case=d"}}, // capped at the input length
			{"bottomk(2, ap_m)", []string{"case=c", "case=d"}},
		} {
			got, _ := nbVec(t, id, nil, c.q, instantAt(20_000), m...)
			nbWantKeys(t, id+" "+c.q, got, c.want...)
		}
		// +Inf is not convertible to int64 on either profile; NaN additionally on 3.1.0.
		q := "topk(Inf, ap_m)"
		if strings.HasSuffix(id, "3.1.0") {
			q = "topk(NaN, ap_m)"
		}
		if _, _, err := evalWith(t, featureProfile(t, id), q, instantAt(20_000), m...); err == nil || nbLanguageCode(err) != "aggregation.parameter-range" {
			t.Errorf("%s %s: err %v, want aggregation.parameter-range", id, q, err)
		}
		// quantile with q outside [0,1] warns and yields the signed infinity; NaN gives NaN.
		for _, c := range []struct {
			q    string
			want float64
		}{{"quantile(2, ap_m)", math.Inf(1)}, {"quantile(-1, ap_m)", math.Inf(-1)}, {"quantile(NaN, ap_m)", math.NaN()}} {
			got, cats := nbVec(t, id, nil, c.q, instantAt(20_000), m...)
			nbNear(t, id+" "+c.q, got[""], c.want, 0)
			if len(cats) != 1 || cats[0] != "InvalidQuantileWarning" {
				t.Errorf("%s %s: annotations %v, want InvalidQuantileWarning", id, c.q, cats)
			}
		}
		// limit_ratio (experimental): a ratio outside [-1,1] clamps with a warning, zero gives empty,
		// and a negative ratio selects the complement of the corresponding positive threshold.
		got, cats := nbVec(t, id, exp, "limit_ratio(2, ap_m)", instantAt(20_000), m...)
		nbWantKeys(t, id+" limit_ratio(2)", got, "case=a", "case=b", "case=c", "case=d")
		if len(cats) != 1 || cats[0] != "InvalidRatioWarning" {
			t.Errorf("%s limit_ratio(2): annotations %v", id, cats)
		}
		got, _ = nbVec(t, id, exp, "limit_ratio(0, ap_m)", instantAt(20_000), m...)
		nbWantKeys(t, id+" limit_ratio(0)", got)
		pos, _ := nbVec(t, id, exp, "limit_ratio(0.5, ap_m)", instantAt(20_000), m...)
		neg, _ := nbVec(t, id, exp, "limit_ratio(-0.5, ap_m)", instantAt(20_000), m...)
		for _, k := range []string{"case=a", "case=b", "case=c", "case=d"} {
			_, p := pos[k]
			_, n := neg[k]
			if p == n {
				t.Errorf("%s: series %s selected by both or neither of limit_ratio(0.5) and limit_ratio(-0.5)", id, k)
			}
		}
	}
}

func nbBuckets(name string, counts map[string]float64) []value.Series {
	var out []value.Series
	for le, c := range counts {
		out = append(out, metricSeries(name+"_bucket", nbLabels("le", le), msSample(15_000, c)))
	}
	sort.Slice(out, func(i, j int) bool { return value.CompareLabels(out[i].Labels, out[j].Labels) < 0 })
	return out
}

func TestReleaseNumericClassicQuantile(t *testing.T) {
	inf := math.Inf(1)
	for _, id := range nbProfiles {
		run := func(q string, series []value.Series) (float64, []string, bool) {
			got, cats := nbVec(t, id, nil, q, instantAt(20_000), series...)
			v, ok := got[""]
			return v, cats, ok
		}
		ok := nbBuckets("cq", map[string]float64{"0.1": 2, "0.5": 6, "1": 10, "+Inf": 10})
		// rank = q*10; q=0.5 -> rank 5 in (0.1,0.5]: 0.1 + 0.4*(5-2)/(6-2) = 0.4; q=0.25 -> rank 2.5: 0.1 + 0.4*0.5/4 = 0.15
		for _, c := range []struct{ q, want float64 }{{0.5, 0.4}, {0.25, 0.15}, {0.9, 0.875}, {1, 1}} {
			v, cats, present := run("histogram_quantile("+nbFmt(c.q)+", cq_bucket)", ok)
			if !present || len(cats) != 0 {
				t.Fatalf("%s q=%v: present=%v annotations=%v", id, c.q, present, cats)
			}
			nbNear(t, id+" q="+nbFmt(c.q), v, c.want, 1e-12)
		}
		for _, c := range []struct {
			q    string
			want float64
		}{{"-1", math.Inf(-1)}, {"2", inf}, {"NaN", math.NaN()}} {
			v, cats, _ := run("histogram_quantile("+c.q+", cq_bucket)", ok)
			nbNear(t, id+" q="+c.q, v, c.want, 0)
			if c.q != "NaN" && !nbHasCategory(cats, "InvalidQuantileWarning") {
				t.Errorf("%s q=%s: annotations %v", id, c.q, cats)
			}
		}
		// the quantile falling in the +Inf bucket returns the previous upper bound
		v, _, _ := run("histogram_quantile(0.9, cq_inf_bucket)", nbBuckets("cq_inf", map[string]float64{"1": 5, "+Inf": 10}))
		nbNear(t, id+" +Inf bucket", v, 1, 0)
		// the first bucket's upper bound is returned when it is not positive
		v, _, _ = run("histogram_quantile(0.1, cq_neg_bucket)", nbBuckets("cq_neg", map[string]float64{"-5": 3, "5": 10, "+Inf": 10}))
		nbNear(t, id+" nonpositive first bucket", v, -5, 0)
		// duplicate boundaries add their counts: le=1 (3) and le="1.0" (2) -> 5 observations: rank 2.5 of 5 in (0,1]
		v, _, _ = run("histogram_quantile(0.5, cq_dup_bucket)", nbBuckets("cq_dup", map[string]float64{"1": 3, "1.0": 2, "+Inf": 5}))
		nbNear(t, id+" duplicate le", v, 0.5, 1e-12)
		// no +Inf bucket, a single bucket, zero total: NaN
		for name, counts := range map[string]map[string]float64{"cq_noinf": {"1": 3, "2": 5}, "cq_one": {"+Inf": 5}, "cq_zero": {"1": 0, "+Inf": 0}} {
			v, _, _ = run("histogram_quantile(0.5, "+name+"_bucket)", nbBuckets(name, counts))
			nbNear(t, id+" "+name, v, math.NaN(), 0)
		}
		// a decrease beyond tolerance is forced up to the previous cumulative value, with an info annotation:
		// cumulative 6,6,8 -> rank 4 falls in the first bucket (0,1]: 1*(4/6)
		v, cats, _ := run("histogram_quantile(0.5, cq_dec_bucket)", nbBuckets("cq_dec", map[string]float64{"1": 6, "2": 4, "+Inf": 8}))
		if len(cats) != 1 || cats[0] != "HistogramQuantileForcedMonotonicityInfo" {
			t.Errorf("%s decrease: annotations %v", id, cats)
		}
		nbNear(t, id+" forced decrease", v, 4.0/6.0, 1e-12)
		// a malformed le is a warning, not a bucket
		_, cats, _ = run("histogram_quantile(0.5, cq_bad_bucket)", nbBuckets("cq_bad", map[string]float64{"abc": 3, "+Inf": 5}))
		if !nbHasCategory(cats, "BadBucketLabelWarning") {
			t.Errorf("%s: malformed le produced %v, want BadBucketLabelWarning", id, cats)
		}
	}
}

func TestReleaseNumericQuantileTolerance(t *testing.T) {
	big := 1e12
	cases := []struct {
		name   string
		counts map[string]float64 // le -> cumulative count (le=1,2,3,+Inf)
		forced bool
	}{
		{"decrease of 1 at 1e12 is 5e-13 relative: tolerated", map[string]float64{"1": big + 1, "2": big, "3": 2 * big, "+Inf": 2 * big}, false},
		{"decrease of 2 at 1e12+1: |a-b|/(|a|+|b|) is exactly 1e-12, STRICT comparison: repaired", map[string]float64{"1": big + 1, "2": big - 1, "3": 2 * big, "+Inf": 2 * big}, true},
		{"decrease of 3: above the epsilon: repaired", map[string]float64{"1": big + 2, "2": big - 1, "3": 2 * big, "+Inf": 2 * big}, true},
		{"zero operand, subnormal difference 1e-320 below 1e-12*2^-1022: tolerated", map[string]float64{"1": 1e-320, "2": 0, "3": 5, "+Inf": 5}, false},
		{"zero operand, difference 3e-320 above 1e-12*2^-1022: repaired", map[string]float64{"1": 3e-320, "2": 0, "3": 5, "+Inf": 5}, true},
		{"equal values are equal", map[string]float64{"1": 4, "2": 4, "3": 8, "+Inf": 8}, false},
	}
	for _, id := range nbProfiles {
		for _, c := range cases {
			_, cats := nbVec(t, id, nil, "histogram_quantile(0.5, qt_bucket)", instantAt(20_000), nbBuckets("qt", c.counts)...)
			forced := nbHasCategory(cats, "HistogramQuantileForcedMonotonicityInfo")
			if forced != c.forced {
				t.Errorf("%s %s: forced-monotonicity info = %v, want %v (annotations %v)", id, c.name, forced, c.forced, cats)
			}
		}
		// tolerated decrease: the cumulative counts are used as given. Rank = 0.5*2e12 = 1e12 falls in the
		// first bucket (count 1e12+1): 0 + 1*(1e12/(1e12+1)).
		got, _ := nbVec(t, id, nil, "histogram_quantile(0.5, qt_bucket)", instantAt(20_000), nbBuckets("qt", cases[0].counts)...)
		nbNear(t, id+" tolerated quantile", got[""], big/(big+1), 1e-15)
	}
}

func TestReleaseNumericFloatSumMean(t *testing.T) {
	ser := func(case_ string, vals ...float64) value.Series {
		var s []value.Sample
		for i, v := range vals {
			s = append(s, msSample(int64(5+5*i)*1000, v))
		}
		return metricSeries("fm", nbLabels("case", case_), s...)
	}
	for _, id := range nbProfiles {
		series := []value.Series{ser("cancel", 1e16, 1, -1e16), ser("single", 3.5), ser("tenths", 0.1, 0.2, 0.3), ser("variance", 2, 4, 9),
			ser("overflow", 1.7e308, 1.7e308, -1.7e308), ser("opposite", math.Inf(1), math.Inf(-1)), ser("samesign", math.Inf(1), math.Inf(1)),
			ser("nan", math.NaN(), 1)}
		sum, _ := nbVec(t, id, nil, "sum_over_time(fm[20s])", instantAt(20_000), series...)
		avg, _ := nbVec(t, id, nil, "avg_over_time(fm[20s])", instantAt(20_000), series...)
		variance, _ := nbVec(t, id, nil, "stdvar_over_time(fm[20s])", instantAt(20_000), series...)
		// compensated: 1e16 + 1 - 1e16 is exactly 1 (a plain running sum gives 0)
		nbNear(t, id+" sum cancel", sum["case=cancel"], 1, 0)
		// the exact sum of the three doubles 0.1+0.2+0.3 rounds to 0.6 (0x3fe3333333333333); left to right gives 0.6000000000000001
		if bits := math.Float64bits(sum["case=tenths"]); bits != 0x3fe3333333333333 {
			t.Errorf("%s sum tenths bits %#x, want 0x3fe3333333333333", id, bits)
		}
		nbNear(t, id+" sum single", sum["case=single"], 3.5, 0)
		nbNear(t, id+" sum +Inf,+Inf", sum["case=samesign"], math.Inf(1), 0)
		nbNear(t, id+" sum +Inf,-Inf", sum["case=opposite"], math.NaN(), 0)
		nbNear(t, id+" sum NaN", sum["case=nan"], math.NaN(), 0)
		// mean: 0.2 (compensated sum / count); overflowing finite sum falls back to the incremental mean 1.7e308/3
		nbNear(t, id+" avg tenths", avg["case=tenths"], 0.2, 1e-15)
		nbNear(t, id+" avg overflow", avg["case=overflow"], 1.7e308/3, 1e-12)
		nbNear(t, id+" avg opposite infinities", avg["case=opposite"], math.NaN(), 0)
		// population variance divides by N: ((2-5)^2+(4-5)^2+(9-5)^2)/3 = 26/3
		nbNear(t, id+" stdvar", variance["case=variance"], 26.0/3.0, 1e-12)
		nbNear(t, id+" stdvar single", variance["case=single"], 0, 0)
		// the window is by samples, not by time: the mean of values at irregular times is unweighted
		uneven := metricSeries("fu", nbLabels("case", "u"), msSample(5_000, 1), msSample(6_000, 2), msSample(14_500, 6))
		u, _ := nbVec(t, id, nil, "avg_over_time(fu[20s])", instantAt(20_000), uneven)
		nbNear(t, id+" avg uneven", u["case=u"], 3, 1e-15)
		// across series, sum() is compensated as well: 1e16 + 0.5 + -1e16 + 0.25 = 0.75
		cross := []value.Series{metricSeries("fa", nbLabels("case", "a"), msSample(15_000, 1e16)), metricSeries("fa", nbLabels("case", "b"), msSample(15_000, 0.5)),
			metricSeries("fa", nbLabels("case", "c"), msSample(15_000, -1e16)), metricSeries("fa", nbLabels("case", "d"), msSample(15_000, 0.25))}
		agg, _ := nbVec(t, id, nil, "sum(fa)", instantAt(20_000), cross...)
		nbNear(t, id+" sum() across series", agg[""], 0.75, 0)
	}
}

func TestReleaseNumericLookbackBoundary(t *testing.T) {
	sec := func(s float64) int64 { return int64(math.Round(s * 1000)) }
	for _, id := range nbProfiles {
		series := []value.Series{
			metricSeries("lb", nbLabels("case", "before"), msSample(sec(99.999), 1)),
			metricSeries("lb", nbLabels("case", "at_bound"), msSample(sec(100), 2)),
			metricSeries("lb", nbLabels("case", "inside"), msSample(sec(100.001), 3)),
			metricSeries("lb", nbLabels("case", "at_target"), msSample(sec(400), 4)),
			metricSeries("lb", nbLabels("case", "after_target"), msSample(sec(400.001), 5)),
			metricSeries("lb", nbLabels("case", "latest"), msSample(sec(50), 6), msSample(sec(300), 7)),
			metricSeries("lb", nbLabels("case", "stale_float"), msSample(sec(100.5), 8), msStale(300_000)),
			metricSeries("lb", nbLabels("case", "resumed"), msSample(sec(100.5), 1), msStale(200_000), msSample(sec(250), 9)),
		}
		// default lookback 5m: the lower boundary 400s-300s = 100s is OPEN, a sample at exactly 100s is excluded
		got, _ := nbVec(t, id, nil, "lb", instantAt(400_000), series...)
		nbWantKeys(t, id+" lb@400s", got, "case=inside", "case=at_target", "case=latest", "case=resumed")
		nbNear(t, id+" inside", got["case=inside"], 3, 0)
		nbNear(t, id+" latest", got["case=latest"], 7, 0)
		nbNear(t, id+" resumed", got["case=resumed"], 9, 0)
	}
}

func TestReleaseNumericMatchingLabels(t *testing.T) {
	a := []value.Series{
		metricSeries("ml_a", nbLabels("extra", "e", "instance", "1", "job", "x"), msSample(15_000, 2)),
		metricSeries("ml_a", nbLabels("extra", "f", "instance", "2", "job", "x"), msSample(15_000, 3)),
		metricSeries("ml_a", nbLabels("extra", "e", "instance", "1", "job", "y"), msSample(15_000, 5)),
	}
	b := []value.Series{
		metricSeries("ml_b", nbLabels("extra", "e2", "instance", "1", "job", "x"), msSample(15_000, 10)),
		metricSeries("ml_b", nbLabels("extra", "f2", "instance", "1", "job", "y"), msSample(15_000, 20)),
	}
	other := []value.Series{
		metricSeries("ml_one", nbLabels("extra", "z", "job", "x"), msSample(15_000, 100)),
		metricSeries("ml_c", nbLabels("job", "x"), msSample(15_000, 7)),
		metricSeries("ml_d", nbLabels("region", "r"), msSample(15_000, 11)),
	}
	all := append(append(append([]value.Series{}, a...), b...), other...)
	for _, id := range nbProfiles {
		for _, c := range []struct {
			q    string
			want map[string]float64
		}{
			{"ml_b + on(job) ml_c", map[string]float64{"job=x": 17}},                                                                          // on keeps only the matching labels
			{"ml_b + ignoring(extra, instance) ml_c", map[string]float64{"job=x": 17}},                                                        // ignoring removes the listed labels
			{"ml_c + on() ml_d", map[string]float64{"": 18}},                                                                                  // empty on(): everything matches, no labels remain
			{"ml_a * on(job) group_left(extra) ml_one", map[string]float64{"extra=z,instance=1,job=x": 200, "extra=z,instance=2,job=x": 300}}, // included label from the one side
			{"ml_a * on(job) group_left(extra) ml_c", map[string]float64{"instance=1,job=x": 14, "instance=2,job=x": 21}},                     // an absent included label deletes it
			{"ml_a * on(job) group_left(nolabel) ml_one", map[string]float64{"extra=e,instance=1,job=x": 200, "extra=f,instance=2,job=x": 300}},
			{"ml_c + on(__name__) ml_c", map[string]float64{"": 14}}, // arithmetic drops the metric name even though on() lists it
		} {
			got, _ := nbVec(t, id, nil, c.q, instantAt(20_000), all...)
			keys := make([]string, 0, len(c.want))
			for k := range c.want {
				keys = append(keys, k)
			}
			nbWantKeys(t, id+" "+c.q, got, keys...)
			for k, v := range c.want {
				nbNear(t, id+" "+c.q+" {"+k+"}", got[k], v, 0)
			}
		}
		// duplicate output label sets after the included label is deleted are an error
		dup := []value.Series{
			metricSeries("ml_dup", nbLabels("extra", "e", "instance", "1", "job", "x"), msSample(15_000, 1)),
			metricSeries("ml_dup", nbLabels("extra", "f", "instance", "1", "job", "x"), msSample(15_000, 2)),
			metricSeries("ml_c", nbLabels("job", "x"), msSample(15_000, 7)),
		}
		if _, _, err := evalWith(t, featureProfile(t, id), "ml_dup * on(job) group_left(extra) ml_c", instantAt(20_000), dup...); err == nil || nbLanguageCode(err) != "binary.matching-cardinality" {
			t.Errorf("%s: duplicate grouped output: err %v, want binary.matching-cardinality", id, err)
		}
	}
}

func nbSamples(startSec, stepSec float64, vals ...float64) []value.Sample {
	var out []value.Sample
	for i, v := range vals {
		out = append(out, msSample(int64(math.Round((startSec+float64(i)*stepSec)*1000)), v))
	}
	return out
}

func TestReleaseNumericQuantileValues(t *testing.T) {
	nan := math.NaN()
	mk := func(name string, vals ...float64) []value.Series {
		var out []value.Series
		for i, v := range vals {
			out = append(out, metricSeries(name, nbLabels("case", string(rune('a'+i))), msSample(15_000, v)))
		}
		return out
	}
	for _, id := range nbProfiles {
		fin := mk("qv_f", 3, 1, 5, 2)
		withNaN := mk("qv_m", 3, 1, nan, 5, 2)
		for _, c := range []struct {
			q      string
			series []value.Series
			want   float64
		}{
			// sorted 1,2,3,5: rank = q*(N-1)
			{"quantile(0, qv_f)", fin, 1}, {"quantile(0.5, qv_f)", fin, 2.5}, {"quantile(1, qv_f)", fin, 5}, {"quantile(0.3, qv_f)", fin, 1.9},
			// NaN sorts before the finite values: NaN,1,2,3,5
			{"quantile(0, qv_m)", withNaN, nan}, {"quantile(0.25, qv_m)", withNaN, 1}, {"quantile(0.5, qv_m)", withNaN, 2}, {"quantile(1, qv_m)", withNaN, 5},
			// N=1 and N=2
			{"quantile(0.5, qv_1)", mk("qv_1", 7), 7}, {"quantile(0.5, qv_2)", mk("qv_2", 1, 3), 2}, {"quantile(0, qv_2)", mk("qv_2", 1, 3), 1}, {"quantile(1, qv_2)", mk("qv_2", 1, 3), 3},
			// out of range -> signed infinity, NaN -> NaN
			{"quantile(2, qv_f)", fin, math.Inf(1)}, {"quantile(-1, qv_f)", fin, math.Inf(-1)}, {"quantile(NaN, qv_f)", fin, nan},
		} {
			got, _ := nbVec(t, id, nil, c.q, instantAt(20_000), c.series...)
			if len(got) != 1 {
				t.Errorf("%s %s: %d series", id, c.q, len(got))
				continue
			}
			nbNear(t, id+" "+c.q, got[""], c.want, 1e-15)
		}
		// no input series: no output (not NaN)
		got, _ := nbVec(t, id, nil, "quantile(0.5, qv_none)", instantAt(20_000), fin...)
		nbWantKeys(t, id+" empty", got)
		over := []value.Series{metricSeries("qv_o", nbLabels("case", "a"), nbSamples(5, 5, 4, 1, 3)...), metricSeries("qv_o", nbLabels("case", "b"), msSample(15_000, 6))}
		oq, _ := nbVec(t, id, nil, "quantile_over_time(0.5, qv_o[20s])", instantAt(20_000), over...)
		nbNear(t, id+" over_time N=3", oq["case=a"], 3, 0) // 1,3,4 -> rank 1 -> 3
		nbNear(t, id+" over_time N=1", oq["case=b"], 6, 0)
		empty, _ := nbVec(t, id, nil, "quantile_over_time(0.5, qv_o[1s])", instantAt(20_000), over...)
		nbWantKeys(t, id+" empty window", empty)
	}
}

func TestReleaseNumericRateExtrapolation(t *testing.T) {
	for _, id := range nbProfiles {
		// window (40s,100s], 60s range. Each case: samples and the hand-computed extrapolated increase.
		cases := []struct {
			name    string
			samples []value.Sample
			incr    float64
		}{
			// 100..140 at 51..91: S=40, n=5, A=10; start gap 11 >= 1.1*A=11 -> A/2=5; end gap 9 kept: 40*(40+5+9)/40
			{"half_hi", nbSamples(51, 10, 100, 110, 120, 130, 140), 54},
			// start gap 10.999 < 11 is kept; end gap 100-90.999=9.001: 40*(40+10.999+9.001)/40 = 60
			{"keep_lo", nbSamples(50.999, 10, 100, 110, 120, 130, 140), 60},
			// right edge: last sample 89, end gap 11 >= 1.1*A where A=(89-41)/5=9.6 (10.56): -> 4.8; start gap 1 kept: 48*(48+1+4.8)/48
			{"rightedge", []value.Sample{msSample(41_000, 100), msSample(51_000, 110), msSample(61_000, 120), msSample(71_000, 130), msSample(81_000, 140), msSample(89_000, 148)}, 48 * (48 + 1 + 4.8) / 48},
			// counter reset 10,20,5,15,25: corrected last-first = 15+20 = 35; S=40, A=10; start gap 5 kept, end gap 15 -> 5; first/diff keeps zero estimate away: 35*(40+5+5)/40
			{"reset", []value.Sample{msSample(45_000, 10), msSample(55_000, 20), msSample(65_000, 5), msSample(75_000, 15), msSample(85_000, 25)}, 35 * 50.0 / 40},
			// two samples 5 -> 25 at 50,60: S=10, A=10; start gap 10 kept, end gap 40 -> 5; extrapolation to zero: first/diff*S = 5/20*10 = 2.5 caps the 10s start gap: 20*(10+2.5+5)/10
			{"zero_cap", []value.Sample{msSample(50_000, 5), msSample(60_000, 25)}, 20 * (10 + 2.5 + 5) / 10},
		}
		for _, c := range cases {
			inc, _ := nbVec(t, id, nil, "increase(rx[60s])", instantAt(100_000), metricSeries("rx", nbLabels("case", c.name), c.samples...))
			rate, _ := nbVec(t, id, nil, "rate(rx[60s])", instantAt(100_000), metricSeries("rx", nbLabels("case", c.name), c.samples...))
			nbNear(t, id+" increase "+c.name, inc["case="+c.name], c.incr, 1e-12)
			nbNear(t, id+" rate "+c.name, rate["case="+c.name], c.incr/60, 1e-12)
		}
		// fewer than two samples: nothing; a mixed float/histogram window: nothing with a warning
		one, _ := nbVec(t, id, nil, "rate(rx[60s])", instantAt(100_000), metricSeries("rx", nbLabels("case", "one"), msSample(70_000, 3)))
		nbWantKeys(t, id+" one sample", one)
		mixedSeries := metricSeries("rx", nbLabels("case", "mixed"), msSample(55_000, 1), nbHist(75_000, 4))
		got, cats := nbVec(t, id, nil, "rate(rx[60s])", instantAt(100_000), mixedSeries)
		nbWantKeys(t, id+" mixed", got)
		if len(cats) == 0 {
			t.Errorf("%s: mixed float/histogram window produced no annotation", id)
		}
		// delta is not counter corrected: gauge 8,6,4 at 45,55,65: S=20, A=10, start gap 5, end gap 35 -> 5: -4*(20+5+5)/20 = -6
		d, _ := nbVec(t, id, nil, "delta(rx[60s])", instantAt(100_000), metricSeries("rx", nbLabels("case", "g"), msSample(45_000, 8), msSample(55_000, 6), msSample(65_000, 4)))
		nbNear(t, id+" delta", d["case=g"], -6, 1e-12)
	}
}

func TestReleaseNumericRegression(t *testing.T) {
	const t0 = 1700000100.0 // seconds, a large epoch
	at := int64(t0 * 1000)
	ser := func(case_ string, step float64, vals ...float64) value.Series {
		var s []value.Sample
		for i, v := range vals {
			s = append(s, msSample(at-int64(math.Round(float64(len(vals)-1-i)*step*1000)), v))
		}
		return metricSeries("rg", nbLabels("case", case_), s...)
	}
	inf := math.Inf(1)
	for _, id := range nbProfiles {
		series := []value.Series{ser("const", 10, 7, 7, 7, 7, 7), ser("linear", 10, 0, 1, 2, 3, 4), ser("two", 10, 2, 5), ser("smallgap", 0.001, 1, 2, 3, 4),
			ser("pinf", 10, inf, inf, inf, inf), ser("opposite", 10, inf, math.Inf(-1)), ser("nan", 10, 1, math.NaN(), 3), ser("one", 10, 3)}
		d, _ := nbVec(t, id, nil, "deriv(rg[60s])", instantAt(at), series...)
		p, _ := nbVec(t, id, nil, "predict_linear(rg[60s], 30)", instantAt(at), series...)
		p0, _ := nbVec(t, id, nil, "predict_linear(rg[60s], 0)", instantAt(at), series...)
		nbNear(t, id+" deriv const", d["case=const"], 0, 0)       // constant finite input: slope 0
		nbNear(t, id+" predict const", p["case=const"], 7, 1e-15) // and the original intercept
		nbNear(t, id+" deriv linear", d["case=linear"], 0.1, 1e-12)
		nbNear(t, id+" predict linear +30s", p["case=linear"], 7, 1e-12) // value at t0 is 4, slope 0.1/s
		nbNear(t, id+" predict linear +0s", p0["case=linear"], 4, 1e-12)
		nbNear(t, id+" deriv two", d["case=two"], 0.3, 1e-12)
		nbNear(t, id+" predict two +0", p0["case=two"], 5, 1e-12)
		nbNear(t, id+" deriv smallgap", d["case=smallgap"], 1000, 1e-9) // 1 unit per millisecond at a 1.7e9 s epoch
		nbNear(t, id+" deriv +Inf constant", d["case=pinf"], math.NaN(), 0)
		nbNear(t, id+" predict +Inf constant", p["case=pinf"], math.NaN(), 0)
		nbNear(t, id+" deriv opposite infinities", d["case=opposite"], math.NaN(), 0)
		nbNear(t, id+" deriv NaN", d["case=nan"], math.NaN(), 0)
		if _, present := d["case=one"]; present {
			t.Errorf("%s: deriv of a single float produced a result", id)
		}
	}
}

func TestReleaseNumericRoundClamp(t *testing.T) {
	inf, nan := math.Inf(1), math.NaN()
	mk := func(vals ...float64) []value.Series {
		var out []value.Series
		for i, v := range vals {
			out = append(out, metricSeries("rc", nbLabels("case", "v"+strconv.Itoa(10+i)), msSample(15_000, v)))
		}
		return append(out, metricSeries("rc", nbLabels("case", "z_hist"), nbHist(15_000, 3)))
	}
	vals := []float64{-2.5, -1.5, -0.5, 0.25, 0.5, 1.5, 2.5, 7}
	for _, id := range nbProfiles {
		series := mk(vals...)
		check := func(q string, want ...float64) {
			t.Helper()
			got, _ := nbVec(t, id, nil, q, instantAt(20_000), series...)
			if len(got) != len(want) {
				t.Errorf("%s %s: %d series (histogram must be ignored), want %d", id, q, len(got), len(want))
				return
			}
			for i, w := range want {
				nbNear(t, id+" "+q+" v"+strconv.Itoa(10+i), got["case=v"+strconv.Itoa(10+i)], w, 1e-15)
			}
		}
		// round = floor(v*(1/nearest)+0.5)/(1/nearest): halves round toward +Inf
		check("round(rc)", -2, -1, 0, 0, 1, 2, 3, 7)
		check("round(rc, 0.5)", -2.5, -1.5, -0.5, 0.5, 0.5, 1.5, 2.5, 7)
		check("round(rc, 2)", -2, -2, 0, 0, 0, 2, 2, 8)
		// nearest -2: 1/-2 = -0.5: floor(v*-0.5+0.5)/-0.5
		check("round(rc, -2)", -2, -2, 0, 0, 0, 2, 2, 6)
		// nearest 0, +/-Inf, NaN follow the same expression: 1/0 = +Inf makes floor(v*Inf+0.5)/Inf = NaN; 1/Inf = 0 gives floor(0.5)/0 = NaN
		for _, q := range []string{"round(rc, 0)", "round(rc, -0)", "round(rc, Inf)", "round(rc, NaN)"} {
			check(q, nan, nan, nan, nan, nan, nan, nan, nan)
		}
		check("clamp(rc, -1, 1)", -1, -1, -0.5, 0.25, 0.5, 1, 1, 1)
		check("clamp(rc, 1, 1)", 1, 1, 1, 1, 1, 1, 1, 1)
		check("clamp_min(rc, 0)", 0, 0, 0, 0.25, 0.5, 1.5, 2.5, 7)
		check("clamp_max(rc, 0)", -2.5, -1.5, -0.5, 0, 0, 0, 0, 0)
		check("clamp(rc, 5, 1)") // min > max: empty
		check("clamp(rc, NaN, 1)", nan, nan, nan, nan, nan, nan, nan, nan)
		check("clamp(rc, 0, NaN)", nan, nan, nan, nan, nan, nan, nan, nan)
		_ = inf
	}
}

func TestReleaseNumericScalarSampleKind(t *testing.T) {
	fl := metricSeries("sk_f", nbLabels("case", "a"), msSample(15_000, 3))
	hs := metricSeries("sk_h", nbLabels("case", "a"), nbHist(15_000, 3))
	fh := []value.Series{metricSeries("sk_fh", nbLabels("case", "a"), msSample(15_000, 5)), metricSeries("sk_fh", nbLabels("case", "b"), nbHist(15_000, 3))}
	ff := []value.Series{metricSeries("sk_ff", nbLabels("case", "a"), msSample(15_000, 1)), metricSeries("sk_ff", nbLabels("case", "b"), msSample(15_000, 2))}
	hh := []value.Series{metricSeries("sk_hh", nbLabels("case", "a"), nbHist(15_000, 3)), metricSeries("sk_hh", nbLabels("case", "b"), nbHist(15_000, 6))}
	all := append(append(append([]value.Series{fl, hs}, fh...), ff...), hh...)
	nan := math.NaN()
	for id, want := range map[string]map[string]float64{
		// 3.1.0: exactly one vector element, then its F field (a histogram has F=0)
		"promql-prometheus-3.1.0": {"sk_f": 3, "sk_h": 0, "sk_fh": nan, "sk_ff": nan, "sk_hh": nan, "sk_none": nan},
		// 3.13.5: histogram elements are ignored; exactly one float element is returned
		"promql-prometheus-3.13.5": {"sk_f": 3, "sk_h": nan, "sk_fh": 5, "sk_ff": nan, "sk_hh": nan, "sk_none": nan},
	} {
		for name, w := range want {
			got, _ := nbVec(t, id, nil, "vector(scalar("+name+"))", instantAt(20_000), all...)
			nbNear(t, id+" scalar("+name+")", got[""], w, 0)
		}
	}
}

func TestReleaseNumericSmoothing(t *testing.T) {
	exp := []string{"promql-experimental-functions"}
	nan := math.NaN()
	series := metricSeries("sm", nbLabels("case", "a"), nbSamples(5, 5, 1, 3, 2, 5, 4)...)
	for _, id := range nbProfiles {
		// sf = tf = 0.5 over 1,3,2,5,4: level 1, trend 2; then (3,2),(3.5,1.25),(4.875,1.3125); the last level is
		// 0.5*4 + 0.5*(4.875+1.3125) = 5.09375 (all binary-exact)
		got, _ := nbVec(t, id, exp, "double_exponential_smoothing(sm[40s], 0.5, 0.5)", instantAt(30_000), series)
		nbNear(t, id+" smoothing", got["case=a"], 5.09375, 0)
		// two floats: the level is the second value after one update: s1=1, trend=3; 0.5*4 + 0.5*(1+3) = 4
		two := metricSeries("sm", nbLabels("case", "b"), nbSamples(10, 10, 1, 4)...)
		g2, _ := nbVec(t, id, exp, "double_exponential_smoothing(sm[40s], 0.5, 0.5)", instantAt(30_000), two)
		nbNear(t, id+" smoothing two floats", g2["case=b"], 4, 0)
		// a single float has no trend: no result
		one, _ := nbVec(t, id, exp, "double_exponential_smoothing(sm[40s], 0.5, 0.5)", instantAt(30_000), metricSeries("sm", nbLabels("case", "c"), msSample(15_000, 3)))
		nbWantKeys(t, id+" one float", one)
		// NaN factors pass the range checks and propagate
		for _, q := range []string{"double_exponential_smoothing(sm[40s], NaN, 0.5)", "double_exponential_smoothing(sm[40s], 0.5, NaN)"} {
			g, _ := nbVec(t, id, exp, q, instantAt(30_000), series)
			nbNear(t, id+" "+q, g["case=a"], nan, 0)
		}
		// factors outside (0,1) are an evaluation error
		for _, q := range []string{"double_exponential_smoothing(sm[40s], 0, 0.5)", "double_exponential_smoothing(sm[40s], 1, 0.5)", "double_exponential_smoothing(sm[40s], 0.5, 0)", "double_exponential_smoothing(sm[40s], 0.5, 1)"} {
			if _, _, err := evalWith(t, featureProfile(t, id, exp...), q, instantAt(30_000), series); err == nil {
				t.Errorf("%s %s: no error", id, q)
			}
		}
	}
}

func TestReleaseNumericUTCCalendar(t *testing.T) {
	type cal struct{ dom, dow, doy, dim, hour, minute, month, year float64 }
	for _, id := range nbProfiles {
		for _, c := range []struct {
			name string
			at   float64
			want cal
		}{
			{"epoch", 0, cal{1, 4, 1, 31, 0, 0, 1, 1970}},
			{"minus0.9s truncates toward zero", -0.9, cal{1, 4, 1, 31, 0, 0, 1, 1970}},
			{"leap Feb 2000", 951782400, cal{29, 2, 60, 29, 0, 0, 2, 2000}},
			{"last second of Feb 2100 (not leap)", 4107542399, cal{28, 0, 59, 28, 23, 59, 2, 2100}},
			{"1 Mar 2100", 4107542400, cal{1, 1, 60, 31, 0, 0, 3, 2100}},
			{"year end", 1704067199, cal{31, 0, 365, 31, 23, 59, 12, 2023}},
			{"year start", 1704067200, cal{1, 1, 1, 31, 0, 0, 1, 2024}},
			{"fraction truncated", 1704067199.9, cal{31, 0, 365, 31, 23, 59, 12, 2023}},
		} {
			s := []value.Series{metricSeries("cal", nbLabels("case", "x"), msSample(15_000, c.at))}
			for fn, want := range map[string]float64{"day_of_month": c.want.dom, "day_of_week": c.want.dow, "day_of_year": c.want.doy, "days_in_month": c.want.dim,
				"hour": c.want.hour, "minute": c.want.minute, "month": c.want.month, "year": c.want.year} {
				got, _ := nbVec(t, id, nil, fn+"(cal)", instantAt(20_000), s...)
				nbNear(t, id+" "+fn+" "+c.name, got["case=x"], want, 0)
			}
		}
		// omitted argument: the evaluation time, 2000-02-29 01:01:01 UTC
		at := int64(951786061) * 1000
		for fn, want := range map[string]float64{"day_of_month": 29, "day_of_week": 2, "day_of_year": 60, "days_in_month": 29, "hour": 1, "minute": 1, "month": 2, "year": 2000} {
			got, _ := nbVec(t, id, nil, fn+"()", instantAt(at))
			nbNear(t, id+" "+fn+"()", got[""], want, 0)
		}
		// histograms are ignored; an empty vector gives an empty result
		got, _ := nbVec(t, id, nil, "hour(calh)", instantAt(20_000), metricSeries("calh", nbLabels("case", "h"), nbHist(15_000, 3)))
		nbWantKeys(t, id+" hour(histogram)", got)
	}
}

func TestReleaseNumericInstantLatestTwo(t *testing.T) {
	const id = "promql-prometheus-3.13.5"
	at := instantAt(90_000)
	one := func(name string, samples ...value.Sample) value.Series {
		return metricSeries(name, nbLabels("case", "x"), samples...)
	}
	ir := func(q string, s value.Series) (map[string]float64, []string) { return nbVec(t, id, nil, q, at, s) }
	// latest two floats globally: (60s,4) and (80s,9): irate 5/20, idelta 5; the older sample is ignored
	g, _ := ir("irate(il[40s])", one("il", msSample(50_000, 1), msSample(60_000, 4), msSample(80_000, 9)))
	nbNear(t, "irate floats", g["case=x"], 0.25, 1e-15)
	g, _ = ir("idelta(il[40s])", one("il", msSample(50_000, 1), msSample(60_000, 4), msSample(80_000, 9)))
	nbNear(t, "idelta floats", g["case=x"], 5, 0)
	// counter reset 10 -> 3: irate uses the last value as the increase: 3/20
	g, _ = ir("irate(il[40s])", one("il", msSample(60_000, 10), msSample(80_000, 3)))
	nbNear(t, "irate reset", g["case=x"], 0.15, 1e-15)
	g, _ = ir("idelta(il[40s])", one("il", msSample(60_000, 10), msSample(80_000, 3)))
	nbNear(t, "idelta reset", g["case=x"], -7, 0)
	// an older histogram does not matter when the latest two samples are floats
	g, _ = ir("idelta(il[60s])", one("il", nbHist(40_000, 2), msSample(60_000, 1), msSample(80_000, 3)))
	nbNear(t, "idelta old histogram", g["case=x"], 2, 0)
	// two histograms: the difference; histogram_count of idelta = 10-4, of irate = 6/20
	hh := one("ilh", nbHist(60_000, 4), nbHist(80_000, 10))
	g, _ = ir("histogram_count(idelta(ilh[40s]))", hh)
	nbNear(t, "idelta histograms count", g["case=x"], 6, 0)
	g, _ = ir("histogram_count(irate(ilh[40s]))", hh)
	nbNear(t, "irate histograms count", g["case=x"], 0.3, 1e-15)
	// histogram counter reset (10 -> 4): irate uses the last histogram as the increase: 4/20
	g, _ = ir("histogram_count(irate(ilh[40s]))", one("ilh", nbHist(60_000, 10), nbHist(80_000, 4)))
	nbNear(t, "irate histogram reset", g["case=x"], 0.2, 1e-15)
	// mixed last pair, a single sample: nothing; the mixed pair warns
	for _, c := range []struct {
		q string
		s value.Series
	}{
		{"irate(il[40s])", one("il", msSample(60_000, 1), nbHist(80_000, 4))},
		{"idelta(il[40s])", one("il", nbHist(60_000, 4), msSample(80_000, 2))},
		{"irate(il[40s])", one("il", msSample(80_000, 5))},
		{"idelta(il[40s])", one("il", msSample(10_000, 5), msSample(20_000, 7))},
	} {
		got, cats := ir(c.q, c.s)
		nbWantKeys(t, c.q, got)
		if len(c.s.Samples) == 2 && c.s.Samples[0].Histogram != nil != (c.s.Samples[1].Histogram != nil) && !nbHasCategory(cats, "MixedFloatsHistogramsWarning") {
			t.Errorf("%s mixed pair: annotations %v, want MixedFloatsHistogramsWarning", c.q, cats)
		}
	}
}

func nbHistogramOf(t *testing.T, s value.Series) model.FloatHistogram {
	t.Helper()
	if len(s.Samples) != 1 || s.Samples[0].Histogram == nil {
		t.Fatalf("series %v is not one histogram sample", s.Labels)
	}
	return value.FloatHistogram(*s.Samples[0].Histogram)
}

func nbHistFloat(bits model.FloatBits) float64 { return math.Float64frombits(uint64(bits)) }

func TestReleaseNumericArithmeticSemantics(t *testing.T) {
	pairs := []struct {
		name string
		x, y float64
	}{{"a", 5, 2}, {"b", -5, 2}, {"c", 5, -2}, {"d", 0, math.Copysign(0, -1)}, {"e", math.Copysign(0, -1), 0}, {"f", math.Inf(1), math.Inf(-1)}, {"i", 1, 0}, {"j", 2, 0.5}}
	var series []value.Series
	for _, p := range pairs {
		series = append(series, metricSeries("sx", nbLabels("case", p.name), msSample(15_000, p.x)), metricSeries("sy", nbLabels("case", p.name), msSample(15_000, p.y)))
	}
	ops := map[string]func(x, y float64) float64{
		"+": func(x, y float64) float64 { return x + y }, "-": func(x, y float64) float64 { return x - y }, "*": func(x, y float64) float64 { return x * y },
		"/": func(x, y float64) float64 { return x / y }, "%": math.Mod, "^": math.Pow, "atan2": math.Atan2,
	}
	for _, id := range nbProfiles {
		for op, f := range ops {
			r, _, err := evalWith(t, featureProfile(t, id), "sx "+op+" sy", instantAt(20_000), series...)
			if err != nil || len(r.Vector) != len(pairs) {
				t.Fatalf("%s sx %s sy: %v, %d series", id, op, err, len(r.Vector))
			}
			for _, s := range r.Vector {
				name := nbLabel(s.Labels, "case")
				for _, p := range pairs {
					if p.name != name {
						continue
					}
					want := f(p.x, p.y)
					got := math.Float64frombits(uint64(s.Samples[0].Float))
					if math.IsNaN(want) {
						if !math.IsNaN(got) {
							t.Errorf("%s %v %s %v = %v, want NaN", id, p.x, op, p.y, got)
						}
					} else if math.Float64bits(got) != math.Float64bits(want) {
						t.Errorf("%s %v %s %v = %v (%#x), want %v (%#x)", id, p.x, op, p.y, got, math.Float64bits(got), want, math.Float64bits(want))
					}
				}
			}
		}
		// histograms: counts add/subtract exactly; scaling and division apply to count, sum and buckets
		hs := []value.Series{metricSeries("hx", nbLabels("case", "a"), nbHist(15_000, 4)), metricSeries("hy", nbLabels("case", "a"), nbHist(15_000, 6)), metricSeries("sx", nbLabels("case", "a"), msSample(15_000, 3))}
		for _, c := range []struct {
			q          string
			count, sum float64
		}{{"hx + hy", 10, 10}, {"hy - hx", 2, 2}, {"hx * 2", 8, 8}, {"2 * hx", 8, 8}, {"hx / 2", 2, 2}, {"hx * -1", -4, -4}} {
			r, _, err := evalWith(t, featureProfile(t, id), c.q, instantAt(20_000), hs...)
			if err != nil || len(r.Vector) != 1 {
				t.Fatalf("%s %s: %v %v", id, c.q, err, r.Vector)
			}
			f := nbHistogramOf(t, r.Vector[0])
			if nbHistFloat(f.Count) != c.count || nbHistFloat(f.Sum) != c.sum {
				t.Errorf("%s %s: count %v sum %v, want %v %v", id, c.q, nbHistFloat(f.Count), nbHistFloat(f.Sum), c.count, c.sum)
			}
		}
		// invalid kind/operator pairs are removed with an info annotation
		for _, q := range []string{"hx + sx", "hx ^ 2", "2 / hx", "hx * hy", "hx % 2", "hx atan2 hy", "1 + hx"} {
			r, notes, err := evalWith(t, featureProfile(t, id), q, instantAt(20_000), hs...)
			if err != nil || len(r.Vector) != 0 || len(notes) == 0 || notes[0].Category != "IncompatibleTypesInBinOpInfo" {
				t.Errorf("%s %s: err %v, %d series, notes %v; want removal with IncompatibleTypesInBinOpInfo", id, q, err, len(r.Vector), notes)
			}
		}
	}
}

func TestReleaseNumericComparisonSemantics(t *testing.T) {
	nan := math.NaN()
	pairs := []struct {
		name string
		x, y float64
	}{{"a", 5, 2}, {"b", 2, 5}, {"c", 4, 4}, {"d", nan, nan}, {"e", math.Inf(1), math.Inf(1)}}
	var series []value.Series
	for _, p := range pairs {
		series = append(series, metricSeries("sx", nbLabels("case", p.name), msSample(15_000, p.x)), metricSeries("sy", nbLabels("case", p.name), msSample(15_000, p.y)))
	}
	for _, id := range nbProfiles {
		// filter comparisons keep the left value; NaN is never equal, greater or smaller
		for _, c := range []struct {
			q    string
			want map[string]float64
		}{
			{"sx > sy", map[string]float64{"case=a": 5}},
			{"sx < sy", map[string]float64{"case=b": 2}},
			{"sx >= sy", map[string]float64{"case=a": 5, "case=c": 4, "case=e": math.Inf(1)}},
			{"sx == sy", map[string]float64{"case=c": 4, "case=e": math.Inf(1)}},
			{"sx != sy", map[string]float64{"case=a": 5, "case=b": 2, "case=d": nan}},
			{"sx > bool sy", map[string]float64{"case=a": 1, "case=b": 0, "case=c": 0, "case=d": 0, "case=e": 0}},
			{"sx == bool sy", map[string]float64{"case=a": 0, "case=b": 0, "case=c": 1, "case=d": 0, "case=e": 1}},
			{"sx != bool sy", map[string]float64{"case=a": 1, "case=b": 1, "case=c": 0, "case=d": 1, "case=e": 0}},
		} {
			got, _ := nbVec(t, id, nil, c.q, instantAt(20_000), series...)
			keys := make([]string, 0, len(c.want))
			for k := range c.want {
				keys = append(keys, k)
			}
			nbWantKeys(t, id+" "+c.q, got, keys...)
			for k, v := range c.want {
				nbNear(t, id+" "+c.q+" {"+k+"}", got[k], v, 0)
			}
		}
		// the filter form keeps the metric name, the bool form drops it
		r, _, _ := evalWith(t, featureProfile(t, id), "sx > sy", instantAt(20_000), series...)
		if nbLabel(r.Vector[0].Labels, "__name__") != "sx" {
			t.Errorf("%s: filter comparison dropped the metric name", id)
		}
		r, _, _ = evalWith(t, featureProfile(t, id), "sx > bool sy", instantAt(20_000), series...)
		if nbLabel(r.Vector[0].Labels, "__name__") != "" {
			t.Errorf("%s: bool comparison kept the metric name", id)
		}
		// scalar/scalar needs bool
		if _, _, err := evalWith(t, featureProfile(t, id), "1 == 1", instantAt(20_000)); err == nil {
			t.Errorf("%s: scalar comparison without bool accepted", id)
		}
		got, _ := nbVec(t, id, nil, "vector(2 > bool 3)", instantAt(20_000))
		nbNear(t, id+" 2 > bool 3", got[""], 0, 0)
		// histograms: only == and != between two histograms; everything else is removed with info
		hs := []value.Series{metricSeries("hx", nbLabels("case", "a"), nbHist(15_000, 4)), metricSeries("hy", nbLabels("case", "a"), nbHist(15_000, 6)),
			metricSeries("hz", nbLabels("case", "a"), nbHist(15_000, 4)), metricSeries("sx", nbLabels("case", "a"), msSample(15_000, 3))}
		count := func(q string) (int, []string) {
			r, notes, err := evalWith(t, featureProfile(t, id), q, instantAt(20_000), hs...)
			if err != nil {
				t.Fatalf("%s %s: %v", id, q, err)
			}
			var cats []string
			for _, n := range notes {
				cats = append(cats, n.Category)
			}
			return len(r.Vector), cats
		}
		for q, want := range map[string]int{"hx == hz": 1, "hx != hy": 1, "hx == hy": 0, "hx != hz": 0} {
			if n, cats := count(q); n != want || len(cats) != 0 {
				t.Errorf("%s %s: %d series, notes %v, want %d series and no note", id, q, n, cats, want)
			}
		}
		for _, q := range []string{"hx > hy", "hx < sx", "hx <= 3", "hx >= hy", "hx == sx", "hx != 3"} {
			if n, cats := count(q); n != 0 || !nbHasCategory(cats, "IncompatibleTypesInBinOpInfo") {
				t.Errorf("%s %s: %d series, notes %v, want removal with IncompatibleTypesInBinOpInfo", id, q, n, cats)
			}
		}
	}
}

func TestReleaseNumericIEEESemantics(t *testing.T) {
	nz, inf := math.Copysign(0, -1), math.Inf(1)
	payload := math.Float64frombits(0x7ff8000000000123)
	vals := []float64{0, nz, inf, math.Inf(-1), payload, 1}
	var series []value.Series
	for i, v := range vals {
		series = append(series, metricSeries("ie", nbLabels("case", "v"+strconv.Itoa(i)), msSample(15_000, v)))
	}
	bitsOf := func(t *testing.T, id, q string, ser []value.Series) map[string]uint64 {
		r, _, err := evalWith(t, featureProfile(t, id), q, instantAt(20_000), ser...)
		if err != nil {
			t.Fatalf("%s %s: %v", id, q, err)
		}
		out := map[string]uint64{}
		for _, s := range r.Vector {
			out[nbLabel(s.Labels, "case")] = uint64(s.Samples[0].Float)
		}
		return out
	}
	for _, id := range nbProfiles {
		neg := bitsOf(t, id, "-ie", series)
		for i, want := range []uint64{0x8000000000000000, 0, 0xfff0000000000000, 0x7ff0000000000000, 0xfff8000000000123, 0xbff0000000000000} {
			if got := neg["v"+strconv.Itoa(i)]; got != want {
				t.Errorf("%s -ie v%d = %#x, want %#x (signed zero, infinities and NaN keep IEEE negation)", id, i, got, want)
			}
		}
		// +0 + -0 = +0, -0 + -0 = -0 (IEEE round-to-nearest); x*0: signed result; inf*0 = NaN; 1/0 = +Inf
		mul0 := bitsOf(t, id, "ie * 0", series)
		if mul0["v0"] != 0 || mul0["v1"] != 0x8000000000000000 || !math.IsNaN(math.Float64frombits(mul0["v2"])) || mul0["v5"] != 0 {
			t.Errorf("%s ie*0 = %#x", id, mul0)
		}
		div0 := bitsOf(t, id, "1 / ie", series)
		if div0["v0"] != 0x7ff0000000000000 || div0["v1"] != 0xfff0000000000000 || div0["v2"] != 0 || div0["v3"] != 0x8000000000000000 {
			t.Errorf("%s 1/ie = %#x", id, div0)
		}
		sub := bitsOf(t, id, "ie - ie", series)
		if sub["v0"] != 0 || sub["v1"] != 0 || !math.IsNaN(math.Float64frombits(sub["v2"])) {
			t.Errorf("%s ie-ie = %#x", id, sub)
		}
		// an input NaN keeps its payload through arithmetic
		if got := bitsOf(t, id, "ie + 1", series)["v4"]; got != 0x7ff8000000000123 {
			t.Errorf("%s NaN payload through +1 = %#x, want 0x7ff8000000000123", id, got)
		}
		// NaN is unordered: == excludes it, != keeps it
		eq := bitsOf(t, id, "ie == ie", series)
		ne := bitsOf(t, id, "ie != ie", series)
		if _, ok := eq["v4"]; ok || len(eq) != 5 {
			t.Errorf("%s ie == ie kept NaN: %v", id, eq)
		}
		if len(ne) != 1 || ne["v4"] != 0x7ff8000000000123 {
			t.Errorf("%s ie != ie = %v, want only the NaN", id, ne)
		}
		// the stale marker is missingness, not NaN: a series whose newest sample is the marker is absent
		stale := []value.Series{
			metricSeries("ie_s", nbLabels("case", "a_ok"), msSample(15_000, 1)),
			metricSeries("ie_s", nbLabels("case", "b_stale"), msSample(10_000, 1), value.Sample{Time: model.UnixNano(15_000_000_000), Float: value.StaleBits}),
			metricSeries("ie_s", nbLabels("case", "c_nan"), msSample(15_000, math.NaN())),
		}
		got, _ := nbVec(t, id, nil, "ie_s", instantAt(20_000), stale...)
		nbWantKeys(t, id+" ie_s", got, "case=a_ok", "case=c_nan")
		cnt, _ := nbVec(t, id, nil, "count(ie_s)", instantAt(20_000), stale...)
		nbNear(t, id+" count", cnt[""], 2, 0)
		only := []value.Series{metricSeries("ie_t", nbLabels("case", "x"), value.Sample{Time: model.UnixNano(15_000_000_000), Float: value.StaleBits})}
		ab, _ := nbVec(t, id, nil, "absent(ie_t)", instantAt(20_000), only...)
		nbNear(t, id+" absent(stale-only)", ab[""], 1, 0)
		// histogram buckets and counts keep their exact representation through selection
		h := metricSeries("hx", nbLabels("case", "a"), nbHist(15_000, 4))
		r, _, err := evalWith(t, featureProfile(t, id), "hx", instantAt(20_000), h)
		if err != nil || len(r.Vector) != 1 || !reflectDeepEqualHistogram(r.Vector[0].Samples[0].Histogram, h.Samples[0].Histogram) {
			t.Errorf("%s: selected histogram differs from the stored one (%v)\n got  %+v\n want %+v", id, err, value.FloatHistogram(*r.Vector[0].Samples[0].Histogram), value.FloatHistogram(*h.Samples[0].Histogram))
		}
	}
}

func reflectDeepEqualHistogram(a, b *model.NativeHistogram) bool {
	if a == nil || b == nil {
		return a == b
	}
	// the engine returns float histograms: compare the exact float form of both
	return fmt.Sprintf("%+v", value.FloatHistogram(*a)) == fmt.Sprintf("%+v", value.FloatHistogram(*b))
}

func TestReleaseNumericOrderingSemantics(t *testing.T) {
	order := func(t *testing.T, id, q string, series []value.Series) []float64 {
		r, _, err := evalWith(t, featureProfile(t, id), q, instantAt(20_000), series...)
		if err != nil {
			t.Fatalf("%s %s: %v", id, q, err)
		}
		var out []float64
		for _, s := range r.Vector {
			out = append(out, math.Float64frombits(uint64(s.Samples[0].Float)))
		}
		return out
	}
	m := []value.Series{}
	for i, v := range []float64{3, 9, 1, 7, 5, 2} {
		m = append(m, metricSeries("ord_m", nbLabels("case", string(rune('a'+i))), msSample(15_000, v)))
	}
	n := []value.Series{}
	for i, v := range []float64{3, math.NaN(), 1, 7, -2} {
		n = append(n, metricSeries("ord_n", nbLabels("case", string(rune('a'+i))), msSample(15_000, v)))
	}
	same := func(got, want []float64) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if math.Float64bits(got[i]) != math.Float64bits(want[i]) && !(math.IsNaN(got[i]) && math.IsNaN(want[i])) {
				return false
			}
		}
		return true
	}
	for _, id := range nbProfiles {
		for q, want := range map[string][]float64{
			"sort(ord_m)":       {1, 2, 3, 5, 7, 9},
			"sort_desc(ord_m)":  {9, 7, 5, 3, 2, 1},
			"topk(4, ord_m)":    {9, 7, 5, 3}, // value order for instant queries
			"bottomk(2, ord_m)": {1, 2},
			"sort(ord_n)":       {math.NaN(), -2, 1, 3, 7}, // sort_desc is the exact reverse of sort: NaN first when ascending
			"sort_desc(ord_n)":  {7, 3, 1, -2, math.NaN()}, // and last when descending
		} {
			series := m
			if strings.Contains(q, "ord_n") {
				series = n
			}
			if got := order(t, id, q, series); !same(got, want) {
				t.Errorf("%s %s = %v, want %v", id, q, got, want)
			}
		}
	}
}

func TestReleaseNumericRangeWindowSemantics(t *testing.T) {
	at := func(sec float64) int64 { return int64(math.Round(sec * 1000)) }
	for _, id := range nbProfiles {
		a := metricSeries("rw", nbLabels("case", "a"), msSample(at(0), 1), msSample(at(0.001), 2), msSample(at(10), 3), msSample(at(20), 4), msSample(at(20.001), 5))
		b := metricSeries("rw", nbLabels("case", "b"), msSample(at(5), 1), msStale(10_000), msSample(at(15), 3))
		c := metricSeries("rw", nbLabels("case", "c_far"), msSample(at(2), 9))
		r, _, err := evalWith(t, featureProfile(t, id), "rw[20s]", instantAt(20_000), a, b, c)
		if err != nil || r.Type != "matrix" {
			t.Fatalf("%s: %v %s", id, err, r.Type)
		}
		got := map[string][]int64{}
		for _, s := range r.Matrix {
			for _, p := range s.Samples {
				got[nbLabel(s.Labels, "case")] = append(got[nbLabel(s.Labels, "case")], int64(p.Time))
			}
		}
		// the window is (t-20s, t]: the sample at exactly 0s is excluded, the one at 20s included, 20.001s is in the future
		want := map[string][]int64{"a": {1_000_000, 10_000_000_000, 20_000_000_000}, "b": {5_000_000_000, 15_000_000_000}, "c_far": {2_000_000_000}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s rw[20s] = %v, want %v", id, got, want)
		}
		// no lookback substitution: a sample before the window is not used, and a sample on its open bound is excluded
		none, _, err := evalWith(t, featureProfile(t, id), "rwn[15s]", instantAt(20_000), metricSeries("rwn", nbLabels("case", "x"), msSample(at(5), 1)), metricSeries("rwn", nbLabels("case", "y"), msSample(at(1), 2)))
		if err != nil || len(none.Matrix) != 0 {
			t.Errorf("%s rwn[15s]: %v %d series, want none", id, err, len(none.Matrix))
		}
		// a stale marker is excluded from the window values
		cnt, _ := nbVec(t, id, nil, "count_over_time(rw[20s])", instantAt(20_000), a, b, c)
		nbNear(t, id+" count_over_time a", cnt["case=a"], 3, 0)
		nbNear(t, id+" count_over_time b", cnt["case=b"], 2, 0)
	}
}
