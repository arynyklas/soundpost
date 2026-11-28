// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"
	"runtime"
	"sort"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// Independent binary64 expectations for the `numeric` release partition. Expected values come from
// IEEE-754 / the rule texts of the numeric/* obligations (exact special values) and from Go's
// math package for finite transcendental results; they are never read from an oracle run.

const (
	nbPZ   = uint64(0x0000000000000000)
	nbNZ   = uint64(0x8000000000000000)
	nbPInf = uint64(0x7ff0000000000000)
	nbNInf = uint64(0xfff0000000000000)
	nbSub  = uint64(0x0000000000000001) // smallest positive subnormal 5e-324
	nbNaN  = uint64(0x7ff8000000000001)
	nbOne  = uint64(0x3ff0000000000000)
	nbNOne = uint64(0xbff0000000000000)
	nbPi   = uint64(0x400921fb54442d18)
	nbHPi  = uint64(0x3ff921fb54442d18)
	nbNHPi = uint64(0xbff921fb54442d18)
)

func nbLabel(l model.Labels, name string) string {
	for _, x := range l {
		if x.Name == name {
			return x.Value
		}
	}
	return ""
}

func nbF(b uint64) float64 { return math.Float64frombits(b) }

// nbIsNaN marks an expected NaN: the NaN payload is not part of the rule, only NaN-ness.
const nbIsNaN = uint64(0xffffffffffffffff)

type numericCase struct{ in, want uint64 }

var releaseNumericTable = map[string][]numericCase{
	"abs": {{nbNInf, nbPInf}, {0xc004000000000000, 0x4004000000000000}, {nbNZ, nbPZ}, {nbPZ, nbPZ}, {nbSub, nbSub}, {0x400e000000000000, 0x400e000000000000}, {nbPInf, nbPInf}, {nbNaN, nbIsNaN}},
	"acos": {{nbNOne, nbPi}, {nbOne, nbPZ}, {nbPZ, nbHPi}, {nbNZ, nbHPi}, {0x4000000000000000, nbIsNaN}, {0xbff8000000000000, nbIsNaN},
		{nbPInf, nbIsNaN}, {nbNInf, nbIsNaN}, {nbNaN, nbIsNaN}, {0x3ff0000000000001, nbIsNaN}},
	"acosh": {{nbOne, nbPZ}, {nbPInf, nbPInf}, {0x3fe0000000000000, nbIsNaN}, {nbPZ, nbIsNaN}, {nbNZ, nbIsNaN}, {0xc008000000000000, nbIsNaN}, {nbNInf, nbIsNaN}, {nbNaN, nbIsNaN}},
	"asin":  {{nbPZ, nbPZ}, {nbNZ, nbNZ}, {nbSub, nbSub}, {nbOne, nbHPi}, {nbNOne, nbNHPi}, {0x4000000000000000, nbIsNaN}, {nbPInf, nbIsNaN}, {nbNInf, nbIsNaN}, {nbNaN, nbIsNaN}},
	"asinh": {{nbPZ, nbPZ}, {nbNZ, nbNZ}, {nbPInf, nbPInf}, {nbNInf, nbNInf}, {nbSub, nbSub}, {nbNaN, nbIsNaN}},
	"atan":  {{nbPZ, nbPZ}, {nbNZ, nbNZ}, {nbSub, nbSub}, {nbPInf, nbHPi}, {nbNInf, nbNHPi}, {nbNaN, nbIsNaN}},
	"atanh": {{nbPZ, nbPZ}, {nbNZ, nbNZ}, {nbOne, nbPInf}, {nbNOne, nbNInf}, {0x4000000000000000, nbIsNaN}, {0xc000000000000000, nbIsNaN}, {0x3ff0000000000001, nbIsNaN}, {nbPInf, nbIsNaN}, {nbNInf, nbIsNaN}, {nbNaN, nbIsNaN}},
	"ceil": {{0xbfe0000000000000, nbNZ}, {nbNZ, nbNZ}, {nbPZ, nbPZ}, {nbSub, nbOne}, {0x3fe0000000000000, nbOne}, {0x400e000000000000, 0x4010000000000000}, {0xc004000000000000, 0xc000000000000000},
		{nbPInf, nbPInf}, {nbNInf, nbNInf}, {nbNaN, nbIsNaN}},
	"cos":   {{nbPZ, nbOne}, {nbNZ, nbOne}, {nbPInf, nbIsNaN}, {nbNInf, nbIsNaN}, {nbNaN, nbIsNaN}},
	"cosh":  {{nbPZ, nbOne}, {nbNZ, nbOne}, {nbPInf, nbPInf}, {nbNInf, nbPInf}, {0x4086380000000000, nbPInf}, {0xc086380000000000, nbPInf}, {nbNaN, nbIsNaN}},
	"deg":   {{nbPZ, nbPZ}, {nbNZ, nbNZ}, {nbPInf, nbPInf}, {nbNInf, nbNInf}, {nbSub, 0x39}, {nbPi, 0x4066800000000000}, {nbHPi, 0x4056800000000000}, {0x7fe0000000000000, nbPInf}, {nbNaN, nbIsNaN}},
	"exp":   {{nbPZ, nbOne}, {nbNZ, nbOne}, {nbPInf, nbPInf}, {nbNInf, nbPZ}, {nbOne, 0x4005bf0a8b145769}, {0x4086380000000000, nbPInf}, {0xc087500000000000, nbPZ}, {nbNaN, nbIsNaN}},
	"floor": {{0xbfe0000000000000, nbNOne}, {0x3fe0000000000000, nbPZ}, {nbNZ, nbNZ}, {nbPZ, nbPZ}, {nbSub, nbPZ}, {0x400e000000000000, 0x4008000000000000}, {0xc004000000000000, 0xc008000000000000}, {nbPInf, nbPInf}, {nbNInf, nbNInf}, {nbNaN, nbIsNaN}},
	"ln":    {{nbPZ, nbNInf}, {nbNZ, nbNInf}, {nbOne, nbPZ}, {nbPInf, nbPInf}, {nbNOne, nbIsNaN}, {nbNInf, nbIsNaN}, {nbNaN, nbIsNaN}},
	"log10": {{nbPZ, nbNInf}, {nbNZ, nbNInf}, {nbOne, nbPZ}, {nbPInf, nbPInf}, {nbNOne, nbIsNaN}, {nbNInf, nbIsNaN}, {nbNaN, nbIsNaN}},
	"log2":  {{nbPZ, nbNInf}, {nbNZ, nbNInf}, {nbOne, nbPZ}, {0x4000000000000000, nbOne}, {0x4020000000000000, 0x4008000000000000}, {0x4090000000000000, 0x4024000000000000}, {0x3fe0000000000000, nbNOne}, {nbPInf, nbPInf}, {nbNOne, nbIsNaN}, {nbNInf, nbIsNaN}, {nbNaN, nbIsNaN}},
	"rad":   {{nbPZ, nbPZ}, {nbNZ, nbNZ}, {nbPInf, nbPInf}, {nbNInf, nbNInf}, {0x4066800000000000, nbPi}, {0x4056800000000000, nbHPi}, {0x7fefffffffffffff, nbPInf}, {nbNaN, nbIsNaN}},
	"sgn":   {{nbNInf, nbNOne}, {0xc004000000000000, nbNOne}, {nbNZ, nbNZ}, {nbPZ, nbPZ}, {nbSub, nbOne}, {0x400e000000000000, nbOne}, {nbPInf, nbOne}, {nbNaN, nbNaN}},
	"sin":   {{nbPZ, nbPZ}, {nbNZ, nbNZ}, {nbSub, nbSub}, {nbPInf, nbIsNaN}, {nbNInf, nbIsNaN}, {nbNaN, nbIsNaN}},
	"sinh":  {{nbPZ, nbPZ}, {nbNZ, nbNZ}, {nbSub, nbSub}, {nbPInf, nbPInf}, {nbNInf, nbNInf}, {0x4086380000000000, nbPInf}, {0xc086380000000000, nbNInf}, {nbNaN, nbIsNaN}},
	"sqrt":  {{nbNZ, nbNZ}, {nbPZ, nbPZ}, {0x3fd0000000000000, 0x3fe0000000000000}, {0x4000000000000000, 0x3ff6a09e667f3bcd}, {nbPInf, nbPInf}, {nbNOne, nbIsNaN}, {0x8000000000000001, nbIsNaN}, {nbNInf, nbIsNaN}, {nbNaN, nbIsNaN}},
	"tan":   {{nbPZ, nbPZ}, {nbNZ, nbNZ}, {nbSub, nbSub}, {nbPInf, nbIsNaN}, {nbNInf, nbIsNaN}, {nbNaN, nbIsNaN}},
}

// releaseNumericEval evaluates query at t=20s over float series (one per case label, sample at 15s)
// plus one native-histogram series carrying the same metric name, and returns the result bits by
// case label.
func releaseNumericEval(t *testing.T, profileID, query string, inputs []uint64) map[string]uint64 {
	t.Helper()
	p := featureProfile(t, profileID)
	var series []value.Series
	for i, in := range inputs {
		series = append(series, metricSeries("nd_in", model.Labels{{Name: "case", Value: "v" + itoa(i)}}, value.Sample{Time: model.UnixNano(15_000_000_000), Float: model.FloatBits(in)}))
	}
	series = append(series, metricSeries("nd_in", model.Labels{{Name: "case", Value: "hist"}}, value.Sample{Time: model.UnixNano(15_000_000_000), Histogram: nativeTestHistogram(3)}))
	r, _, err := evalWith(t, p, query, instantAt(20_000), series...)
	if err != nil {
		t.Fatalf("%s %s: %v", profileID, query, err)
	}
	if r.Type != "vector" {
		t.Fatalf("%s %s: result type %q", profileID, query, r.Type)
	}
	out := map[string]uint64{}
	for _, s := range r.Vector {
		if len(s.Samples) != 1 || s.Samples[0].Histogram != nil {
			t.Fatalf("%s %s: series %v has %d samples / histogram", profileID, query, s.Labels, len(s.Samples))
		}
		out[nbLabel(s.Labels, "case")] = uint64(s.Samples[0].Float)
	}
	return out
}

func nbCheck(t *testing.T, what string, got, want uint64) {
	t.Helper()
	if want == nbIsNaN {
		if !math.IsNaN(nbF(got)) {
			t.Errorf("%s = %#016x, want NaN", what, got)
		}
		return
	}
	if got != want {
		t.Errorf("%s = %#016x, want %#016x", what, got, want)
	}
}

// TestReleaseNumericFunctionDomains pins every numeric function's special-value domain bit for
// bit through a real query under both profiles; the native-histogram series sharing the metric
// name must be ignored (no result series).
func TestReleaseNumericFunctionDomains(t *testing.T) {
	names := make([]string, 0, len(releaseNumericTable))
	for name := range releaseNumericTable {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		for _, name := range names {
			cases := releaseNumericTable[name]
			inputs := make([]uint64, len(cases))
			for i, c := range cases {
				inputs[i] = c.in
			}
			got := releaseNumericEval(t, id, name+"(nd_in)", inputs)
			if len(got) != len(cases) {
				t.Errorf("%s %s: %d result series for %d float inputs (histogram must be ignored): %v", id, name, len(got), len(cases), got)
			}
			if _, leaked := got["hist"]; leaked {
				t.Errorf("%s %s: native histogram series produced a result", id, name)
			}
			for i, c := range cases {
				nbCheck(t, id+" "+name+"("+itoa(int(c.in>>32))+"…)", got["v"+itoa(i)], c.want)
			}
		}
	}
}

// TestReleaseNumericFiniteResultsAreGoMath compares finite transcendental results with Go's
// math package (the pinned reference arithmetic) bit for bit, including deg/rad in the stated
// operation order, which differs from a pre-rounded multiplier.
func TestReleaseNumericFiniteResultsAreGoMath(t *testing.T) {
	inputs := []float64{-2.5, 0.75, 3.75, 1e22, math.Pi / 2, 0.5, 2, 709, 1e300, 1e-300, 1e307}
	ref := map[string]func(float64) float64{
		"acos": math.Acos, "acosh": math.Acosh, "asin": math.Asin, "asinh": math.Asinh, "atan": math.Atan, "atanh": math.Atanh,
		"cos": math.Cos, "cosh": math.Cosh, "exp": math.Exp, "ln": math.Log, "log10": math.Log10, "log2": math.Log2,
		"sin": math.Sin, "sinh": math.Sinh, "sqrt": math.Sqrt, "tan": math.Tan,
		"deg": func(x float64) float64 { return float64(x*180) / math.Pi },
		"rad": func(x float64) float64 { return float64(x*math.Pi) / 180 },
	}
	bitsOf := make([]uint64, len(inputs))
	for i, x := range inputs {
		bitsOf[i] = math.Float64bits(x)
	}
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		for name, f := range ref {
			got := releaseNumericEval(t, id, name+"(nd_in)", bitsOf)
			for i, x := range inputs {
				want := f(x)
				if math.IsNaN(want) {
					nbCheck(t, id+" "+name+"("+itoa(i)+")", got["v"+itoa(i)], nbIsNaN)
					continue
				}
				nbCheck(t, id+" "+name+"("+itoa(i)+")", got["v"+itoa(i)], math.Float64bits(want))
			}
		}
	}
}

// TestReleaseNumericLogSubnormalFollowsPinnedAmd64Math: the pinned references are amd64 builds,
// whose math.Log assembly does not normalise a subnormal argument: it reads the exponent field as
// 0 (k = -1022) and the mantissa bits as the fraction of [0.5,1). So ln(5e-324) is about -709.09,
// not the mathematical -744.44, and log10 is that value times 1/Ln10.
func TestReleaseNumericLogSubnormalFollowsPinnedAmd64Math(t *testing.T) {
	// mathematically derived: ln(2^-1022 * f1) with f1 = 0.5*(1+m/2^52), m = mantissa bits.
	for _, m := range []uint64{1, 3, 0x6a09e667f3bcd, 0xfffffffffffff} {
		x := math.Float64frombits(m)
		f1 := 0.5 * (1 + float64(m)/(1<<52))
		wantLn := -1022*math.Ln2 + math.Log(f1)
		inputs := []uint64{math.Float64bits(x)}
		for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
			gotLn := nbF(releaseNumericEval(t, id, "ln(nd_in)", inputs)["v0"])
			if math.Abs(gotLn-wantLn) > 1e-9*math.Abs(wantLn) {
				t.Errorf("%s ln(%#x subnormal) = %v, want about %v", id, m, gotLn, wantLn)
			}
			gotLog10 := nbF(releaseNumericEval(t, id, "log10(nd_in)", inputs)["v0"])
			if want := wantLn / math.Ln10; math.Abs(gotLog10-want) > 1e-9*math.Abs(want) {
				t.Errorf("%s log10(%#x subnormal) = %v, want about %v", id, m, gotLog10, want)
			}
			if runtime.GOARCH == "amd64" { // the stdlib assembly is the pinned reference only there
				if want := math.Float64bits(math.Log(x)); math.Float64bits(gotLn) != want {
					t.Errorf("%s ln(%#x subnormal) bits %#016x, amd64 math.Log %#016x", id, m, math.Float64bits(gotLn), want)
				}
				if want := math.Float64bits(math.Log10(x)); math.Float64bits(gotLog10) != want {
					t.Errorf("%s log10(%#x subnormal) bits %#016x, amd64 math.Log10 %#016x", id, m, math.Float64bits(gotLog10), want)
				}
			}
		}
	}
}

// TestReleaseNumericMaxMinOverTimeSignedZeroKeepsFirst: max_over_time / min_over_time select a
// later sample only when it is strictly greater / smaller (IEEE: -0 == +0), so equal-comparing
// zeros keep the first observed sign. NaN is replaced by any later value.
func TestReleaseNumericMaxMinOverTimeSignedZeroKeepsFirst(t *testing.T) {
	cases := []struct {
		fn       string
		in, want []uint64
	}{
		{"max_over_time", []uint64{nbNZ, nbPZ}, []uint64{nbNZ}},
		{"max_over_time", []uint64{nbPZ, nbNZ}, []uint64{nbPZ}},
		{"min_over_time", []uint64{nbNZ, nbPZ}, []uint64{nbNZ}},
		{"min_over_time", []uint64{nbPZ, nbNZ}, []uint64{nbPZ}},
		{"max_over_time", []uint64{nbNZ, nbPZ, nbNZ, nbPZ}, []uint64{nbNZ}},
		{"min_over_time", []uint64{nbPZ, nbNZ, nbPZ, nbNZ}, []uint64{nbPZ}},
		{"max_over_time", []uint64{nbNaN, nbNZ, nbPZ}, []uint64{nbNZ}},
	}
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		p := featureProfile(t, id)
		for i, c := range cases {
			var samples []value.Sample
			for j, in := range c.in {
				samples = append(samples, value.Sample{Time: model.UnixNano(int64(11+j) * 1_000_000_000), Float: model.FloatBits(in)})
			}
			r, _, err := evalWith(t, p, c.fn+"(nd_in[20s])", instantAt(20_000), metricSeries("nd_in", model.Labels{{Name: "case", Value: "a"}}, samples...))
			if err != nil || len(r.Vector) != 1 {
				t.Fatalf("%s case %d: %v %v", id, i, err, r.Vector)
			}
			if got := uint64(r.Vector[0].Samples[0].Float); got != c.want[0] {
				t.Errorf("%s %s%#x = %#016x, want %#016x", id, c.fn, c.in, got, c.want[0])
			}
		}
	}
}

// TestReleaseNumericRangeResultSeriesSortedByLabels: a range query returns its series sorted by
// label set (the ordering rule: "range series sorted by labels"), whatever order the operands
// produced them in; `or` yields the left operand's series first, so the unsorted order is
// observable there.
func TestReleaseNumericRangeResultSeriesSortedByLabels(t *testing.T) {
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		p := featureProfile(t, id)
		a := metricSeries("ord_a", model.Labels{{Name: "case", Value: "z"}}, msSample(5_000, 1), msSample(15_000, 2))
		b := metricSeries("ord_b", model.Labels{{Name: "case", Value: "a"}}, msSample(5_000, 3), msSample(15_000, 4))
		r, _, err := evalWith(t, p, `label_replace(ord_a, "q", "x", "", "") or label_replace(ord_b, "q", "x", "", "")`, rangeOf(10_000, 20_000, 10_000), a, b)
		if err != nil || r.Type != "matrix" || len(r.Matrix) != 2 {
			t.Fatalf("%s: %v %v", id, err, r)
		}
		// label sets sorted by name then value: (__name__=ord_a ...) < (__name__=ord_b ...)
		first, second := nbLabel(r.Matrix[0].Labels, "__name__"), nbLabel(r.Matrix[1].Labels, "__name__")
		if first != "ord_a" || second != "ord_b" {
			t.Errorf("%s: order %s,%s", id, first, second)
		}
		// reversed operands: the right operand's series sorts first only if the result is sorted.
		r, _, err = evalWith(t, p, `label_replace(ord_b, "q", "x", "", "") or label_replace(ord_a, "q", "x", "", "")`, rangeOf(10_000, 20_000, 10_000), a, b)
		if err != nil || len(r.Matrix) != 2 {
			t.Fatalf("%s: %v %v", id, err, r)
		}
		if first, second = nbLabel(r.Matrix[0].Labels, "__name__"), nbLabel(r.Matrix[1].Labels, "__name__"); first != "ord_a" || second != "ord_b" {
			t.Errorf("%s: reversed operands order %s,%s, want sorted ord_a,ord_b", id, first, second)
		}
	}
}

// TestReleaseNumericAggregationParameterEvaluationPerProfile: the 3.13.5 aggregation parameter is
// evaluated at every query step; the 3.1.0 parameter is evaluated once and its first step's value
// applies to the whole range. topk(scalar(k), m) with k = 1, 2, 3 at steps 10s, 20s, 30s over
// four constant series (values 4,3,2,1) therefore returns series a,b,c with 3,2,1 points on 3.13.5
// and only a, with 3 points, on 3.1.0.
func TestReleaseNumericAggregationParameterEvaluationPerProfile(t *testing.T) {
	var m []value.Series
	for _, c := range []struct {
		name string
		v    float64
	}{{"a", 4}, {"b", 3}, {"c", 2}, {"d", 1}} {
		m = append(m, metricSeries("ap_m", model.Labels{{Name: "case", Value: c.name}}, msSample(5_000, c.v)))
	}
	k := metricSeries("ap_k", nil, msSample(10_000, 1), msSample(20_000, 2), msSample(30_000, 3))
	want := map[string]map[string]int{
		"promql-prometheus-3.1.0":  {"a": 3},
		"promql-prometheus-3.13.5": {"a": 3, "b": 2, "c": 1},
	}
	for id, counts := range want {
		p := featureProfile(t, id)
		r, _, err := evalWith(t, p, "topk(scalar(ap_k), ap_m)", rangeOf(10_000, 30_000, 10_000), append(m, k)...)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		got := map[string]int{}
		for _, s := range r.Matrix {
			got[nbLabel(s.Labels, "case")] = len(s.Samples)
		}
		if len(got) != len(counts) {
			t.Errorf("%s: series %v, want %v", id, got, counts)
			continue
		}
		for name, n := range counts {
			if got[name] != n {
				t.Errorf("%s: series %s has %d points, want %d (all: %v)", id, name, got[name], n, got)
			}
		}
	}
}

// TestReleaseNumericHistogramScalarOperationsDropEmptyBuckets: a histogram scaled or divided by a
// scalar keeps its non-empty buckets and drops buckets that became zero (the pinned engines
// compact the result with no empty buckets allowed): a histogram times 0, or divided by +Inf,
// has no bucket spans at all, while NaN and +Inf bucket values are not empty and stay.
func TestReleaseNumericHistogramScalarOperationsDropEmptyBuckets(t *testing.T) {
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		p := featureProfile(t, id)
		hs := metricSeries("hx", model.Labels{{Name: "case", Value: "a"}}, value.Sample{Time: model.UnixNano(15_000_000_000), Histogram: nativeTestHistogram(4)})
		for _, c := range []struct {
			q       string
			buckets int
		}{{"hx * 0", 0}, {"0 * hx", 0}, {"hx / Inf", 0}, {"hx / 1e308 / 1e308", 0}, {"hx * 2", 1}, {"hx * NaN", 1}, {"hx * Inf", 1}} {
			r, _, err := evalWith(t, p, c.q, instantAt(20_000), hs)
			if err != nil || len(r.Vector) != 1 || r.Vector[0].Samples[0].Histogram == nil || r.Vector[0].Samples[0].Histogram.Float == nil {
				t.Fatalf("%s %s: %v %v", id, c.q, err, r)
			}
			f := r.Vector[0].Samples[0].Histogram.Float
			if len(f.PositiveBuckets) != c.buckets || len(f.PositiveSpans) != c.buckets {
				t.Errorf("%s %s: %d spans, %d buckets, want %d of each", id, c.q, len(f.PositiveSpans), len(f.PositiveBuckets), c.buckets)
			}
		}
	}
}
