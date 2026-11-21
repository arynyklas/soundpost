// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func integerHistogram() *model.NativeHistogram {
	return &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Schema: 3, ZeroThreshold: 0x3f50624dd2f1a9fc, Sum: 0x4059000000000000, Count: 18014398509481985, ZeroCount: 7,
		PositiveSpans: []model.HistogramSpan{{Offset: -1, Length: 2}, {Offset: 3, Length: 1}}, NegativeSpans: []model.HistogramSpan{{Offset: 2, Length: 1}},
		PositiveBuckets: []model.DeltaBucket{9007199254740993, -1, 4}, NegativeBuckets: []model.DeltaBucket{-9007199254740993}, ResetHint: "reset"}}
}

func floatHistogram() *model.NativeHistogram {
	return &model.NativeHistogram{Float: &model.FloatHistogram{Flavor: "counter", Schema: -2, ZeroThreshold: 0x3f50624dd2f1a9fc, Sum: 0x8000000000000000, Count: 0x43b0000000000000, ZeroCount: 0x3fd0000000000000,
		PositiveSpans: []model.HistogramSpan{{Offset: -1, Length: 1}, {Offset: 1, Length: 1}}, NegativeSpans: []model.HistogramSpan{{Offset: 0, Length: 1}},
		PositiveBuckets: []model.FloatBits{0x3ff4000000000000, 0x4000000000000000}, NegativeBuckets: []model.FloatBits{0x7ff8000000000001}, ResetHint: "not_reset"}}
}

func customHistogram() *model.NativeHistogram {
	h := integerHistogram()
	h.Integer.Schema = -53
	h.Integer.CustomBounds = []model.FloatBits{0x3ff0000000000000, 0x4024000000000000}
	return h
}

func mustHistogramInput(t *testing.T, h *model.NativeHistogram) string {
	t.Helper()
	got, err := HistogramInput(h)
	if err != nil {
		t.Fatal(err)
	}
	return canonical(got)
}

// The record carries every exact field: a count above 2^53 stays a decimal, floats are their bits.
func TestHistogramInputRendersEveryExactField(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    *model.NativeHistogram
		want string
	}{
		{"integer", integerHistogram(), `{"kind":"integer","schema":3,"reset_hint":"reset","count":"18014398509481985","zero_count":"7","zero_threshold_bits":"3f50624dd2f1a9fc","sum_bits":"4059000000000000","positive_spans":[{"offset":-1,"length":2},{"offset":3,"length":1}],"negative_spans":[{"offset":2,"length":1}],"positive_deltas":["9007199254740993","-1","4"],"negative_deltas":["-9007199254740993"]}`},
		{"float", floatHistogram(), `{"kind":"float","schema":-2,"reset_hint":"not_reset","count_bits":"43b0000000000000","zero_count_bits":"3fd0000000000000","zero_threshold_bits":"3f50624dd2f1a9fc","sum_bits":"8000000000000000","positive_spans":[{"offset":-1,"length":1},{"offset":1,"length":1}],"negative_spans":[{"offset":0,"length":1}],"positive_bucket_bits":["3ff4000000000000","4000000000000000"],"negative_bucket_bits":["7ff8000000000001"]}`},
		{"custom bounds", customHistogram(), `{"kind":"integer","schema":-53,"reset_hint":"reset","count":"18014398509481985","zero_count":"7","zero_threshold_bits":"3f50624dd2f1a9fc","sum_bits":"4059000000000000","positive_spans":[{"offset":-1,"length":2},{"offset":3,"length":1}],"negative_spans":[{"offset":2,"length":1}],"positive_deltas":["9007199254740993","-1","4"],"negative_deltas":["-9007199254740993"],"custom_boundary_bits":["3ff0000000000000","4024000000000000"]}`},
	} {
		if got := mustHistogramInput(t, tc.h); got != tc.want {
			t.Errorf("%s: got\n%s\nwant\n%s", tc.name, got, tc.want)
		}
	}
}

// Changing any single field of either form changes the record: a normalization that alters one
// field of a stored histogram is never invisible to the check that compares these records.
func TestHistogramInputSeesEveryFieldChange(t *testing.T) {
	integer := map[string]func(*model.IntegerHistogram){
		"schema":            func(h *model.IntegerHistogram) { h.Schema++ },
		"zero threshold":    func(h *model.IntegerHistogram) { h.ZeroThreshold++ },
		"sum":               func(h *model.IntegerHistogram) { h.Sum++ },
		"sum sign":          func(h *model.IntegerHistogram) { h.Sum ^= 1 << 63 },
		"count":             func(h *model.IntegerHistogram) { h.Count++ },
		"count past 2^53":   func(h *model.IntegerHistogram) { h.Count += 2 },
		"zero count":        func(h *model.IntegerHistogram) { h.ZeroCount++ },
		"positive offset":   func(h *model.IntegerHistogram) { h.PositiveSpans[0].Offset++ },
		"positive length":   func(h *model.IntegerHistogram) { h.PositiveSpans[1].Length++ },
		"negative offset":   func(h *model.IntegerHistogram) { h.NegativeSpans[0].Offset++ },
		"negative length":   func(h *model.IntegerHistogram) { h.NegativeSpans[0].Length++ },
		"positive bucket":   func(h *model.IntegerHistogram) { h.PositiveBuckets[2]++ },
		"negative bucket":   func(h *model.IntegerHistogram) { h.NegativeBuckets[0]++ },
		"reset hint":        func(h *model.IntegerHistogram) { h.ResetHint = "gauge" },
		"custom bound":      func(h *model.IntegerHistogram) { h.CustomBounds = []model.FloatBits{1} },
		"a span dropped":    func(h *model.IntegerHistogram) { h.PositiveSpans = h.PositiveSpans[:1] },
		"a bucket dropped":  func(h *model.IntegerHistogram) { h.PositiveBuckets = h.PositiveBuckets[:2] },
		"negative dropped":  func(h *model.IntegerHistogram) { h.NegativeBuckets, h.NegativeSpans = nil, nil },
		"negative appended": func(h *model.IntegerHistogram) { h.NegativeBuckets = append(h.NegativeBuckets, 0) },
	}
	base := mustHistogramInput(t, integerHistogram())
	for name, change := range integer {
		h := integerHistogram()
		change(h.Integer)
		if mustHistogramInput(t, h) == base {
			t.Errorf("integer histogram: changing the %s is invisible", name)
		}
	}
	float := map[string]func(*model.FloatHistogram){
		"schema":            func(h *model.FloatHistogram) { h.Schema++ },
		"zero threshold":    func(h *model.FloatHistogram) { h.ZeroThreshold++ },
		"sum":               func(h *model.FloatHistogram) { h.Sum++ },
		"count":             func(h *model.FloatHistogram) { h.Count++ },
		"zero count":        func(h *model.FloatHistogram) { h.ZeroCount++ },
		"positive offset":   func(h *model.FloatHistogram) { h.PositiveSpans[0].Offset++ },
		"positive length":   func(h *model.FloatHistogram) { h.PositiveSpans[1].Length++ },
		"negative offset":   func(h *model.FloatHistogram) { h.NegativeSpans[0].Offset++ },
		"positive bucket":   func(h *model.FloatHistogram) { h.PositiveBuckets[1]++ },
		"negative bucket":   func(h *model.FloatHistogram) { h.NegativeBuckets[0] ^= 1 },
		"NaN payload":       func(h *model.FloatHistogram) { h.NegativeBuckets[0]++ },
		"reset hint":        func(h *model.FloatHistogram) { h.ResetHint = "reset" },
		"custom bound":      func(h *model.FloatHistogram) { h.CustomBounds = []model.FloatBits{1} },
		"a bucket dropped":  func(h *model.FloatHistogram) { h.PositiveBuckets = h.PositiveBuckets[:1] },
		"negative appended": func(h *model.FloatHistogram) { h.NegativeBuckets = append(h.NegativeBuckets, 0) },
	}
	base = mustHistogramInput(t, floatHistogram())
	for name, change := range float {
		h := floatHistogram()
		change(h.Float)
		if mustHistogramInput(t, h) == base {
			t.Errorf("float histogram: changing the %s is invisible", name)
		}
	}
	// A float histogram is never the integer histogram that holds the same numbers.
	asInteger := &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Count: 3, ZeroCount: 1}}
	asFloat := &model.NativeHistogram{Float: &model.FloatHistogram{Flavor: "counter", Count: 0x4008000000000000, ZeroCount: 0x3ff0000000000000}}
	if mustHistogramInput(t, asInteger) == mustHistogramInput(t, asFloat) {
		t.Error("the integer and the float form render alike")
	}
}

// A list that is nil and one that is allocated and empty are the same list: the form a
// storage round trip returns must not read as a change.
func TestHistogramInputTreatsNilAndEmptyListsAlike(t *testing.T) {
	a := &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Count: 1}}
	b := &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Count: 1, PositiveSpans: []model.HistogramSpan{}, NegativeSpans: []model.HistogramSpan{}, PositiveBuckets: []model.DeltaBucket{}, NegativeBuckets: []model.DeltaBucket{}, CustomBounds: []model.FloatBits{}}}
	if mustHistogramInput(t, a) != mustHistogramInput(t, b) {
		t.Errorf("nil and empty lists render differently:\n%s\n%s", mustHistogramInput(t, a), mustHistogramInput(t, b))
	}
	c := &model.NativeHistogram{Float: &model.FloatHistogram{Flavor: "counter"}}
	d := &model.NativeHistogram{Float: &model.FloatHistogram{Flavor: "counter", PositiveSpans: []model.HistogramSpan{}, NegativeSpans: []model.HistogramSpan{}, PositiveBuckets: []model.FloatBits{}, NegativeBuckets: []model.FloatBits{}, CustomBounds: []model.FloatBits{}}}
	if mustHistogramInput(t, c) != mustHistogramInput(t, d) {
		t.Errorf("nil and empty float lists render differently")
	}
}

// What the record cannot carry exactly is refused rather than rendered lossily.
func TestHistogramInputRefusesWhatItCannotCarry(t *testing.T) {
	gaugeInteger := integerHistogram()
	gaugeInteger.Integer.Flavor = "gauge"
	gaugeFloat := floatHistogram()
	gaugeFloat.Float.Flavor = "gauge"
	absolute := integerHistogram()
	absolute.Integer.PositiveCounts = []model.AbsoluteBucket{1}
	absoluteNegative := integerHistogram()
	absoluteNegative.Integer.NegativeCounts = []model.AbsoluteBucket{1}
	for name, h := range map[string]*model.NativeHistogram{
		"nil": nil, "neither form": {}, "both forms": {Integer: integerHistogram().Integer, Float: floatHistogram().Float},
		"integer gauge flavor": gaugeInteger, "float gauge flavor": gaugeFloat, "absolute positive counts": absolute, "absolute negative counts": absoluteNegative,
	} {
		got, err := HistogramInput(h)
		if err == nil || got != nil {
			t.Errorf("%s: rendered %v, error %v", name, got, err)
			continue
		}
		if !strings.Contains(err.Error(), "histogram") {
			t.Errorf("%s: error does not name the histogram: %v", name, err)
		}
	}
}
