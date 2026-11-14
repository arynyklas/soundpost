//go:build soundpost_evaluation_oracle

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/prometheus/prometheus/promql/parser/posrange"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
	"github.com/prometheus/prometheus/util/annotations"
)

func TestReferenceWirePreservesBitsAndIntegerCounts(t *testing.T) {
	for _, text := range []string{"8000000000000000", "7ff8000000000042", "7ff0000000000002", "fff0000000000000"} {
		var b bits
		if err := json.Unmarshal([]byte(`"`+text+`"`), &b); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(b)
		if err != nil || string(raw) != `"`+text+`"` {
			t.Fatal(string(raw), err)
		}
	}
	var h integerHistogram
	if err := json.Unmarshal([]byte(`{"count":"9007199254740993","zero_count":"9007199254740993"}`), &h); err != nil {
		t.Fatal(err)
	}
	if h.Count != 9_007_199_254_740_993 || h.ZeroCount != h.Count {
		t.Fatal("integer input rounded before actual engine")
	}
}
func TestReferenceIteratorSeeksAcrossActualSampleKinds(t *testing.T) {
	zero := bits(0x8000000000000000)
	it := &fixtureIterator{index: -1, samples: []sample{{Time: 0, Float: &zero}, {Time: 1_000_000, Histogram: &nativeHistogram{Integer: &integerHistogram{Flavor: "counter", ResetHint: "unknown", Count: 9_007_199_254_740_993, ZeroCount: 9_007_199_254_740_993}}}}}
	if it.Seek(0) != chunkenc.ValFloat {
		t.Fatal("initial seek lost float")
	}
	_, v := it.At()
	if math.Float64bits(v) != uint64(zero) {
		t.Fatal("signed zero changed")
	}
	if it.Next() != chunkenc.ValHistogram {
		t.Fatal("histogram kind erased")
	}
	_, h := it.AtHistogram(nil)
	if h.Count != 9_007_199_254_740_993 {
		t.Fatal("native integer input rounded")
	}
	if it.Seek(1) != chunkenc.ValHistogram || it.Next() != chunkenc.ValNone {
		t.Fatal("seek/next exhaustion changed")
	}
}
func TestReferenceRejectsNativeTimestampCollisionInsteadOfMerging(t *testing.T) {
	one := bits(0x3ff0000000000000)
	_, err := makeQueryable(fixtureCase{Series: []series{{Samples: []sample{{Time: 1, Float: &one}, {Time: 2, Float: &one}}}}})
	if err == nil || !strings.Contains(err.Error(), "collide") {
		t.Fatalf("native timestamp collision: %v", err)
	}
	if millis(-1) != -1 || millis(1_000_001) != 1 {
		t.Fatal("source-proven timestamp domain changed")
	}
}
func TestReferenceExecutesActualPinnedEngineAndEmitsCompleteScalar(t *testing.T) {
	configuration := map[string]json.RawMessage{
		"query.max-samples":             json.RawMessage(`{"default":"50000000"}`),
		"query.timeout":                 json.RawMessage(`{"default":"2m"}`),
		"engine.enable-at-modifier":     json.RawMessage(`{"default":"true"}`),
		"engine.enable-negative-offset": json.RawMessage(`{"default":"true"}`),
	}
	got, err := evaluate(input{Lookback: 300_000_000_000, SubqueryStep: 60_000_000_000, Configuration: configuration}, fixtureCase{ID: "scalar", Query: "1 + 2", Kind: "instant", Time: 2_000_000_000})
	if err != nil || got.Error != nil || got.Type != "scalar" || !got.Complete || got.Partial || len(got.Series) != 1 {
		t.Fatalf("actual upstream result: %+v, %v", got, err)
	}
	p := got.Series[0].Samples[0]
	if p.Time != 2_000_000_000 || p.Float == nil || *p.Float != bits(0x4008000000000000) {
		t.Fatalf("scalar bits/time: %+v", p)
	}
}
func TestReferenceRuntimeErrorsRemainSemanticallyDistinct(t *testing.T) {
	if classifyNativeError("many-to-many matching not allowed") == classifyNativeError("vector cannot contain metrics with the same labelset") {
		t.Fatal("unrelated runtime errors collapsed")
	}
	if classifyNativeError("unknown native failure") != "" {
		t.Fatal("unknown failure treated as a known expected language error")
	}
}

func TestReferenceObservesActualAnnotationSentinelsAndExactRanges(t *testing.T) {
	mixed := annotations.NewMixedFloatsHistogramsWarning("fixture", posrange.PositionRange{Start: 4, End: 8})
	quantile := annotations.NewInvalidQuantileWarning(2, posrange.PositionRange{Start: 1, End: 3})
	got, err := observeAnnotations(annotations.Annotations{mixed.Error(): mixed, quantile.Error(): quantile})
	if err != nil || len(got) != 2 {
		t.Fatal(got, err)
	}
	if got[0].ID != "InvalidQuantileWarning" || got[0].Start != 1 || got[0].End != 3 || got[1].ID != "MixedFloatsHistogramsWarning" || got[1].Start != 4 || got[1].End != 8 {
		t.Fatalf("actual annotation metadata: %+v", got)
	}
}

func TestReferenceIteratorUsesGenuineOptionalStartTimestamp(t *testing.T) {
	one := bits(0x3ff0000000000000)
	for _, text := range []string{"", `,"start_timestamp_ns":"0"`, `,"start_timestamp_ns":"-1000001"`, `,"start_timestamp_ns":"9223372036854775807"`} {
		var p sample
		if err := json.Unmarshal([]byte(`{"time":"2000000000","float_bits":"3ff0000000000000"`+text+`}`), &p); err != nil {
			t.Fatal(err)
		}
		if (text == "") != (p.StartTimestamp == nil) {
			t.Fatal("wire collapsed absent/present zero")
		}
		p.Float = &one
		it := &fixtureIterator{index: -1, samples: []sample{p}}
		if it.Next() != chunkenc.ValFloat {
			t.Fatal("missing actual sample")
		}
		want := int64(0)
		if p.StartTimestamp != nil {
			want = millis(*p.StartTimestamp)
		}
		if it.AtST() != want {
			t.Fatalf("native AtST=%d want=%d", it.AtST(), want)
		}
		if p.StartTimestamp != nil {
			raw, err := json.Marshal(p)
			if err != nil || !strings.Contains(string(raw), `"start_timestamp_ns":`) {
				t.Fatal("present start timestamp was not retained", string(raw), err)
			}
		}
	}
}
