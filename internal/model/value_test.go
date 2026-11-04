// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model_test

import (
	"encoding/json"
	"soundpost/internal/model"
	"testing"
)

func TestExactHistogramCountsAndFloatBits(t *testing.T) {
	count := uint64(9007199254740993)
	h := model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", Schema: 0, Count: model.Uint64(count), PositiveSpans: []model.HistogramSpan{{Length: 1}}, PositiveCounts: []model.AbsoluteBucket{model.AbsoluteBucket(count)}, ResetHint: "unknown"}}
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	var decoded model.NativeHistogram
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if uint64(decoded.Integer.Count) != count || uint64(decoded.Integer.PositiveCounts[0]) != count {
		t.Fatal("count lost integer precision")
	}
	decoded.Integer.PositiveSpans[0].Length = 2
	if err = decoded.Validate(); err == nil {
		t.Fatal("mismatched histogram span accepted")
	}
	for _, bits := range []model.FloatBits{0x7ff0000000000002, 0x7ff8000000000001} {
		raw, err = json.Marshal(bits)
		if err != nil {
			t.Fatal(err)
		}
		var roundtrip model.FloatBits
		if err = json.Unmarshal(raw, &roundtrip); err != nil || roundtrip != bits {
			t.Fatal("NaN/stale payload changed")
		}
	}
}
func TestCanonicalIDsAndDecimalStrings(t *testing.T) {
	for _, raw := range []string{`"00000000000000000000000000000000"`, `"ABCDEF0123456789ABCDEF0123456789"`} {
		var id model.ID
		if err := json.Unmarshal([]byte(raw), &id); err == nil {
			t.Fatal("noncanonical ID accepted")
		}
	}
	for _, raw := range []string{`1`, `"01"`, `"+1"`, `"-0"`} {
		var n model.UnixNano
		if err := json.Unmarshal([]byte(raw), &n); err == nil {
			t.Fatal("noncanonical nanoseconds accepted")
		}
	}
	var h model.IntegerHistogram
	if err := json.Unmarshal([]byte(`{"count":"01","zero_count":"0"}`), &h); err == nil {
		t.Fatal("noncanonical histogram count accepted")
	}
}
