//go:build soundpost_evaluation_oracle

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestReferenceActualParserErrorsExposeFamiliesAndRangesNotIndependentStages(t *testing.T) {
	in := input{Lookback: 300_000_000_000, SubqueryStep: 60_000_000_000, Configuration: map[string]json.RawMessage{
		"query.max-samples":             json.RawMessage(`{"default":"50000000"}`),
		"query.timeout":                 json.RawMessage(`{"default":"2m"}`),
		"engine.enable-at-modifier":     json.RawMessage(`{"default":"true"}`),
		"engine.enable-negative-offset": json.RawMessage(`{"default":"true"}`),
	}}
	for _, c := range []struct {
		query, code string
		start, end  int
	}{
		{`abs("x")`, "function.argument-type", 4, 7},
		{`clamp(1)`, "function.arity", 0, 8},
		{`sum("x")`, "aggregation.input-type", 4, 7},
		{`topk("x")`, "aggregation.arity", 0, 9},
		{`soundpost_missing_function(1)`, "function.unknown", 0, len("soundpost_missing_function")},
		{`mad_over_time(m[1m])`, "function.feature-disabled", 0, len("mad_over_time")},
		{`limitk(1, m)`, "aggregation.feature-disabled", 0, len("limitk(1, m)")},
	} {
		got, err := evaluate(in, fixtureCase{ID: "actual-native-error", Query: c.query, Kind: "instant", Time: 2_000_000_000})
		if err != nil {
			t.Fatal(err)
		}
		if got.Error == nil || got.Error.ID != c.code {
			t.Fatalf("actual %s: %+v", c.query, got.Error)
		}
		if got.Error.Category != "parse-error" || got.Error.CategoryExposed {
			t.Fatalf("ParseErrors stage fabricated: %+v", got.Error)
		}
		if !got.Error.RangeExposed || got.Error.Start != c.start || got.Error.End != c.end {
			t.Fatalf("actual %s range: %+v", c.query, got.Error)
		}
	}
}

func TestReferenceUnknownNativeErrorFamilyRemainsUnclassified(t *testing.T) {
	got := observeError(errors.New("unknown actual native failure"), "execution")
	if got.ID != "" {
		t.Fatalf("unknown error optimistically classified: %+v", got)
	}
	if !got.CategoryExposed || got.Category != "execution" || got.RangeExposed {
		t.Fatalf("native runtime exposure metadata: %+v", got)
	}
}
