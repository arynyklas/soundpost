// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import "testing"

func TestComparatorRetainsIntegerHistogramPrecision(t *testing.T) {
	a := SemanticResult{Kind: "vector", Values: []Value{{Histogram: &Histogram{Kind: "integer", Count: "9007199254740992", PositiveDeltas: []string{"9007199254740992"}}}}}
	b := SemanticResult{Kind: "vector", Values: []Value{{Histogram: &Histogram{Kind: "integer", Count: "9007199254740993", PositiveDeltas: []string{"9007199254740993"}}}}}
	if len(Compare(a, b, OrderingFreedom{})) == 0 {
		t.Fatal("integer histogram count precision lost")
	}
}
