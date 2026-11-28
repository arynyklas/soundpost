// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import "testing"

// A string literal evaluated as an instant query is reported at the evaluation
// time, as the pinned references do (the instant result is a (time, string) pair).
func TestStringLiteralResultCarriesEvaluationTime(t *testing.T) {
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		p := featureProfile(t, id)
		r, _, err := evalWith(t, p, `"text"`, instantAt(20_000))
		if err != nil {
			t.Fatal(err)
		}
		if r.Type != "string" || r.String != "text" {
			t.Fatalf("%s: got %+v", id, r)
		}
		if want := instantAt(20_000).Time; r.Scalar.Time != want {
			t.Fatalf("%s: string result time %d, want %d", id, r.Scalar.Time, want)
		}
	}
}
