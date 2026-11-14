// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/syntax"
)

// k = -2^63 is representable as int64 and below one, so the result is empty.
// A parameter that overflows int64 upward fails during execution on both
// pinned profiles. Below -2^63 3.1.0 fails the range check first, while 3.13.5
// answers any parameter below one with an empty result before checking it.
func TestNativeTopkParameterRange(t *testing.T) {
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5"} {
		p := featureProfile(t, id, "promql-experimental-functions")
		for _, name := range []string{"topk", "bottomk", "limitk"} {
			for _, in := range []struct {
				text  string
				fails bool
			}{
				{"-9223372036854775808", false},
				{"-9223372036854777856", id == "promql-prometheus-3.1.0"},
				{"9223372036854775807", true},
				{"9223372036854775808", true},
				{"9223372036854777856", true},
			} {
				query := name + "(" + in.text + ", m)"
				r, _, err := evalWith(t, p, query, instantAt(10_000),
					metricSeries("m", model.Labels{{Name: "i", Value: "1"}}, msSample(0, 1)),
					metricSeries("m", model.Labels{{Name: "i", Value: "2"}}, msSample(0, 2)))
				if !in.fails {
					if err != nil || r.Type != "vector" || len(r.Vector) != 0 {
						t.Fatalf("%s %s: %+v %v", id, query, r, err)
					}
					continue
				}
				var language *syntax.LanguageError
				if !errors.As(err, &language) || language.Code != "aggregation.parameter-range" || language.Category != "execution" {
					t.Fatalf("%s %s: want execution aggregation.parameter-range, got %+v", id, query, err)
				}
			}
		}
	}
}
