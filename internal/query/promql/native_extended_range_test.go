// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"errors"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
)

const extendedGate = "promql-extended-range-selectors"

type extendedCase struct {
	name    string
	query   string
	series  []value.Sample
	ev      value.Evaluation
	want    []observedPoint // empty = no output series
	wantAnn []string
}

func runExtendedCases(t *testing.T, cases []extendedCase) {
	t.Helper()
	p := featureProfile(t, "promql-prometheus-3.13.5", extendedGate)
	for _, tc := range cases {
		r, notes, err := evalWith(t, p, tc.query, tc.ev, metricSeries("m", nil, tc.series...))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		var got []observedPoint
		switch r.Type {
		case "vector":
			if len(r.Vector) > 1 {
				t.Fatalf("%s: %d series", tc.name, len(r.Vector))
			}
			if len(r.Vector) == 1 {
				got = floatsOf(t, r.Vector[0])
			}
		case "matrix":
			if len(r.Matrix) > 1 {
				t.Fatalf("%s: %d series", tc.name, len(r.Matrix))
			}
			if len(r.Matrix) == 1 {
				got = floatsOf(t, r.Matrix[0])
			}
		}
		if !samePoints(got, tc.want) {
			t.Fatalf("%s: %s\n got %v\nwant %v", tc.name, tc.query, got, tc.want)
		}
		if tc.wantAnn != nil && !reflect.DeepEqual(diagnosticKeys(notes), tc.wantAnn) {
			t.Fatalf("%s: annotations %v want %v", tc.name, diagnosticKeys(notes), tc.wantAnn)
		}
	}
}

func pt(milliseconds int64, f float64) observedPoint {
	return observedPoint{Time: milliseconds * 1_000_000, Float: f}
}

var (
	rising   = []value.Sample{msSample(0, 1), msSample(10_000, 2), msSample(20_000, 4), msSample(30_000, 7)}
	reset    = []value.Sample{msSample(0, 5), msSample(10_000, 8), msSample(20_000, 2), msSample(30_000, 3)}
	staleMid = []value.Sample{msSample(0, 1), msStale(10_000), msSample(20_000, 3)}
	lone     = []value.Sample{msSample(12_000, 4)}
	sparse   = []value.Sample{msSample(5_000, 1), msSample(15_000, 3), msSample(25_000, 6)}
)

// Instant "m smoothed" interpolates between the neighbours of the evaluation
// time (stale markers dropped), carries the last value forward and is absent
// before the first sample.
func TestNativeSmoothedInstantSelector(t *testing.T) {
	runExtendedCases(t, []extendedCase{
		{"interpolate", "m smoothed", rising, instantAt(5_000), []observedPoint{pt(5_000, 1.5)}, nil},
		{"interpolate 2", "m smoothed", rising, instantAt(12_000), []observedPoint{pt(12_000, 2.4)}, nil},
		{"exact", "m smoothed", rising, instantAt(20_000), []observedPoint{pt(20_000, 4)}, nil},
		{"interpolate 3", "m smoothed", rising, instantAt(26_000), []observedPoint{pt(26_000, 5.8)}, nil},
		{"carry forward", "m smoothed", rising, instantAt(40_000), []observedPoint{pt(40_000, 7)}, nil},
		{"decreasing", "m smoothed", reset, instantAt(12_000), []observedPoint{pt(12_000, 6.8)}, nil},
		{"sparse", "m smoothed", []value.Sample{msSample(0, 1), msSample(25_000, 2)}, instantAt(12_000), []observedPoint{pt(12_000, 1.48)}, nil},
		{"stale dropped before interpolation", "m smoothed", staleMid, instantAt(5_000), []observedPoint{pt(5_000, 1.5)}, nil},
		{"stale dropped, later point", "m smoothed", staleMid, instantAt(12_000), []observedPoint{pt(12_000, 2.2)}, nil},
		{"absent before the first sample", "m smoothed", lone, instantAt(5_000), nil, nil},
		{"range query", "m smoothed", rising, rangeOf(0, 40_000, 5_000), []observedPoint{
			pt(0, 1), pt(5_000, 1.5), pt(10_000, 2), pt(15_000, 3), pt(20_000, 4), pt(25_000, 5.5), pt(30_000, 7), pt(35_000, 7), pt(40_000, 7)}, nil},
		{"range query with stale marker", "m smoothed", staleMid, rangeOf(0, 40_000, 5_000), []observedPoint{
			pt(0, 1), pt(5_000, 1.5), pt(10_000, 2), pt(15_000, 2.5), pt(20_000, 3), pt(25_000, 3), pt(30_000, 3), pt(35_000, 3), pt(40_000, 3)}, nil},
	})
}

func TestNativeExtendedMatrixSelectorBoundaries(t *testing.T) {
	runExtendedCases(t, []extendedCase{
		{"smoothed offset", "m[10s] smoothed offset 5s", rising, instantAt(30_000), []observedPoint{pt(15_000, 3), pt(20_000, 4), pt(25_000, 5.5)}, nil},
		{"anchored offset", "m[10s] anchored offset 5s", rising, instantAt(30_000), []observedPoint{pt(15_000, 2), pt(20_000, 4), pt(25_000, 4)}, nil},
	})
}

func TestNativeExtendedRateFamilyValues(t *testing.T) {
	runExtendedCases(t, []extendedCase{
		// A counter reset between the boundary samples: the left boundary is
		// interpolated as a plain series, the correction restores the lost count.
		{"smoothed rate over a reset", "rate(m[10s] smoothed)", reset, instantAt(15_000), []observedPoint{pt(15_000, 0.25)}, nil},
		{"smoothed increase over a reset", "increase(m[10s] smoothed)", reset, instantAt(15_000), []observedPoint{pt(15_000, 2.5)}, nil},
		{"smoothed rate range over a reset", "rate(m[10s] smoothed)", reset, rangeOf(10_000, 40_000, 5_000), []observedPoint{
			pt(10_000, 0.3), pt(15_000, 0.25), pt(20_000, 0.2), pt(25_000, 0.15), pt(30_000, 0.1), pt(35_000, 0.05)}, nil},
		// Stale markers are dropped before the boundary samples are chosen.
		{"smoothed rate across a stale marker", "rate(m[10s] smoothed)", staleMid, instantAt(20_000), []observedPoint{pt(20_000, 0.1)}, nil},
		{"smoothed rate across a stale marker 2", "rate(m[10s] smoothed)", staleMid, instantAt(25_000), []observedPoint{pt(25_000, 0.05)}, nil},
		{"smoothed increase across a stale marker", "increase(m[10s] smoothed)", staleMid, instantAt(20_000), []observedPoint{pt(20_000, 1)}, nil},
		{"smoothed delta across a stale marker", "delta(m[10s] smoothed)", staleMid, instantAt(20_000), []observedPoint{pt(20_000, 1)}, nil},
		{"smoothed delta across a stale marker 2", "delta(m[10s] smoothed)", staleMid, instantAt(25_000), []observedPoint{pt(25_000, 0.5)}, nil},
		{"smoothed rate range across a stale marker", "rate(m[10s] smoothed)", staleMid, rangeOf(10_000, 40_000, 5_000), []observedPoint{
			pt(10_000, 0.1), pt(15_000, 0.1), pt(20_000, 0.1), pt(25_000, 0.05)}, nil},
		// A lone sample inside the window yields a zero delta, not an empty result.
		{"smoothed rate of a lone sample", "rate(m[10s] smoothed)", lone, instantAt(15_000), []observedPoint{pt(15_000, 0)}, nil},
		{"smoothed delta of a lone sample", "delta(m[10s] smoothed)", lone, instantAt(15_000), []observedPoint{pt(15_000, 0)}, nil},
		{"smoothed rate range of a lone sample", "rate(m[10s] smoothed)", lone, rangeOf(10_000, 40_000, 5_000), []observedPoint{pt(15_000, 0), pt(20_000, 0)}, nil},
		{"anchored rate across a stale marker", "rate(m[10s] anchored)", staleMid, instantAt(20_000), []observedPoint{pt(20_000, 0.2)}, nil},
		{"anchored rate across a stale marker 2", "rate(m[10s] anchored)", staleMid, instantAt(25_000), []observedPoint{pt(25_000, 0.2)}, nil},
		{"anchored increase across a stale marker", "increase(m[10s] anchored)", staleMid, instantAt(25_000), []observedPoint{pt(25_000, 2)}, nil},
		{"anchored delta across a stale marker", "delta(m[10s] anchored)", staleMid, instantAt(20_000), []observedPoint{pt(20_000, 2)}, nil},
		{"anchored rate range across a stale marker", "rate(m[10s] anchored)", staleMid, rangeOf(10_000, 40_000, 5_000), []observedPoint{pt(20_000, 0.2), pt(25_000, 0.2)}, nil},
		{"anchored rate of a lone sample", "rate(m[10s] anchored)", lone, instantAt(15_000), []observedPoint{pt(15_000, 0)}, nil},
		{"anchored delta of a lone sample", "delta(m[10s] anchored)", lone, instantAt(20_000), []observedPoint{pt(20_000, 0)}, nil},
		{"anchored rate range of a lone sample", "rate(m[10s] anchored)", lone, rangeOf(10_000, 40_000, 5_000), []observedPoint{pt(15_000, 0), pt(20_000, 0)}, nil},
		{"anchored rate range with a sample past the first window", "rate(m[10s] anchored)", sparse, rangeOf(10_000, 40_000, 5_000), []observedPoint{
			pt(10_000, 0), pt(15_000, 0.2), pt(20_000, 0.2), pt(25_000, 0.3), pt(30_000, 0.3)}, nil},
		// changes() under anchored counts from the sample at or before the window start.
		{"anchored changes across a stale marker", "changes(m[10s] anchored)", staleMid, instantAt(20_000), []observedPoint{pt(20_000, 1)}, nil},
		{"anchored changes across a stale marker 2", "changes(m[10s] anchored)", staleMid, instantAt(25_000), []observedPoint{pt(25_000, 1)}, nil},
	})
}

func TestNativeExtendedAnnotationRangeExcludesKeyword(t *testing.T) {
	runExtendedCases(t, []extendedCase{
		{"rate", "rate(m[10s] smoothed)", rising, instantAt(15_000), []observedPoint{pt(15_000, 0.15)}, []string{"PossibleNonCounterInfo@5-11"}},
		{"increase", "increase(m[10s] anchored)", rising, instantAt(15_000), []observedPoint{pt(15_000, 1)}, []string{"PossibleNonCounterInfo@9-15"}},
		{"keyword after offset", "rate(m[10s] offset 5s smoothed)", rising, instantAt(30_000), []observedPoint{pt(30_000, 0.25)}, []string{"PossibleNonCounterInfo@5-21"}},
		{"keyword before offset", "rate(m[10s] smoothed offset 5s)", rising, instantAt(30_000), []observedPoint{pt(30_000, 0.25)}, []string{"PossibleNonCounterInfo@5-30"}},
		{"keyword before @", "rate(m[10s] smoothed @ 20)", rising, instantAt(30_000), []observedPoint{pt(30_000, 0.2)}, []string{"PossibleNonCounterInfo@5-25"}},
	})
}

func TestNativeExtendedRejectedFunctionsFailDuringExecution(t *testing.T) {
	p := featureProfile(t, "promql-prometheus-3.13.5", extendedGate)
	for _, tc := range []struct {
		query string
		ok    bool
	}{
		{"count_over_time(m[10s] smoothed)", false}, {"count_over_time(m[10s] anchored)", false},
		{"changes(m[10s] smoothed)", false}, {"resets(m[10s] smoothed)", false},
		{"irate(m[10s] anchored)", false}, {"deriv(m[10s] smoothed)", false}, {"last_over_time(m[10s] anchored)", false},
		{"changes(m[10s] anchored)", true}, {"resets(m[10s] anchored)", true},
		{"rate(m[10s] smoothed)", true}, {"delta(m[10s] anchored)", true},
	} {
		// No series at all: the native engine rejects the call before it reads any.
		_, _, err := evalWith(t, p, tc.query, instantAt(20_000))
		var language *syntax.LanguageError
		if tc.ok {
			if err != nil {
				t.Fatalf("%s: %v", tc.query, err)
			}
			continue
		}
		if !errors.As(err, &language) || language.Code != "function.range-extension" || language.Category != "execution" {
			t.Fatalf("%s: want execution function.range-extension, got %+v", tc.query, err)
		}
	}
}

func TestNativeExtensionOnSubqueryIsAParseError(t *testing.T) {
	p := featureProfile(t, "promql-prometheus-3.13.5", extendedGate)
	for _, tc := range []struct {
		query      string
		start, end int
	}{
		{"m[30s:5s] smoothed", 0, 9},
		{"m[30s:5s] anchored", 0, 9},
		{"rate(m[30s:5s] smoothed)", 5, 14},
		{"rate(m[30s:5s] offset 5s anchored)", 5, 24},
	} {
		_, err := Parse(tc.query, p)
		var language *syntax.LanguageError
		if !errors.As(err, &language) || language.Code != "range.extension-subquery" || language.Range.StartByte != tc.start || language.Range.EndByte != tc.end {
			t.Fatalf("%s: %+v", tc.query, err)
		}
	}
}
