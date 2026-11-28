// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// The rows below restate observations of the lock-pinned Loki 3.5.2 oracle
// (testdata/native-logql-wave2-observations.json in internal/conformance/query
// holds the full recorded rows; the ids are given per row). start is -1 where
// the reference reports no position.

func TestApproxTopKParameterGrammarIsTheTopKGrammar(t *testing.T) {
	p := profileWithGate(t, "approx_topk")
	const tail = `,count_over_time({app="api"}[2s]))`
	for _, c := range []struct {
		param, code string
		start       int
	}{
		{`-1`, "syntax.unexpected-token", 14}, {`+1`, "syntax.unexpected-token", 14}, {`1+1`, "syntax.unexpected-token", 15},
		{`(1)`, "syntax.unexpected-token", 15}, {`vector(1)`, "syntax.unexpected-token", 21}, {`"1"`, "syntax.unexpected-token", 12},
		{`-1.5`, "syntax.unexpected-token", 16}, {`-1+2`, "syntax.unexpected-token", 16},
		{`0`, "function.arguments", -1}, {`1.5`, "function.arguments", -1}, {`2.0`, "function.arguments", -1},
		{`1e0`, "function.arguments", -1}, {`0x2`, "function.arguments", -1}, {`1_0`, "function.arguments", -1},
		{`99999999999999999999`, "function.arguments", -1},
	} {
		q := "approx_topk(" + c.param + tail
		_, err := parseCheck(t, q, p)
		var language *syntax.LanguageError
		if !errors.As(err, &language) || language.Code != c.code {
			t.Fatalf("%s: err=%v want %s", q, err, c.code)
		}
		if c.start >= 0 && language.Range.StartByte != c.start {
			t.Fatalf("%s: start=%d want %d", q, language.Range.StartByte, c.start)
		}
	}
	for _, q := range []string{`approx_topk(1` + tail, `approx_topk(02` + tail, `approx_topk(2,sum by (host)(count_over_time({app="api"}[2s])))`} {
		if _, err := parseCheck(t, q, p); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func TestBinaryModifiersAreAcceptedWherePinnedEngineAcceptsThem(t *testing.T) {
	p := testProfile(t)
	const a, w = `count_over_time({app="api"}[2s])`, `count_over_time({app="web"}[2s])`
	for _, q := range []string{
		// set operators ignore the cardinality and its include list (wave2-group-m-and-on-gl ...)
		a + ` and on() group_left ` + w, a + ` or on(host) group_right(app) ` + w, a + ` unless ignoring(app) group_left ` + w,
		// bool is ignored off comparisons (wave2-group-m-plus-bool, wave2-group2-m-and-bool ...)
		a + ` + bool ` + w, a + ` * bool 2`, `2 / bool ` + a, a + ` and bool ` + w, a + ` or bool on(host) ` + w, `1 + bool 2`,
		// repeated and on()-overlapping include labels (wave2-group-m-gl-dup, m-gr-overlap)
		a + ` * on(host) group_left(app,app) ` + w, a + ` * on(host) group_right(host) ` + w, a + ` * on(host) group_left(host) ` + w,
		// matching clauses against scalar operands (wave2-group3-i-sc-on-gl, wave2-group4-i-ss-on)
		a + ` * on(host) group_left 2`, `1 + on() group_left 2`, `1 + on(host) 2`, `1 + ignoring(host) group_right(x) 2`,
	} {
		if _, err := parseCheck(t, q, p); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// A group modifier is only grammatical after on(...)/ignoring(...): it is an
	// unexpected token at the keyword (wave2-group2-m-gl-bare, m-bool-gl, m-gl-on).
	for _, c := range []struct {
		q     string
		start int
	}{
		{a + ` * group_left ` + w, 35}, {a + ` * group_right ` + w, 35}, {a + ` * group_left(app) ` + w, 35},
		{a + ` + group_left 2`, 35}, {a + ` * bool group_left ` + w, 40}, {a + ` * group_left on(host) ` + w, 35},
	} {
		_, err := parseCheck(t, c.q, p)
		var language *syntax.LanguageError
		if !errors.As(err, &language) || language.Code != "syntax.unexpected-token" || language.Range.StartByte != c.start {
			t.Fatalf("%s: %v want unexpected token at %d", c.q, err, c.start)
		}
	}
}

func streamRow(id byte, at int64, app, host, line string) scan.LogRow {
	row := metricRow(id, at, line)
	row.Record.StreamLabels = model.Labels{{Name: "app", Value: app}, {Name: "host", Value: host}}
	return row
}

func evalSeries(t *testing.T, q string, s *metricSource, at int64) []value.Series {
	t.Helper()
	a := value.NewBoundedAccount(32 << 20)
	r, _, err := Evaluate(context.Background(), metricPlan(t, q, value.Evaluation{Instant: true, Time: model.UnixNano(at)}), s, a)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	defer a.Release(value.ResultBytes(r))
	return append([]value.Series(nil), r.Vector...)
}

func TestSetOperatorsIgnoreGroupModifiersAndBoolIsIgnoredOnArithmetic(t *testing.T) {
	// The recorded oracle rows use these seven entries (release-logql-met fixture).
	s := &metricSource{rows: []scan.LogRow{
		streamRow(1, 1e9, "api", "a", "n=1"), streamRow(2, 1.5e9, "api", "a", "n=2"), streamRow(3, 1e9, "api", "b", "n=3"),
		streamRow(4, 0.5e9, "web", "a", "n=4"), streamRow(5, 1.2e9, "web", "a", "n=5"), streamRow(6, 1.8e9, "web", "a", "n=6"), streamRow(7, 1.1e9, "web", "c", "n=7"),
	}}
	const a, w = `count_over_time({app="api"}[2s])`, `count_over_time({app="web"}[2s])`
	values := func(q string) map[string]float64 {
		out := map[string]float64{}
		for _, v := range evalSeries(t, q, s, 2e9) {
			out[value.Label(v.Labels, "app")+"/"+value.Label(v.Labels, "host")] = math.Float64frombits(uint64(v.Samples[0].Float))
		}
		return out
	}
	same := func(q, plain string) {
		t.Helper()
		got, want := values(q), values(plain)
		if len(got) != len(want) {
			t.Fatalf("%s = %v, want %v (%s)", q, got, want, plain)
		}
		for k, v := range want {
			if got[k] != v {
				t.Fatalf("%s = %v, want %v (%s)", q, got, want, plain)
			}
		}
	}
	// wave2-group-m-and-on-gl: both api series survive (the one side is not swapped).
	if got := values(a + ` and on() group_left ` + w); len(got) != 2 || got["api/a"] != 2 || got["api/b"] != 1 {
		t.Fatalf("and on() group_left: %v", got)
	}
	same(a+` and on(host) group_right(app) `+w, a+` and on(host) `+w)
	same(a+` or on(host) group_left(app,app) `+w, a+` or on(host) `+w)
	same(a+` unless on(host) group_right `+w, a+` unless on(host) `+w)
	same(a+` and bool on(host) `+w, a+` and on(host) `+w)
	// wave2-group-m-plus-bool-scalar: bool on arithmetic is the plain operation.
	same(a+` * bool 2`, a+` * 2`)
	same(a+` + bool on(host) group_left `+w, a+` + on(host) group_left `+w)
	if got := values(a + ` * on(host) group_right(host) ` + w); got["web/a"] != 6 || len(got) != 1 {
		t.Fatalf("overlapping group_right include: %v", got)
	}
}

func TestZeroLengthRangeSelectsNothingExceptAbsent(t *testing.T) {
	s := &metricSource{rows: []scan.LogRow{metricRow(1, 1e9, "n=2"), metricRow(2, 1.5e9, "n=6")}}
	for _, q := range []string{
		`count_over_time({app="api"}[0s])`, `rate({app="api"}[0s])`, `bytes_over_time({app="api"}[0s])`,
		`sum_over_time({app="api"}|logfmt|unwrap n[0s])`, `quantile_over_time(0.5,{app="api"}|logfmt|unwrap n[0s])`,
		`sum(count_over_time({app="api"}[0s]))`, `count_over_time({app="api"}[0s] offset 1s)`, `count_over_time({app="api"}[0ms])`,
	} {
		// An entry exactly at the evaluation instant is outside the empty window (wave2-zero-i-*).
		for _, at := range []int64{1.5e9, 2e9} {
			if got := evalSeries(t, q, s, at); len(got) != 0 {
				t.Fatalf("%s at %d selected %v", q, at, got)
			}
		}
	}
	// absent_over_time reports 1 with the equality matchers as labels (wave2-zero-i-absent).
	got := evalSeries(t, `absent_over_time({app="api"}[0s])`, s, 1.5e9)
	if len(got) != 1 || value.Label(got[0].Labels, "app") != "api" || math.Float64frombits(uint64(got[0].Samples[0].Float)) != 1 {
		t.Fatalf("absent_over_time over an empty window: %v", got)
	}
	// Only a negative range is refused, and the lexer never produces one.
	p := testProfile(t)
	e, err := Parse(`count_over_time({app="api"}[0s0s])`, p)
	if err == nil {
		_, _, err = Check(e, p)
	}
	var language *syntax.LanguageError
	if !errors.As(err, &language) || language.Code != "syntax.duration" {
		t.Fatalf("0s0s: %v", err)
	}
}
