// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// Expectations in this file are derived from the pinned Prometheus
// promql/parser sources (generated_parser.y grammar actions, lex.go scanNumber /
// acceptRemainingDuration / lexInsideBraces, parse.go checkAST and the setters)
// and from IEEE 754 arithmetic. They are never copied from owned-engine output.

const (
	gV310  = "promql-prometheus-3.1.0"
	gV3135 = "promql-prometheus-3.13.5"
	gdur   = "promql-duration-expr"
	gfill  = "promql-binop-fill-modifiers"
	gext   = "promql-extended-range-selectors"
	gexp   = "promql-experimental-functions"
)

func labelsFor(name string) model.Labels { return model.Labels{{Name: "__name__", Value: name}} }
func model64(ns int64) model.UnixNano    { return model.UnixNano(ns) }
func testCtx() context.Context           { return context.Background() }

func gProfile(ver string, features ...string) profile.Profile {
	p := profile.Profile{ID: "promql-prometheus-" + ver, ActiveFeatureSet: profile.FeatureSet{ID: "default", Enabled: features}}
	if ver == "3.1.0" {
		p.Commit = "7086161a93b262aa0949dbf2aba15a5a7b13e0a3"
	} else {
		p.Commit = "f497435984d1ca1d84cda5ed309387ac2eb1f8f6"
	}
	return p
}

// gParse parses and checks; it returns the checked type or the language error.
func gParse(p profile.Profile, text string) (ValueType, *syntax.LanguageError) {
	e, err := Parse(text, p)
	if err == nil {
		var typed TypedExpr
		typed, _, err = Check(e, p)
		if err == nil {
			return typed.Type, nil
		}
	}
	var le *syntax.LanguageError
	if !errors.As(err, &le) {
		panic("non-language error: " + err.Error())
	}
	return "", le
}

type gStart struct {
	ver      string // "" = both profiles
	features []string
	text     string
	start    int
}

func TestReleaseGrammarDiagnosticStarts(t *testing.T) {
	for _, tc := range []gStart{
		// scanNumber/lexNumberOrDuration/number(): the diagnostic starts at the number or duration token.
		{"", nil, "1e", 0}, {"", nil, "1e+", 0}, {"", nil, "1.2.3", 0}, {"", nil, "1__2", 0}, {"", nil, "1_", 0},
		{"", nil, "1e_1", 0}, {"", nil, "0x1.8p1", 0}, {"", nil, "0xG", 0}, {"", nil, "0b11", 0}, {"", nil, "0x", 0},
		{"", nil, "0x_", 0}, {"", nil, "1x", 0}, {"", nil, "1M", 0}, {"", nil, "0xFFFFFFFFFFFFFFFFF", 0}, {"", nil, "1e309", 0},
		{"", nil, "-1e309", 1}, {"", nil, "sum(foo) * 1e309", 11}, {"", nil, "5m1h", 0}, {"", nil, "1h1h", 0}, {"", nil, "1ms1s", 0},
		{"", nil, "foo[5x]", 4}, {"", nil, "foo[1h1h]", 4}, {"", nil, "foo[1x]", 4}, {"", nil, "foo[a]", 4},
		// lexStatements: an unmatched ) is a lexical error positioned after the paren.
		{"", nil, "foo)", 4}, {"", nil, "abs(foo))", 9}, {"", nil, ")", 1}, {"", nil, ")(", 1},
		{"", nil, "sum(rate(foo[5m]) / ignoring(job) bar))", 39},
		// lexInsideBraces and checkAST.
		{"", nil, `foo{a:b="c"}`, 5}, {"", nil, `foo{a=="x"}`, 6}, {"", nil, `foo{"a"}`, 0}, {"", nil, `foo{__name__="bar"}`, 0},
		// function_call_args: the trailing comma itself.
		{"", nil, "abs(foo,)", 7}, {"", nil, "sum(foo,)", 7}, {"", nil, "abs(foo,,)", 7},
		// grouping_label: the label token.
		{"", nil, `sum by ("") (foo)`, 8},
		// keywords are never metric names; modifier order.
		{"", nil, "foo > on(a) bool bar", 12}, {"", nil, "foo > ignoring(a) bool bar", 18},
		{"", nil, "foo + on() group_left() group_left() bar", 24}, {"", nil, "foo + group_left bar", 6},
		{"", nil, "bool", 0}, {"", nil, "on", 0}, {"", nil, "on + 1", 0}, {"", nil, "ignoring", 0}, {"", nil, "group_left + bar", 0}, {"", nil, "atan2 + 1", 0},
		// @, offset, range attachment.
		{"", nil, "foo @ --5", 7}, {"", nil, `foo @ "5"`, 6}, {"", nil, "foo @ NaN", 0}, {"", nil, "foo @ Inf", 0}, {"", nil, "foo @ -Inf", 0},
		{"", nil, "sum(rate(foo[5m] @ NaN))", 9}, {"", nil, "foo offset 1m offset 2m", 0}, {"", nil, "foo offset 5m @ 5 offset 6m", 0},
		{"", nil, "foo offset 5m [5m]", 14}, {"", nil, "sum(foo)[5m]", 8}, {"", nil, "(foo)[5m]", 5}, {"", nil, "foo[5m][5m]", 7},
		{"", nil, "foo[5m] offset 5m [5m]", 18},
		{"", nil, "foo offset foo", 11}, {"", nil, "foo offset 106752d", 11}, {"", nil, "foo offset -106752d", 12}, {"", nil, `foo offset "5m"`, 11},
		// 3.1.0 parseDuration rejects a zero duration token.
		{"3.1.0", nil, "foo offset 0s", 11}, {"3.1.0", nil, "foo[0s]", 4},
		// 3.13.5 duration-expression productions.
		{"3.13.5", nil, "foo[5m + 1m]", 4}, {"3.13.5", nil, "foo[(5m)]", 5},
		{"3.13.5", []string{gexp}, "foo offset min_of(1h, 30m)", 18}, {"3.13.5", []string{gexp}, "foo[10m:step()]", 8},
		{"3.13.5", []string{gdur}, "foo[1m % 0]", 7}, {"3.13.5", []string{gdur}, "foo[1m / 0]", 7}, {"3.13.5", []string{gdur}, "foo[step() / 0]", 11},
		{"3.13.5", []string{gdur}, "foo[min_of(1m, 2m, 3m)]", 17},
		{"3.13.5", []string{gext}, "foo[5m] anchored smoothed", 0}, {"3.13.5", nil, "sum(rate(foo[5m] smoothed))", 9},
		{"3.13.5", []string{gext}, "foo[5m:1m] smoothed", 0},
		{"3.13.5", []string{gfill}, "foo + fill(bar) baz", 11}, {"3.13.5", []string{gfill}, "foo + fill(0) fill_left(1) bar", 23},
		{"3.13.5", []string{gfill}, "foo + fill(0) on(job) bar", 14},
		{"3.13.5", nil, "foo + fill(0) bar", 0}, {"3.13.5", []string{gdur}, "foo + fill(0) bar", 0},
		{"3.13.5", nil, "foo[:1m]", 5}, {"3.13.5", nil, "foo[5m:1m:1m]", 9},
		{"3.13.5", []string{gexp}, "foo offset -step()", 11}, {"3.13.5", []string{gexp}, "foo offset +range()", 11},
		{"3.13.5", []string{gexp}, "foo offset -min_of(1h, 30m)", 11},
		{"3.1.0", nil, "foo offset --1m", 12}, {"3.1.0", nil, "foo offset +5m", 11},
		{"3.13.5", nil, "foo[1m == 2m]", 7},
		// an unknown function is reported when the call is reduced, before later tokens are read.
		{"", nil, "foo + nosuch(0) bar", 6}, {"3.1.0", nil, "foo + fill(0) bar", 6},
	} {
		vers := []string{tc.ver}
		if tc.ver == "" {
			vers = []string{"3.1.0", "3.13.5"}
		}
		for _, ver := range vers {
			_, le := gParse(gProfile(ver, tc.features...), tc.text)
			if le == nil {
				t.Errorf("%s %q %v: accepted", ver, tc.text, tc.features)
				continue
			}
			if le.Range.StartByte != tc.start {
				t.Errorf("%s %q %v: start %d want %d (%s: %s)", ver, tc.text, tc.features, le.Range.StartByte, tc.start, le.Category, le.SafeMessage)
			}
		}
	}
}

func TestReleaseGrammarNumberLiterals(t *testing.T) {
	for _, tc := range []struct {
		text string
		want float64
	}{
		{"0X_FF", 255}, {"1_024", 1024}, {"1_0", 10}, {"0x10", 16}, {".5E1", 5}, {"5.", 5}, {"1e-3", 0.001}, {"1.5E+2", 150},
		{"010", 8}, {"0777", 511}, // base-inferred int64 first: a leading zero is octal
		{"0x7FFFFFFFFFFFFFFF", 9223372036854775807}, {"9223372036854775808", 9223372036854775808},
		{"1h30m", 5400}, {"1w", 604800}, {"5m", 300}, {"1ms", 0.001}, {"2y", 63072000}, {"1d1h", 90000},
		{"inf", math.Inf(1)}, {"INF", math.Inf(1)}, {"Inf", math.Inf(1)},
	} {
		for _, ver := range []string{"3.1.0", "3.13.5"} {
			p := gProfile(ver)
			e, err := Parse(tc.text, p)
			if err != nil {
				t.Errorf("%s %q: %v", ver, tc.text, err)
				continue
			}
			n := e.(*Node)
			if n.Kind != "number" || n.FloatBits != math.Float64bits(tc.want) {
				t.Errorf("%s %q: kind %s value %v want %v", ver, tc.text, n.Kind, math.Float64frombits(n.FloatBits), tc.want)
			}
		}
	}
	e, err := Parse("nan", gProfile("3.13.5"))
	if err != nil || !math.IsNaN(math.Float64frombits(e.(*Node).FloatBits)) {
		t.Errorf("nan literal: %v", err)
	}
}

func TestReleaseGrammarCommentsAndNestedSigns(t *testing.T) {
	// After the first number inside brackets the pinned 3.13.5 lexer is back in lexStatements, where comments are legal.
	if typ, le := gParse(gProfile("3.13.5"), "foo[1m # c\n]"); le != nil || typ != Matrix {
		t.Errorf("comment inside range: type %q error %v", typ, le)
	}
	// duration_expr: unary_op duration_expr nests in 3.13.5 offsets; 3.1.0 allows one minus and a literal only.
	if typ, le := gParse(gProfile("3.13.5"), "foo offset --1m"); le != nil || typ != Vector {
		t.Errorf("3.13.5 nested sign: type %q error %v", typ, le)
	}
	if typ, le := gParse(gProfile("3.13.5", gdur), "foo offset -(-(1m + 30s))"); le != nil || typ != Vector {
		t.Errorf("3.13.5 nested paren sign: type %q error %v", typ, le)
	}
	// keywords match case-insensitively; their values keep the source spelling as names.
	for _, text := range []string{"SUM(foo)", "sum BY (a) (foo)", "foo AND bar", "foo + ON(a) GROUP_LEFT bar", "foo OFFSET 5m", "TOPK(1, foo)", "foo > BOOL 1"} {
		if _, le := gParse(gProfile("3.13.5"), text); le != nil {
			t.Errorf("%q: %v", text, le)
		}
	}
	if typ, le := gParse(gProfile("3.13.5"), "Sum"); le != nil || typ != Vector {
		t.Errorf("Sum as a metric name: type %q error %v", typ, le)
	}
	e, _ := Parse("SUM(foo)", gProfile("3.13.5"))
	if n := e.(*Node); n.Kind != "aggregate" || n.Text != "sum" {
		t.Errorf("SUM(foo) = %s %q", n.Kind, n.Text)
	}
}

func TestReleaseGrammarKeywordsAndMetricNames(t *testing.T) {
	for _, text := range []string{"by", "without", "offset", "start", "end", "sum", "and + or", "job:requests:rate5m + offset", "by + without"} {
		for _, ver := range []string{"3.1.0", "3.13.5"} {
			if typ, le := gParse(gProfile(ver), text); le != nil || typ != Vector {
				t.Errorf("%s %q: type %q error %v", ver, text, typ, le)
			}
		}
	}
	// fill, fill_left and fill_right are keywords only when followed by '(' and are ordinary names otherwise.
	for _, text := range []string{"fill + fill_left", "fill_right"} {
		if typ, le := gParse(gProfile("3.13.5", gfill), text); le != nil || typ != Vector {
			t.Errorf("%q: type %q error %v", text, typ, le)
		}
	}
}

func TestReleaseGrammarAtModifierForms(t *testing.T) {
	for _, ver := range []string{"3.1.0", "3.13.5"} {
		p := gProfile(ver)
		for _, tc := range []struct {
			text string
			typ  ValueType
			at   string
		}{
			{"foo @ 5m", Vector, "300"}, {"foo @ -5m", Vector, "-300"}, {"foo @ 1h30m", Vector, "5400"}, {"foo[5m] @ 5m", Matrix, "300"},
			{"foo @ 0x10", Vector, "16"}, {"foo @ +5", Vector, "+5"}, {"foo @ 1.5e3", Vector, "1.5e3"}, {"foo[5m:1m] @ 2m", Matrix, "120"},
		} {
			e, err := Parse(tc.text, p)
			if err != nil {
				t.Errorf("%s %q: %v", ver, tc.text, err)
				continue
			}
			typed, _, err := Check(e, p)
			if err != nil || typed.Type != tc.typ {
				t.Errorf("%s %q: type %q err %v", ver, tc.text, typed.Type, err)
			}
			if at := e.(*Node).At; at != tc.at {
				t.Errorf("%s %q: At %q want %q", ver, tc.text, at, tc.at)
			}
			// the formatted text must reparse to the same timestamp
			again, err := Parse(Format(e), p)
			if err != nil || again.(*Node).At != tc.at {
				t.Errorf("%s %q: format %q reparse At %v err %v", ver, tc.text, Format(e), again, err)
			}
		}
	}
}

func TestReleaseGrammarZeroNumericRange(t *testing.T) {
	// 3.1.0: the numeric seconds literal 0 is accepted for ranges and resolutions; the duration token 0s is not.
	p := gProfile("3.1.0")
	for _, text := range []string{"foo[0]", "foo[5m:0]", "foo[0:1m]"} {
		if typ, le := gParse(p, text); le != nil || (typ != Matrix) {
			t.Errorf("3.1.0 %q: type %q error %v", text, typ, le)
		}
	}
	for _, text := range []string{"foo[0s]", "foo[5m:0s]", "0s", "foo offset 0s"} {
		if _, le := gParse(p, text); le == nil {
			t.Errorf("3.1.0 %q accepted", text)
		}
	}
	// 3.13.5: positive_duration_expr rejects every literal <= 0, numeric or duration token.
	q := gProfile("3.13.5")
	for _, text := range []string{"foo[0]", "foo[0s]", "foo[5m:0]", "foo[5m:0s]"} {
		if _, le := gParse(q, text); le == nil {
			t.Errorf("3.13.5 %q accepted", text)
		} else if text == "foo[0]" && le.Range.StartByte != 4 {
			t.Errorf("3.13.5 %q start %d want 4", text, le.Range.StartByte)
		}
	}
	// matrixIterSlice with equal bounds still returns a sample exactly at the right endpoint.
	src := seriesSource{{Labels: nil, Samples: []value.Sample{sample(10e9, 1), sample(15e9, 2), sample(20e9, 3)}}}
	src[0].Labels = append(src[0].Labels, labelsFor("sig")...)
	for _, tc := range []struct {
		q    string
		at   int64
		want int
	}{{"count_over_time(sig[0])", 20e9, 1}, {"count_over_time(sig[0])", 17e9, 0}, {"count_over_time(sig[0] offset 5s)", 20e9, 1}, {"count_over_time(sig[0])", 15e9, 1}} {
		r, e := executeExpr(t, tc.q, value.Evaluation{Instant: true, Time: model64(tc.at)}, src)
		if e != nil {
			t.Fatalf("%s: %v", tc.q, e)
		}
		if len(r.Vector) != tc.want {
			t.Errorf("%s at %d: %d series want %d", tc.q, tc.at, len(r.Vector), tc.want)
		}
		if tc.want == 1 && math.Float64frombits(uint64(r.Vector[0].Samples[0].Float)) != 1 {
			t.Errorf("%s: count %v want 1", tc.q, math.Float64frombits(uint64(r.Vector[0].Samples[0].Float)))
		}
	}
}

func TestReleaseGrammarDurationExpressionFormat(t *testing.T) {
	p := gProfile("3.13.5", gdur)
	for _, text := range []string{
		"foo[max_of(1m, 2m)]", "foo offset min_of(1h, 30m)", "foo[10m:max_of(step(), 30s)]", "foo[(1m + 30s) * 2]",
		"sum(foo offset (1m * 2))", "foo[5m - 5m]", "foo offset -(5m * 2)", "foo[min_of(5m, 1h):min_of(1m, 30s)]",
		"foo[range() / 2:step()]", "sum_over_time(foo[step() * 4])", "foo[10m:step()] offset (range() / 2)", "foo offset (1h - 2h)",
		"foo[10m:min_of(step(), 30s)] offset max_of(1m, range())", "rate(foo[5m] offset (2 * 1h))", "foo[(5m)]", "foo offset (((1m)))",
	} {
		e, err := Parse(text, p)
		if err != nil {
			t.Errorf("%q: %v", text, err)
			continue
		}
		again, err := Parse(Format(e), p)
		if err != nil {
			t.Errorf("%q: formatted %q does not reparse: %v", text, Format(e), err)
			continue
		}
		if !reflect.DeepEqual(meaning(e), meaning(again)) {
			t.Errorf("%q: format %q changes the tree\n%+v\n%+v", text, Format(e), meaning(e), meaning(again))
		}
	}
}

func TestReleaseGrammarDurationLiteralsKeepTheirSpelling(t *testing.T) {
	p := gProfile("3.13.5", gdur)
	for _, text := range []string{"foo[max_of(1m, 2m)]", "foo[(1m + 30s) * 2]", "foo offset -(5m * 2)", "foo[10m:max_of(step(), 30s)]", "1h30m + 1w", "foo[min_of(5m, 1h):min_of(1m, 30s)]"} {
		e, err := Parse(text, p)
		if err != nil {
			t.Errorf("%q: %v", text, err)
			continue
		}
		if got := Format(e); got != text {
			t.Errorf("Format(%q) = %q", text, got)
		}
	}
}

func TestReleaseGrammarPrecedenceAndSignedValues(t *testing.T) {
	ev := value.Evaluation{Instant: true}
	for _, tc := range []struct {
		q    string
		want float64
	}{
		{"2 ^ 3 ^ 2", 512}, {"-2 ^ 2", -4}, {"2 ^ -1", 0.5}, {"1 + 2 * 3 ^ 2", 19}, {"10 - 2 - 3", 5}, {"2 * 3 % 4", 2}, {"(1 + 2) * 3", 9},
		{"1 + 1 == bool 2", 1}, {"5 > bool 3 == bool 1", 1}, {"1 < bool 2 + 5", 1}, {"2 ^ 3 ^ 2 + -2 ^ 2", 508}, {"7 % 4 * 2", 6}, {"8 / 4 / 2", 1},
		{"1 / -0", math.Inf(-1)}, {"1 / +0", math.Inf(1)}, {"-(-Inf)", math.Inf(1)}, {"+(-Inf)", math.Inf(-1)}, {"--1", 1}, {"-+-1", 1},
		{"0X_FF * 1_024 - 1e-3 + 010", 255*1024 - 0.001 + 8}, {"1h30m + 1w + 1ms", 5400 + 604800 + 0.001},
	} {
		for _, ver := range []string{"3.1.0", "3.13.5"} {
			p := executionProfile(t)
			if ver == "3.13.5" {
				p = trimProfile(t)
			}
			e, err := Parse(tc.q, p)
			if err != nil {
				t.Fatalf("%s %q: %v", ver, tc.q, err)
			}
			typed, _, err := Check(e, p)
			if err != nil {
				t.Fatalf("%s %q: %v", ver, tc.q, err)
			}
			plan, err := BuildPlan(typed, ev, p)
			if err != nil {
				t.Fatalf("%s %q: %v", ver, tc.q, err)
			}
			r, _, err := Evaluate(testCtx(), plan, seriesSource{}, value.NewBoundedAccount(1<<20))
			if err != nil {
				t.Fatalf("%s %q: %v", ver, tc.q, err)
			}
			got := math.Float64frombits(uint64(r.Scalar.Float))
			if got != tc.want && !(got == 0 && tc.want == 0) {
				t.Errorf("%s %q = %v want %v", ver, tc.q, got, tc.want)
			}
			if tc.q == "1 / -0" || tc.q == "1 / +0" {
				continue
			}
		}
	}
	neg, _ := Parse("-0", gProfile("3.13.5"))
	if !math.Signbit(math.Float64frombits(neg.(*Node).FloatBits)) && neg.(*Node).Kind == "number" {
		t.Error("-0 lost its sign")
	}
}

func TestReleaseGrammarStringEscapes(t *testing.T) {
	for _, tc := range []struct {
		text string
		want string
	}{
		{`"a\x41\101\u00e9\U0001F600\a\b\f\n\r\t\v\\\"z"`, "aAA\u00e9\U0001F600\a\b\f\n\r\t\v\\\"z"},
		{`'q\'x'`, "q'x"}, {"`raw\\n\nline`", "raw\\n\nline"}, {`"\000"`, "\x00"}, {`"\377"`, "\xff"}, {`"\uD7FF"`, "\ud7ff"}, {`"\uE000"`, "\ue000"}, {`"\U0010FFFF"`, "\U0010ffff"},
	} {
		for _, ver := range []string{"3.1.0", "3.13.5"} {
			typ, le := gParse(gProfile(ver), tc.text)
			if le != nil || typ != String {
				t.Errorf("%s %q: type %q error %v", ver, tc.text, typ, le)
				continue
			}
			e, _ := Parse(tc.text, gProfile(ver))
			if got := e.(*Node).Text; got != tc.want {
				t.Errorf("%s %q: decoded %q want %q", ver, tc.text, got, tc.want)
			}
		}
	}
	for _, text := range []string{`"\400"`, `"\uD800"`, `"\uDFFF"`, `"\U00110000"`, `"\x4"`, `"\u00e"`, `"\q"`, `"abc`, "\"a\nb\"", "`abc", `'abc`} {
		for _, ver := range []string{"3.1.0", "3.13.5"} {
			if _, le := gParse(gProfile(ver), text); le == nil {
				t.Errorf("%s %q accepted", ver, text)
			} else if le.Range.StartByte != 0 {
				t.Errorf("%s %q: start %d want 0", ver, text, le.Range.StartByte)
			}
		}
	}
}

func TestReleaseGrammarUnknownFunctionKeepsTypeCategory(t *testing.T) {
	for _, ver := range []string{"3.1.0", "3.13.5"} {
		_, le := gParse(gProfile(ver), "foo + nosuch(0) bar")
		if le == nil || le.Code != "function.unknown" || le.Category != "type" || le.Range.StartByte != 6 {
			t.Errorf("%s: %+v", ver, le)
		}
	}
}

func gExec(t *testing.T, p profile.Profile, q string, ev value.Evaluation, src seriesSource) (value.Result, error) {
	t.Helper()
	e, err := Parse(q, p)
	if err != nil {
		t.Fatalf("%q: %v", q, err)
	}
	typed, _, err := Check(e, p)
	if err != nil {
		t.Fatalf("%q: %v", q, err)
	}
	plan, err := BuildPlan(typed, ev, p)
	if err != nil {
		return value.Result{}, err
	}
	r, _, err := Evaluate(testCtx(), plan, src, value.NewBoundedAccount(1<<24))
	return r, err
}

func gValues(r value.Result) []float64 {
	var out []float64
	for _, s := range r.Matrix {
		for _, x := range s.Samples {
			out = append(out, math.Float64frombits(uint64(x.Float)))
		}
	}
	return out
}

// Duration expressions evaluate in binary64 seconds; step() is the query step and
// range() the outer query's end-start. A computed duration truncates seconds*1000 to
// whole milliseconds; zero or negative computed ranges and out-of-range magnitudes fail.
func TestReleaseGrammarDurationRuntime(t *testing.T) {
	p := resolvedProfile(t, "promql-prometheus-3.13.5", "ce434d8cff71b7083768816e1912e11d619b3bdbce5d9bf131b8ce79dc0ba238")
	src := seriesSource{{Labels: labelsFor("sig"), Samples: []value.Sample{sample(0, 1), sample(10e9, 2), sample(20e9, 3), sample(30e9, 4), sample(40e9, 5)}}}
	rng := value.Evaluation{Start: 20e9, End: 40e9, Step: 10e9}
	for _, tc := range []struct {
		q    string
		want []float64
	}{
		{"sum_over_time(sig[step() * 2])", []float64{5, 7, 9}},                // window 20s: (0,20], (10,30], (20,40]
		{"count_over_time(sig[min_of(step(), range())])", []float64{1, 1, 1}}, // min(10s, 20s) = 10s
		{"count_over_time(sig[max_of(step(), range())])", []float64{2, 2, 2}}, // max(10s, 20s) = 20s
		{"sum_over_time(sig[range() / 4 : step()])", []float64{3, 4, 5}},      // 5s window, 10s resolution: one point at t
		{"sum_over_time(sig[20s] offset (step() * 0 + 10s))", []float64{3, 5, 7}},
	} {
		r, err := gExec(t, p, tc.q, rng, src)
		if err != nil {
			t.Errorf("%q: %v", tc.q, err)
			continue
		}
		if got := gValues(r); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q = %v want %v", tc.q, got, tc.want)
		}
	}
	// a negative computed offset reads the future: offset -step() at t=20s selects the 30s sample.
	r, err := gExec(t, p, "sig offset -step()", rng, src)
	if err != nil || len(r.Matrix) != 1 || !reflect.DeepEqual(gValues(r), []float64{4, 5, 5}) {
		t.Errorf("offset -step(): %v %v", r, err)
	}
	// 10s/7 = 1428.57ms truncates to 1428ms: the sample at 18572ms is on the open left edge and is excluded.
	trunc := seriesSource{{Labels: labelsFor("sig"), Samples: []value.Sample{sample(18572e6, 100), sample(18573e6, 7)}}}
	r, err = gExec(t, p, "sum_over_time(sig[step() / 7])", value.Evaluation{Start: 20e9, End: 20e9, Step: 10e9}, trunc)
	if err != nil || !reflect.DeepEqual(gValues(r), []float64{7}) {
		t.Errorf("truncated millisecond window: %v %v", r, err)
	}
	// computed zero or negative ranges and out-of-range magnitudes are errors at evaluation time.
	for _, q := range []string{"sum_over_time(sig[step() - step()])", "sum_over_time(sig[range() - range() * 2])", "sig offset (9e9 * 2)", "sig offset -(9e9 * 2)"} {
		if _, err := gExec(t, p, q, rng, src); err == nil {
			t.Errorf("%q succeeded", q)
		}
	}
	// the zero literal divisor is a parse error for / and %; a nonliteral zero divisor is not.
	for _, q := range []string{"sig[step() / 0]", "sig[1m % 0]", "sig offset (1m / 0)"} {
		if _, le := gParse(gProfile("3.13.5", gdur), q); le == nil {
			t.Errorf("%q accepted", q)
		}
	}
	if typ, le := gParse(gProfile("3.13.5", gdur), "sig[1m / (1 - 1)]"); le != nil || typ != Matrix {
		t.Errorf("computed zero divisor: %q %v", typ, le)
	}
}

// An invalid RE2 matcher is a parse error positioned at its label; an invalid
// label_replace pattern is a named evaluation error, never a silent no-match;
// an empty grouping label name is invalid in both profiles.
func TestReleaseGrammarRegexAndLabelErrors(t *testing.T) {
	for _, ver := range []string{"3.1.0", "3.13.5"} {
		p := gProfile(ver)
		for _, tc := range []struct {
			text  string
			start int
		}{
			{`foo{job=~"("}`, 4}, {`sum(rate(foo{job=~"a(b"}[5m]))`, 13}, {`foo{a="x", job!~"[a-"}`, 11}, {`foo{job=~"a**"}`, 4}, {`foo{job=~"(?P<n>a"}`, 4},
		} {
			if _, le := gParse(p, tc.text); le == nil || le.Range.StartByte != tc.start {
				t.Errorf("%s %q: %+v want start %d", ver, tc.text, le, tc.start)
			}
		}
		for _, text := range []string{`foo{job=~"a(b|c)+"}`, `foo{job=~""}`, `foo{job!~"a|"}`, `sum by ("a-b", "测") (foo)`} {
			if _, le := gParse(p, text); le != nil {
				t.Errorf("%s %q: %v", ver, text, le)
			}
		}
		if _, le := gParse(p, `sum by ("") (foo)`); le == nil || le.Range.StartByte != 8 {
			t.Errorf("%s empty grouping label: %+v", ver, le)
		}
	}
	src := seriesSource{{Labels: labelsFor("foo"), Samples: []value.Sample{sample(0, 1)}}}
	_, err := executeExpr(t, `label_replace(foo, "dst", "$1", "src", "(.*")`, value.Evaluation{Instant: true, Time: 1e9}, src)
	var le *syntax.LanguageError
	if !errors.As(err, &le) || le.Code != "function.invalid-regex" {
		t.Errorf("label_replace with an invalid pattern: %v", err)
	}
	r, err := executeExpr(t, `label_replace(foo, "dst", "$1", "__name__", "(f)oo")`, value.Evaluation{Instant: true, Time: 1e9}, src)
	if err != nil || len(r.Vector) != 1 || value.Label(r.Vector[0].Labels, "dst") != "f" {
		t.Errorf("label_replace valid pattern: %+v %v", r, err)
	}
}
