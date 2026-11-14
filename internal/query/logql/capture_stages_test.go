// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
	"sort"
	"strings"
	"testing"
)

// runCaptureVector runs a pipeline over a stream {app="api"} with optional
// structured metadata sm, and returns the resulting line and the sorted
// name=value pairs (spaces inside a pair become underscores).
func runCaptureVector(t *testing.T, expr, line string, sm *string) (string, string) {
	t.Helper()
	e := LogEntry{Line: line, ID: model.ID{1}, Multiplicity: 1, StreamLabels: model.Labels{{Name: "app", Value: "api"}}}
	if sm != nil {
		e.StructuredMetadata = model.Labels{{Name: "sm", Value: *sm}}
	}
	account := value.NewBoundedAccount(16 << 20)
	r, err := RunPipeline(context.Background(), testPlan(t, expr), e, account)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Retained {
		t.Fatal("entry dropped")
	}
	got := make([]string, 0, len(r.Labels))
	for _, l := range r.Labels {
		got = append(got, strings.ReplaceAll(l.Name+"="+l.Value, " ", "_"))
	}
	sort.Strings(got)
	return r.Entry.Line, strings.Join(got, " ")
}

// TestCaptureStageLabels pins the capture stages (regexp, pattern, unpack).
// Vectors marked [native] restate a corpus observation of the reference; those
// marked [model] follow the shared label-builder rule (see captureWriter) where
// no observation constrains the corner.
func TestCaptureStageLabels(t *testing.T) {
	pre, empty := "pre", ""
	type vec struct {
		name, expr, line string
		sm               *string
		wantLine         string // "" means the line is unchanged
		want             string
	}
	vecs := []vec{
		// regexp: groups that did not take part in the match are empty labels.
		{"[native] alternative group that did not match is empty", `{app="api"}|regexp "(?P<a>x)|(?P<b>y)"`, `y`, nil, "", `a= app=api b=y`},
		{"[native] the other alternative is empty when the first matched", `{app="api"}|regexp "(?P<a>x)|(?P<b>y)"`, `xxyy`, &pre, "", `a=x app=api b= sm=pre`},
		{"[native] optional group that did not match is empty", `{app="api"}|regexp "(?P<a>\\d+)(?P<b>[a-z]+)?"`, `12`, &pre, "", `a=12 app=api b= sm=pre`},
		{"[native] two optional groups, none present", `{app="api"}|regexp "(?P<a>x)?(?P<b>y)?"`, `ab`, nil, "", `a= app=api b=`},
		{"[native] a line the expression does not match writes nothing", `{app="api"}|regexp "(?P<a>x)|(?P<b>y)"`, `ab`, &pre, "", `app=api sm=pre`},
		{"[native] a group that matched nothing is an empty label", `{app="api"}|regexp "(?P<a>)"`, `x`, nil, "", `a= app=api`},
		{"[native] a repeated group keeps its last iteration", `{app="api"}|regexp "(?P<x>a|b)+"`, `abc`, nil, "", `app=api x=b`},
		{"[native] unnamed groups write nothing", `{app="api"}|regexp "(\\w+) (?P<b>\\w+)"`, `a a`, &pre, "", `app=api b=a sm=pre`},
		// regexp: collisions.
		{"[native] stream name renames", `{app="api"}|regexp "(?P<app>\\w+)"`, `GET /a`, &pre, "", `app=api app_extracted=GET sm=pre`},
		{"[native] metadata is kept", `{app="api"}|regexp "(?P<sm>\\w+)"`, `GET /a`, &pre, "", `app=api sm=pre`},
		{"[native] empty metadata is kept", `{app="api"}|regexp "(?P<sm>\\w+)"`, `y`, &empty, "", `app=api sm=`},
		{"[native] name free of metadata is set", `{app="api"}|regexp "(?P<sm>\\w+)"`, `xy`, nil, "", `app=api sm=xy`},
		{"[native] a second regexp does not rewrite a parsed name", `{app="api"}|regexp "(?P<a>\\w+)"|regexp "(?P<a>\\d+)"`, `a=1`, &pre, "", `a=a app=api sm=pre`},
		{"[native] regexp after logfmt does not rewrite a parsed name", `{app="api"}|logfmt|regexp "(?P<level>\\w+)"`, `ts=1 level=info`, nil, "", `app=api level=info ts=1`},
		{"[native] regexp after logfmt adds a free name", `{app="api"}|logfmt|regexp "(?P<level>\\w+)"`, `a=1`, nil, "", `a=1 app=api level=a`},
		{"[model] a second renamed stream name is refused like any parsed name", `{app="api"}|regexp "(?P<app>\\w+)"|regexp "(?P<app>\\d+)"`, `a=1`, nil, "", `app=api app_extracted=a`},

		// pattern.
		{"[native] empty leading capture", `{app="api"}|pattern "<a> <b>"`, `  a b`, &pre, "", `a= app=api b=_a_b sm=pre`},
		{"[native] empty leading capture before a literal", `{app="api"}|pattern "<a>x<b>"`, `x=1 y=2`, nil, "", `a= app=api b==1_y=2`},
		{"[native] empty trailing capture", `{app="api"}|pattern "<a>é<b>"`, `é`, nil, "", `a= app=api b=`},
		{"[native] empty middle capture", `{app="api"}|pattern "<a> <b> <c>"`, `a  b`, &pre, "", `a=a app=api b= c=b sm=pre`},
		{"[native] missing literal ends the walk with the rest", `{app="api"}|pattern "<a> <b> <c>"`, `a b`, nil, "", `a=a app=api b=b`},
		{"[native] empty line captures nothing", `{app="api"}|pattern "<a> <b>"`, ``, nil, "", `app=api`},
		{"[native] leading literal must be a prefix", `{app="api"}|pattern "x<a>"`, `axb`, &pre, "", `app=api sm=pre`},
		{"[native] stream name renames", `{app="api"}|pattern "<app> <b>"`, `  a b`, nil, "", `app=api app_extracted= b=_a_b`},
		{"[native] metadata is kept", `{app="api"}|pattern "<sm> <b>"`, `x a`, &pre, "", `app=api b=a sm=pre`},
		{"[native] empty metadata is kept", `{app="api"}|pattern "<sm> <b>"`, `a b`, &empty, "", `app=api b=b sm=`},
		{"[native] name free of metadata is set, empty included", `{app="api"}|pattern "<sm> <b>"`, `  a b`, nil, "", `app=api b=_a_b sm=`},

		// unpack: line shapes.
		{"[native] empty line is left alone", `{app="api"}|unpack`, ``, nil, "", `app=api`},
		{"[native] array", `{app="api"}|unpack`, `[1,2]`, nil, "", `__error__=JSONParserErr __error_details__=expecting_json_object(6),_but_it_is_not app=api`},
		{"[native] scalar", `{app="api"}|unpack`, `5`, &pre, "", `__error__=JSONParserErr __error_details__=expecting_json_object(6),_but_it_is_not app=api sm=pre`},
		{"[native] null", `{app="api"}|unpack`, `null`, nil, "", `__error__=JSONParserErr __error_details__=expecting_json_object(6),_but_it_is_not app=api`},
		{"[native] leading space", `{app="api"}|unpack`, ` {"a":1}`, nil, "", `__error__=JSONParserErr __error_details__=expecting_json_object(6),_but_it_is_not app=api`},
		{"[native] leading tab", `{app="api"}|unpack`, "\t{\"a\":1}", nil, "", `__error__=JSONParserErr __error_details__=expecting_json_object(6),_but_it_is_not app=api`},
		{"[native] truncated object", `{app="api"}|unpack`, `{"a":`, nil, "", `__error__=JSONParserErr __error_details__=Malformed_JSON_error app=api`},
		{"[native] missing colon", `{app="api"}|unpack`, `{"a" 1}`, nil, "", `__error__=JSONParserErr __error_details__=Malformed_JSON_error app=api`},
		{"[native] trailing comma is accepted", `{app="api"}|unpack`, `{"a":1,}`, &pre, "", `app=api sm=pre`},
		{"[native] trailing bytes after the object are accepted", `{app="api"}|unpack`, `{"a":1}x`, &pre, "", `app=api sm=pre`},
		{"[native] trailing space is accepted", `{app="api"}|unpack`, `{"a":1} `, nil, "", `app=api`},
		// unpack: members.
		{"[native] string members are ignored without _entry", `{app="api"}|unpack`, `{"a":"1","b":"2"}`, nil, "", `app=api`},
		{"[native] _entry replaces the line and string members become labels", `{app="api"}|unpack`, `{"_entry":"inner line","a":"1"}`, nil, "inner line", `a=1 app=api`},
		{"[native] _entry may come last", `{app="api"}|unpack`, `{"a":"x","_entry":"l"}`, &pre, "l", `a=x app=api sm=pre`},
		{"[native] empty _entry empties the line", `{app="api"}|unpack`, `{"_entry":""}`, &pre, "-", `app=api sm=pre`},
		{"[native] non-string _entry is ignored: number", `{app="api"}|unpack`, `{"_entry":5}`, &pre, "", `app=api sm=pre`},
		{"[native] non-string _entry is ignored: null", `{app="api"}|unpack`, `{"_entry":null}`, nil, "", `app=api`},
		{"[native] non-string _entry is ignored: object", `{app="api"}|unpack`, `{"_entry":{"k":1}}`, nil, "", `app=api`},
		{"[native] non-string _entry is ignored: array", `{app="api"}|unpack`, `{"_entry":["x"]}`, nil, "", `app=api`},
		{"[native] member free of metadata is set", `{app="api"}|unpack`, `{"_entry":"a","sm":"b"}`, nil, "a", `app=api sm=b`},
		{"[model] member naming metadata is kept out", `{app="api"}|unpack`, `{"_entry":"a","sm":"b"}`, &pre, "a", `app=api sm=pre`},
		{"[model] member naming a stream label renames", `{app="api"}|unpack`, `{"_entry":"a","app":"zz"}`, nil, "a", `app=api app_extracted=zz`},
		{"[model] duplicate member keeps the last value, as the json stage does", `{app="api"}|unpack`, `{"_entry":"a","k":"1","k":"2"}`, nil, "a", `app=api k=2`},
		{"[model] a second unpack does not rewrite a parsed name", `{app="api"}|unpack|unpack`, `{"_entry":"{\"_entry\":\"b\",\"k\":\"2\"}","k":"1"}`, nil, "b", `app=api k=1`},
		{"[model] a scanner error after _entry keeps line and labels untouched", `{app="api"}|unpack`, `{"_entry":"a","k":"1","j":`, nil, "", `__error__=JSONParserErr __error_details__=Malformed_JSON_error app=api`},
		{"[model] escapes in _entry are decoded", `{app="api"}|unpack`, `{"_entry":"a\"b\u00e9"}`, nil, "a\"bé", `app=api`},
		// unpack in a chain.
		{"[native] json after unpack sees the unpacked line", `{app="api"}|unpack|json`, `{"_entry":"x"}`, nil, "x", `__error__=JSONParserErr __error_details__=Value_looks_like_object,_but_can't_find_closing_'}'_symbol app=api`},
		{"[native] unpack error replaces the json error", `{app="api"}|json|unpack`, `[1,2]`, nil, "", `__error__=JSONParserErr __error_details__=expecting_json_object(6),_but_it_is_not app=api`},
		{"[native] unpack feeds line_format", `{app="api"}|unpack|line_format "{{.a}}"`, `{"_entry":"inner line","a":"1"}`, nil, "1", `a=1 app=api`},
	}
	for _, v := range vecs {
		t.Run(v.name, func(t *testing.T) {
			line, labels := runCaptureVector(t, v.expr, v.line, v.sm)
			want := v.wantLine
			switch want {
			case "":
				want = v.line
			case "-":
				want = ""
			}
			if line != want {
				t.Fatalf("line=%q want=%q", line, want)
			}
			if labels != v.want {
				t.Fatalf("labels=%s want=%s", labels, v.want)
			}
		})
	}
}

// TestPatternCaptureShapes pins how pattern captures cut a line, independent of
// label collisions. The first six rows restate corpus observations; the rest
// follow the same walk (an empty remainder is still a capture) and are model.
func TestPatternCaptureShapes(t *testing.T) {
	cases := []struct {
		pattern, line string
		want          map[string]string
	}{
		{"<a> <b>", "a  b", map[string]string{"a": "a", "b": " b"}},
		{"<a> <b>", "  a b", map[string]string{"a": "", "b": " a b"}},
		{"<a> <b>", "a b c d", map[string]string{"a": "a", "b": "b c d"}},
		{"<a> <b>", "ab", map[string]string{"a": "ab"}},
		{"<a> <b>", "", map[string]string{}},
		{"<_> <a>", "a  b", map[string]string{"a": " b"}},
		{"x<a>", "x", map[string]string{"a": ""}},
		{"x<a>", "axb", map[string]string{}},
		{"<a>é<b>", "aéb", map[string]string{"a": "a", "b": "b"}},
		{"<a>,<b>,<c>", "a,", map[string]string{"a": "a", "b": ""}},
	}
	for _, c := range cases {
		p, err := parsePattern(c.pattern, true)
		if err != nil {
			t.Fatalf("%q: %v", c.pattern, err)
		}
		got, _ := p.match(c.line)
		if len(got) != len(c.want) {
			t.Fatalf("%q on %q: got %q want %q", c.pattern, c.line, got, c.want)
		}
		for k, v := range c.want {
			if g, ok := got[k]; !ok || g != v {
				t.Fatalf("%q on %q: %s=%q (present %v) want %q", c.pattern, c.line, k, g, ok, v)
			}
		}
	}
}
