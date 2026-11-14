// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"math"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// Hand-authored from the obligation rule text; see release_logql_families_test.go.

type relPipelineCase struct {
	name, query, line string
	stream            []string
	wantRetained      bool
	wantLine          string
	want              map[string]string
	absent            []string
}

func relCheckPipeline(t *testing.T, cases []relPipelineCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stream := c.stream
			if stream == nil {
				stream = []string{"app", "api"}
			}
			r := run(t, c.query, relEntry(c.line, stream...))
			if r.Retained != c.wantRetained {
				t.Fatalf("retained=%v want %v", r.Retained, c.wantRetained)
			}
			if !c.wantRetained {
				return
			}
			if r.Entry.Line != c.wantLine {
				t.Fatalf("line=%q want %q", r.Entry.Line, c.wantLine)
			}
			for k, v := range c.want {
				if !relHas(r.Labels, k) || lookup(r.Labels, k) != v {
					t.Fatalf("label %s=%q want %q (labels %v)", k, lookup(r.Labels, k), v, r.Labels)
				}
			}
			for _, k := range c.absent {
				if relHas(r.Labels, k) {
					t.Fatalf("label %s present: %v", k, r.Labels)
				}
			}
		})
	}
}

func TestReleaseLogQLParserStages(t *testing.T) {
	relCheckPipeline(t, []relPipelineCase{
		{name: "json flattens and sanitizes", query: `{app="api"}|json`, line: `{"user":{"name":"ann","id":7},"ok":true,"app":"web","tags":["a","b"],"a-b":1}`,
			wantRetained: true, wantLine: `{"user":{"name":"ann","id":7},"ok":true,"app":"web","tags":["a","b"],"a-b":1}`,
			want: map[string]string{"user_name": "ann", "user_id": "7", "ok": "true", "app": "api", "app_extracted": "web", "a_b": "1"}, absent: []string{"tags"}},
		{name: "json malformed keeps entry and error", query: `{app="api"}|json`, line: `{bad`, wantRetained: true, wantLine: `{bad`, want: map[string]string{"__error__": "JSONParserErr", "app": "api"}},
		{name: "json expression paths", query: `{app="api"}|json first="items[0].name", n="items[1].id"`, line: `{"items":[{"name":"x"},{"id":3}]}`,
			wantRetained: true, wantLine: `{"items":[{"name":"x"},{"id":3}]}`, want: map[string]string{"first": "x", "n": "3"}},
		{name: "json structured value kept as string", query: `{app="api"}|json items`, line: `{"items":[1,2]}`, wantRetained: true, wantLine: `{"items":[1,2]}`, want: map[string]string{"items": "[1,2]"}},
		{name: "logfmt quoted values", query: `{app="api"}|logfmt`, line: `level=warn msg="hello world" code=500 empty=`,
			wantRetained: true, wantLine: `level=warn msg="hello world" code=500 empty=`, want: map[string]string{"level": "warn", "msg": "hello world", "code": "500"}, absent: []string{"empty"}},
		{name: "logfmt keep-empty", query: `{app="api"}|logfmt --keep-empty`, line: `level=warn empty=`, wantRetained: true, wantLine: `level=warn empty=`, want: map[string]string{"level": "warn", "empty": ""}},
		{name: "logfmt strict records failure", query: `{app="api"}|logfmt --strict`, line: `a="unterminated`, wantRetained: true, wantLine: `a="unterminated`, want: map[string]string{"__error__": "LogfmtParserErr"}},
		{name: "logfmt expression selects fields", query: `{app="api"}|logfmt lvl="level", code="code"`, line: `level=warn code=500 x=1`,
			wantRetained: true, wantLine: `level=warn code=500 x=1`, want: map[string]string{"lvl": "warn", "code": "500"}, absent: []string{"x", "level"}},
		{name: "pattern named captures", query: `{app="api"}|pattern "<ip> <_> <path> <status>"`, line: `10.0.0.1 GET /index 200`,
			wantRetained: true, wantLine: `10.0.0.1 GET /index 200`, want: map[string]string{"ip": "10.0.0.1", "path": "/index", "status": "200"}, absent: []string{"_"}},
		{name: "pattern initial literal anchors", query: `{app="api"}|pattern "GET <path>"`, line: `x GET /a`, wantRetained: true, wantLine: `x GET /a`, absent: []string{"path"}},
		{name: "pattern initial wildcard relaxes", query: `{app="api"}|pattern "<_> GET <path>"`, line: `x GET /a`, wantRetained: true, wantLine: `x GET /a`, want: map[string]string{"path": "/a"}},
		{name: "pattern no match is not a filter failure", query: `{app="api"}|pattern "prefix <code>"`, line: `unmatched`, wantRetained: true, wantLine: `unmatched`, absent: []string{"code"}},
		{name: "regexp named captures", query: `{app="api"}|regexp "(?P<method>\\w+) (?P<path>/\\S+)"`, line: `GET /items 200`,
			wantRetained: true, wantLine: `GET /items 200`, want: map[string]string{"method": "GET", "path": "/items"}},
		{name: "regexp no match survives", query: `{app="api"}|regexp "(?P<code>[0-9]+)"`, line: `nodigits`, wantRetained: true, wantLine: `nodigits`, absent: []string{"code"}},
		{name: "line regex filter drops what regexp parser keeps", query: `{app="api"}|~"[0-9]+"`, line: `nodigits`, wantRetained: false},
		{name: "unpack restores entry", query: `{app="api"}|unpack`, line: `{"_entry":"hello world","region":"north","code":"7"}`,
			wantRetained: true, wantLine: "hello world", want: map[string]string{"region": "north", "code": "7"}, absent: []string{"_entry"}},
		{name: "unpack invalid json keeps the line", query: `{app="api"}|unpack`, line: `plain text`, wantRetained: true, wantLine: "plain text", want: map[string]string{"__error__": "JSONParserErr"}},
		{name: "unpack then json parses the restored line", query: `{app="api"}|unpack|json`, line: `{"_entry":"{\"a\":\"1\"}","stream":"x"}`,
			wantRetained: true, wantLine: `{"a":"1"}`, want: map[string]string{"stream": "x", "a": "1"}},
	})
	if _, err := parseCheck(t, `{app="api"}|regexp "(\\w+)"`, testProfile(t)); err == nil || languageCode(t, err) != "regexp.capture-required" {
		t.Fatalf("regexp parser without a named capture: %v", err)
	}
}

func TestReleaseLogQLFilterStages(t *testing.T) {
	relCheckPipeline(t, []relPipelineCase{
		{name: "ip v4 cidr hit", query: `{app="api"}|=ip("192.168.0.0/16")`, line: `conn from 192.168.4.7 ok`, wantRetained: true, wantLine: `conn from 192.168.4.7 ok`},
		{name: "ip v4 cidr miss", query: `{app="api"}|=ip("192.168.0.0/16")`, line: `conn from 10.1.1.1 ok`, wantRetained: false},
		{name: "ip v6 cidr", query: `{app="api"}|=ip("2001:db8::/32")`, line: `peer=[2001:db8::8]`, wantRetained: true, wantLine: `peer=[2001:db8::8]`},
		{name: "ip negation", query: `{app="api"}!=ip("192.168.0.0/16")`, line: `conn from 192.168.4.7 ok`, wantRetained: false},
		{name: "ip range inclusive upper end", query: `{app="api"}|logfmt|addr=ip("10.0.0.1-10.0.0.9")`, line: `addr=10.0.0.9`, wantRetained: true, wantLine: `addr=10.0.0.9`},
		{name: "ip range beyond upper end", query: `{app="api"}|logfmt|addr=ip("10.0.0.1-10.0.0.9")`, line: `addr=10.0.0.10`, wantRetained: false},
		{name: "label filter numeric and string", query: `{app="api"}|logfmt|status>=400 and method="GET"`, line: `status=503 method=GET`, wantRetained: true, wantLine: `status=503 method=GET`},
		{name: "label filter numeric fails", query: `{app="api"}|logfmt|status>=400 and method="GET"`, line: `status=200 method=GET`, wantRetained: false},
		{name: "absent label is empty string", query: `{app="api"}|missing=""`, line: `x`, wantRetained: true, wantLine: `x`},
		{name: "duration comparison", query: `{app="api"}|logfmt|d>1s`, line: `d=1500ms`, wantRetained: true, wantLine: `d=1500ms`},
		{name: "duration comparison miss", query: `{app="api"}|logfmt|d>1s`, line: `d=500ms`, wantRetained: false},
		{name: "bytes comparison", query: `{app="api"}|logfmt|size>1KiB`, line: `size=2KiB`, wantRetained: true, wantLine: `size=2KiB`},
		{name: "bytes comparison is strict", query: `{app="api"}|logfmt|size>2KiB`, line: `size=2KiB`, wantRetained: false},
		{name: "conversion failure labels error", query: `{app="api"}|logfmt|status>400`, line: `status=abc`, wantRetained: true, wantLine: `status=abc`, want: map[string]string{"__error__": "LabelFilterErr"}},
		{name: "existing error is preserved", query: `{app="api"}|json|status>400 or app="api"`, line: `{bad`, wantRetained: true, wantLine: `{bad`, want: map[string]string{"__error__": "JSONParserErr"}},
		{name: "parenthesized disjunction", query: `{app="api"}|logfmt|a="1" and (b="9" or c="3")`, line: `a=1 b=2 c=3`, wantRetained: true, wantLine: `a=1 b=2 c=3`},
		{name: "parenthesized disjunction miss", query: `{app="api"}|logfmt|a="1" and (b="9" or c="9")`, line: `a=1 b=2 c=3`, wantRetained: false},
		{name: "substring filter", query: `{app="api"}|="GET"!="health"|~"[0-9]{3}"`, line: `GET /items 200`, wantRetained: true, wantLine: `GET /items 200`},
		{name: "negation complements", query: `{app="api"}|="GET"!="health"`, line: `GET /health 200`, wantRetained: false},
		{name: "regex is a search not a full match", query: `{app="api"}|~"[0-9]+"`, line: `prefix 44 suffix`, wantRetained: true, wantLine: `prefix 44 suffix`},
		{name: "anchored regex", query: `{app="api"}|~"^[0-9]+$"`, line: `prefix 44 suffix`, wantRetained: false},
		{name: "chained filters intersect", query: `{app="api"}|="a"|="b"`, line: `a only`, wantRetained: false},
		{name: "same stage or is a disjunction", query: `{app="api"}|="request" or "response"`, line: `response finished`, wantRetained: true, wantLine: `response finished`},
		{name: "pattern filter uses literal spans", query: `{app="api"}|>"<_> /items <_>"`, line: `POST /items 201`, wantRetained: true, wantLine: `POST /items 201`},
		{name: "pattern filter is not a regex", query: `{app="api"}|>"<_> /it.ms <_>"`, line: `POST /items 201`, wantRetained: false},
		{name: "negated pattern filter", query: `{app="api"}!>"<_> health <_>"`, line: `GET health ok`, wantRetained: false},
	})
	for _, bad := range []struct{ query, code string }{
		{`{app="api"}|=ip("192.168.0.300")`, "ip.pattern-invalid"},
		{`{app="api"}|~"("`, "regex.invalid"},
	} {
		if _, err := parseCheck(t, bad.query, testProfile(t)); err == nil || languageCode(t, err) != bad.code {
			t.Fatalf("%s: want %s got %v", bad.query, bad.code, err)
		}
	}
}

func TestReleaseLogQLMutationStages(t *testing.T) {
	colored := "\x1b[31merror\x1b[0m: \x1b[1;32mok\x1b[0m done"
	relCheckPipeline(t, []relPipelineCase{
		{name: "decolorize strips control sequences only", query: `{app="api"}|decolorize`, line: colored, wantRetained: true, wantLine: "error: ok done", want: map[string]string{"app": "api"}},
		{name: "decolorize keeps ordinary brackets", query: `{app="api"}|decolorize`, line: "[31m not a control sequence [0m", wantRetained: true, wantLine: "[31m not a control sequence [0m"},
		{name: "drop by name and value", query: `{app="api"}|logfmt|drop level, host="b"`, line: `level=warn host=a msg=hi`, wantRetained: true, wantLine: `level=warn host=a msg=hi`,
			want: map[string]string{"host": "a", "msg": "hi", "app": "api"}, absent: []string{"level"}},
		{name: "drop matcher without match keeps label", query: `{app="api"}|logfmt|drop level="info"`, line: `level=warn host=a`, wantRetained: true, wantLine: `level=warn host=a`, want: map[string]string{"level": "warn", "host": "a"}},
		{name: "keep retains selected", query: `{app="api"}|logfmt|keep level`, line: `level=warn host=a`, wantRetained: true, wantLine: `level=warn host=a`, want: map[string]string{"level": "warn"}, absent: []string{"host", "app"}},
		{name: "keep leaves error labels", query: `{app="api"}|json|keep app`, line: `not json`, wantRetained: true, wantLine: `not json`, want: map[string]string{"__error__": "JSONParserErr", "app": "api"}},
		{name: "drop handles error label explicitly", query: `{app="api"}|json|drop __error__`, line: `not json`, wantRetained: true, wantLine: `not json`, want: map[string]string{"app": "api"}, absent: []string{"__error__", "__error_details__"}},
		{name: "label_format rename removes source", query: `{app="api"}|logfmt|label_format lvl=level`, line: `level=warn host=a`, wantRetained: true, wantLine: `level=warn host=a`,
			want: map[string]string{"lvl": "warn", "host": "a"}, absent: []string{"level"}},
		{name: "label_format template keeps referenced labels", query: `{app="api"}|logfmt|label_format msg="{{.level}}/{{.host}}"`, line: `level=warn host=a`, wantRetained: true, wantLine: `level=warn host=a`,
			want: map[string]string{"msg": "warn/a", "level": "warn", "host": "a"}},
		{name: "rename before the first template is visible to it", query: `{app="api"}|logfmt|label_format x=a,y="{{.a}}"`, line: `a=1`, wantRetained: true, wantLine: `a=1`, want: map[string]string{"x": "1", "y": ""}, absent: []string{"a"}},
		{name: "templates share one snapshot", query: `{app="api"}|logfmt|label_format y="{{.a}}",x=a,z="{{.a}}"`, line: `a=1`, wantRetained: true, wantLine: `a=1`, want: map[string]string{"x": "1", "y": "1", "z": "1"}, absent: []string{"a"}},
		{name: "stages consume the previous line in order", query: `{app="api"}|json|line_format "got {{.a}}"|="got 1"`, line: `{"a":1}`, wantRetained: true, wantLine: "got 1", want: map[string]string{"a": "1"}},
		{name: "filter before parser sees no parsed label", query: `{app="api"}|status="200"|logfmt`, line: `ok status=200`, wantRetained: false},
		{name: "filter after parser sees parsed label", query: `{app="api"}|="ok"|logfmt|status="200"`, line: `ok status=200`, wantRetained: true, wantLine: `ok status=200`, want: map[string]string{"status": "200"}},
		{name: "parser failure attaches an error instead of rejecting", query: `{app="api"}|json|="not"`, line: `not json`, wantRetained: true, wantLine: `not json`, want: map[string]string{"__error__": "JSONParserErr"}},
		{name: "filter after line_format matches formatted bytes", query: `{app="api"}|line_format "x{{.app}}"|="xapi"`, line: `line`, wantRetained: true, wantLine: "xapi"},
		{name: "failed filter cannot be undone by later formatting", query: `{app="api"}|="zzz"|line_format "zzz"`, line: `line`, wantRetained: false},
	})
	for _, bad := range []struct{ query, code string }{
		{`{app="api"}|label_format a=b,a=c`, "label-format.duplicate"},
		{`{app="api"}|label_format __error__="x"`, "label-format.reserved"},
	} {
		if _, err := parseCheck(t, bad.query, testProfile(t)); err == nil || languageCode(t, err) != bad.code {
			t.Fatalf("%s: want %s got %v", bad.query, bad.code, err)
		}
	}
	for _, bad := range []string{`{app="api"}|drop`, `{app="api"}|keep`, `{app="api"}|decolorize "x"`} {
		if _, err := parseCheck(t, bad, testProfile(t)); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
}

func TestReleaseLogQLLexicalAndUnwrapStages(t *testing.T) {
	relCheckPipeline(t, []relPipelineCase{
		{name: "double quotes decode escapes", query: `{app="api"}|="a\tb"`, line: "a\tb", wantRetained: true, wantLine: "a\tb"},
		{name: "double quotes decode escapes miss", query: `{app="api"}|="a\tb"`, line: `a\tb`, wantRetained: false},
		{name: "backticks keep content raw", query: "{app=\"api\"}|=`a\\tb`", line: `a\tb`, wantRetained: true, wantLine: `a\tb`},
		{name: "backticks do not decode", query: "{app=\"api\"}|=`a\\tb`", line: "a\tb", wantRetained: false},
		{name: "multibyte literal", query: `{app="api"}|="héllo wörld"`, line: "say héllo wörld", wantRetained: true, wantLine: "say héllo wörld"},
	})
	for _, bad := range []string{`{app="api"}|="\q"`, `{app="api"}|="unterminated`, `{app="api"}|="a" trailing`, `count_over_time({app="api"}[1x])`} {
		if _, err := parseCheck(t, bad, testProfile(t)); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
	typed, err := parseCheck(t, `count_over_time({app="api"}[1h30m])`, testProfile(t))
	if err != nil || typed.Type != TypeVector {
		t.Fatalf("composite duration: %v", err)
	}
	// unwrap: byte sizes and durations convert to floats; invalid values attach SampleExtractionErr.
	for _, c := range []struct {
		query, line string
		want        float64
	}{
		{`sum_over_time({app="api"}|logfmt|unwrap bytes(size)[1m])`, `size=2KiB`, 2048},
		{`sum_over_time({app="api"}|logfmt|unwrap duration_seconds(d)[1m])`, `d=1500ms`, 1.5},
		{`sum_over_time({app="api"}|logfmt|unwrap duration(d)[1m])`, `d=2s`, 2},
		{`sum_over_time({app="api"}|logfmt|unwrap n[1m])`, `n=2.5`, 2.5},
	} {
		r := run(t, c.query, relEntry(c.line, "app", "api"))
		if !r.Retained || r.Unwrapped == nil || *r.Unwrapped != c.want {
			t.Fatalf("%s %q: %+v", c.query, c.line, r.Unwrapped)
		}
	}
	r := run(t, `sum_over_time({app="api"}|logfmt|unwrap duration_seconds(d)[1m])`, relEntry(`d=bogus`, "app", "api"))
	if !r.Retained || lookup(r.Labels, "__error__") != "SampleExtractionErr" {
		t.Fatalf("invalid duration: %+v", r.Labels)
	}
	// A post-unwrap error filter removes the failure; without it the metric query fails.
	if r = run(t, `sum_over_time({app="api"}|logfmt|unwrap n|__error__=""[1m])`, relEntry(`n=abc`, "app", "api")); r.Retained {
		t.Fatal("error filter after unwrap kept the failure")
	}
	rows := relFixture()[:0]
	rows = append(rows, relRow(1, 1e9, "n=abc", "app", "api"), relRow(2, 12e8, "n=3", "app", "api"))
	if _, err := relEval(t, `sum_over_time({app="api"}|logfmt|unwrap n[2s])`, rows, value.Evaluation{Instant: true, Time: 2e9}); err == nil {
		t.Fatal("unwrap failure reached the metric result")
	}
	q := `sum_over_time({app="api"}|logfmt|unwrap n|__error__=""[2s])`
	relWant(t, q, relInstant(t, q, rows), map[string]float64{"app=api": 3})
}

// Float parsing and string conversion follow the Go standard library the profile was built with.
func TestReleaseLogQLPrimitiveNumericAndStringSemantics(t *testing.T) {
	in := TemplateInput{Labels: model.Labels{{Name: "level", Value: "warn"}}}
	for _, c := range []struct{ source, want string }{
		{`{{float64 "0x1p-2"}}`, "0.25"},
		{`{{float64 "1e2"}}`, "100"},
		{`{{float64 "-0"}}`, "-0"},
		{`{{float64 "Inf"}}`, "+Inf"},
		{`{{float64 "nan"}}`, "NaN"},
		{`{{float64 "2.5e-1"}}`, "0.25"},
		{`{{printf "%q" "a\xffb"}}`, `"a\xffb"`},
		{`{{printf "%x" "é"}}`, "c3a9"},
	} {
		if got, err := templateRender(t, c.source, in); err != nil || got != c.want {
			t.Fatalf("%s: got %q err %v want %q", c.source, got, err, c.want)
		}
	}
	// The any-accepting cast coerces an unparsable string to zero; strict string parameters reject a non-string.
	if got, err := templateRender(t, `{{float64 "not-a-number"}}`, in); err != nil || got != "0" {
		t.Fatalf("float64 of garbage: %q %v", got, err)
	}
	for _, bad := range []string{`{{ToUpper 5}}`, `{{Replace "a" "a" "b" "x"}}`} {
		if got, err := templateRender(t, bad, in); err == nil {
			t.Fatalf("%s rendered %q", bad, got)
		}
	}
	// unwrap uses strconv.ParseFloat: signed zero and infinities keep their bits, overflow fails.
	for _, c := range []struct {
		line string
		bits uint64
		fail bool
	}{
		{`n=0x1p-2`, math.Float64bits(0.25), false},
		{`n=-0`, 0x8000000000000000, false},
		{`n=inf`, 0x7ff0000000000000, false},
		{`n=1e400`, 0, true},
		{`n=1,5`, 0, true},
	} {
		r := run(t, `sum_over_time({app="api"}|logfmt|unwrap n[1m])`, relEntry(c.line, "app", "api"))
		failed := lookup(r.Labels, "__error__") == "SampleExtractionErr"
		if failed != c.fail || (!c.fail && (r.Unwrapped == nil || math.Float64bits(*r.Unwrapped) != c.bits)) {
			t.Fatalf("%s: failed=%v unwrapped=%v", c.line, failed, r.Unwrapped)
		}
	}
}

// The regex engine is the pinned RE2-family engine: no lookaround or backreferences, empty-match
// progression and Unicode classes as documented, label matchers anchored but line filters searching.
func TestReleaseLogQLPrimitiveRegexpEngineIdentity(t *testing.T) {
	in := TemplateInput{Labels: model.Labels{{Name: "level", Value: "warn"}}}
	for _, c := range []struct{ source, want string }{
		{`{{count "a*" "aba"}}`, "2"},
		{`{{count "a*" ""}}`, "1"},
		{`{{count "\\p{L}" "é1ß"}}`, "2"},
		{`{{count "\\p{Lu}" "ÄöÖ"}}`, "2"},
		{`{{regexReplaceAll "(?P<x>a)" "aba" "${x}X"}}`, "aXbaX"},
		{`{{regexReplaceAll "a" "aba" "$$"}}`, "$b$"},
		{`{{regexReplaceAllLiteral "a" "aba" "${0}"}}`, "${0}b${0}"},
		{`{{regexReplaceAll "(?i)straße" "STRAẞE" "x"}}`, "x"},
	} {
		if got, err := templateRender(t, c.source, in); err != nil || got != c.want {
			t.Fatalf("%s: got %q err %v want %q", c.source, got, err, c.want)
		}
	}
	for _, bad := range []string{`{{regexReplaceAll "[" "abc" "x"}}`, `{{regexReplaceAll "(?=a)" "abc" "x"}}`, `{{regexReplaceAll "(a)\\1" "aa" "x"}}`, `{{regexReplaceAll "a**" "a" "x"}}`} {
		if got, err := templateRender(t, bad, in); err == nil {
			t.Fatalf("%s rendered %q", bad, got)
		}
	}
	// Whole-value label matching versus line searching.
	if r := run(t, `{app=~"ap"}|~"pi"`, relEntry("xpiy", "app", "api")); r.Retained {
		t.Fatal("label matcher was not anchored")
	}
	if r := run(t, `{app=~"ap."}|~"pi"`, relEntry("xpiy", "app", "api")); !r.Retained {
		t.Fatal("anchored label match plus searching line filter rejected")
	}
	if r := run(t, `{app="api"}|~"(?i)STRAßE"`, relEntry("straẞe", "app", "api")); !r.Retained {
		t.Fatal("simple case folding of ß/ẞ missed")
	}
	for _, bad := range []string{`{app="api"}|~"(?<=a)b"`, `{app="api"}|~"(a)\\1"`, `{app="api"}|~"a{2,1}"`} {
		if _, err := parseCheck(t, bad, testProfile(t)); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
}

// Case mappings and categories come from the Unicode 15.0.0 tables of the pinned compiler: characters
// added later (Garay, U+10D40..U+10D8F) are unmapped and not letters.
func TestReleaseLogQLPrimitiveUnicodeEdition(t *testing.T) {
	in := TemplateInput{Labels: model.Labels{{Name: "level", Value: "warn"}}}
	garayCapital, garaySmall := "\U00010D50", "\U00010D70"
	for _, c := range []struct{ source, want string }{
		{`{{upper "äbc"}}`, "ÄBC"},
		{`{{lower "ÄBC"}}`, "äbc"},
		{`{{upper "straße"}}`, "STRAßE"},
		{`{{lower "ΑΣ"}}`, "ασ"},
		{`{{upper "ǆ"}}`, "Ǆ"},
		{`{{lower "` + garayCapital + `"}}`, garayCapital},
		{`{{upper "` + garaySmall + `"}}`, garaySmall},
		{`{{ToLower "` + garayCapital + `"}}`, garayCapital},
		{`{{title "` + garaySmall + `x"}}`, garaySmall + "x"},
		{`{{count "\\p{L}" "` + garaySmall + `"}}`, "0"},
		{`{{count "\\p{Lu}" "` + garayCapital + `"}}`, "0"},
		{`{{count "(?i)` + garayCapital + `" "` + garaySmall + `"}}`, "0"},
	} {
		if got, err := templateRender(t, c.source, in); err != nil || got != c.want {
			t.Fatalf("%s: got %q err %v want %q", c.source, got, err, c.want)
		}
	}
	// The same text in a line filter and in a regexp parser.
	if r := run(t, `{app="api"}|~"\\p{L}"`, relEntry(garaySmall, "app", "api")); r.Retained {
		t.Fatal("post-Unicode-15 letter matched \\p{L}")
	}
	r := run(t, `{app="api"}|regexp "(?P<w>\\p{L}+)"`, relEntry("é"+garaySmall+"x", "app", "api"))
	if !r.Retained || lookup(r.Labels, "w") != "é" {
		t.Fatalf("category boundary: %+v", r.Labels)
	}
}
