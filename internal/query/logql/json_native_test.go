// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"errors"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"strings"
	"testing"
)

// Expected rows are copied verbatim from the Loki 3.5.2 reference observations
// of `{app="api"}|json` over malformed input.
func TestJSONStageMatchesReferenceMalformedObservations(t *testing.T) {
	rows := []struct {
		line, errKind, errDetails string
		labels                    map[string]string
	}{
		{"{broken", "JSONParserErr", "Value looks like object, but can't find closing '}' symbol", map[string]string{}},
		{"{\"a\":", "JSONParserErr", "Malformed JSON error", map[string]string{}},
		{"{\"a\":1", "JSONParserErr", "Value is array, but can't find closing ']' symbol", map[string]string{"a": "1"}},
		{"{\"a\" 1}", "JSONParserErr", "Malformed JSON error", map[string]string{}},
		{"[1,2", "JSONParserErr", "Value looks like object, but can't find closing '}' symbol", map[string]string{}},
		{"\"unterminated", "JSONParserErr", "Value looks like object, but can't find closing '}' symbol", map[string]string{}},
		{"nul", "JSONParserErr", "Value looks like object, but can't find closing '}' symbol", map[string]string{}},
		{"{\"a\":tru}", "JSONParserErr", "Unknown value type", map[string]string{}},
		{"{\"a\":1,}", "", "", map[string]string{"a": "1"}},
		{"{", "JSONParserErr", "Malformed JSON error", map[string]string{}},
		{"}", "JSONParserErr", "Value looks like object, but can't find closing '}' symbol", map[string]string{}},
		{"not json", "JSONParserErr", "Value looks like object, but can't find closing '}' symbol", map[string]string{}},
		{"{\"a\":\"x", "JSONParserErr", "Value is string, but can't find closing '\"' symbol", map[string]string{}},
		{"{\"a\":{\"b\":1}", "JSONParserErr", "Value is array, but can't find closing ']' symbol", map[string]string{"a_b": "1"}},
		{"{\"a\":[1,2}", "JSONParserErr", "Value is array, but can't find closing ']' symbol", map[string]string{}},
		{"{\"a\":1}}", "", "", map[string]string{"a": "1"}},
		{"{\"a\":1} trailing", "", "", map[string]string{"a": "1"}},
		{"{\"a\":01}", "", "", map[string]string{"a": "01"}},
		{"{\"a\":1e}", "", "", map[string]string{"a": "1e"}},
		{"{\"a\":\"\\x\"}", "", "", map[string]string{"a": ""}},
		{"{a:1}", "JSONParserErr", "Value looks like object, but can't find closing '}' symbol", map[string]string{}},
		{"{\"a\":1 \"b\":2}", "JSONParserErr", "Value looks like object, but can't find closing '}' symbol", map[string]string{"a": "1"}},
		{"[]", "JSONParserErr", "Value looks like object, but can't find closing '}' symbol", map[string]string{}},
		{"[1]", "JSONParserErr", "Value looks like object, but can't find closing '}' symbol", map[string]string{}},
		{"\"str\"", "JSONParserErr", "Value looks like object, but can't find closing '}' symbol", map[string]string{}},
		{"123", "JSONParserErr", "Value looks like object, but can't find closing '}' symbol", map[string]string{}},
		{"true", "JSONParserErr", "Value looks like object, but can't find closing '}' symbol", map[string]string{}},
		{"{\"a\":{\"b\":}}", "JSONParserErr", "Unknown value type", map[string]string{}},
		{"{\"a\":[}", "JSONParserErr", "Value is array, but can't find closing ']' symbol", map[string]string{}},
		{"{\"\":1}", "", "", map[string]string{"": "1"}},
		{"{\"a\":1,,\"b\":2}", "JSONParserErr", "Value looks like object, but can't find closing '}' symbol", map[string]string{"a": "1"}},
	}
	for _, row := range rows {
		result := run(t, `{app="api"}|json`, entry(row.line))
		if !result.Retained {
			t.Fatalf("%q dropped", row.line)
		}
		if got := lookup(result.Labels, "__error__"); got != row.errKind {
			t.Fatalf("%q __error__ = %q, want %q", row.line, got, row.errKind)
		}
		if got := lookup(result.Labels, "__error_details__"); got != row.errDetails {
			t.Fatalf("%q __error_details__ = %q, want %q", row.line, got, row.errDetails)
		}
		extra := map[string]string{}
		for _, l := range result.Labels {
			if l.Name != "app" && l.Name != "__error__" && l.Name != "__error_details__" {
				extra[l.Name] = l.Value
			}
		}
		if len(extra) != len(row.labels) {
			t.Fatalf("%q labels = %v, want %v", row.line, extra, row.labels)
		}
		for k, v := range row.labels {
			if got, ok := extra[k]; !ok || got != v {
				t.Fatalf("%q labels = %v, want %v", row.line, extra, row.labels)
			}
		}
	}
}

func TestJSONStageFlattensObjectsButNotArrays(t *testing.T) {
	r := run(t, `{app="api"}|json`, entry(`{"a":{"b-c":true,"d":[1,2]},"e":"x\u0041y","f":2.50}`))
	for k, want := range map[string]string{"a_b_c": "true", "e": "xAy", "f": "2.50"} {
		if got := lookup(r.Labels, k); got != want {
			t.Fatalf("%s = %q, want %q", k, got, want)
		}
	}
	if labelPresent(r.Labels, "a_d") || strings.Contains(lookup(r.Labels, "__error__"), "JSON") {
		t.Fatalf("array flattened or spurious error: %v", r.Labels)
	}
}

func TestLabelBooleanAndBindsTighterThanOr(t *testing.T) {
	e := entry(`{"n":"2","method":"POST","size":"1KiB"}`)
	for _, tc := range []struct {
		q    string
		want bool
	}{
		{`{app="api"}|json|n=2 or method="GET" and size>2KiB`, true},
		{`{app="api"}|json|n=2 or method="GET", size>2KiB`, true},
		{`{app="api"}|json|n=2 or method="GET" size>2KiB`, true},
		{`{app="api"}|json|(n=2 or method="GET") and size>2KiB`, false},
		{`{app="api"}|json|n=3 or method="GET" and size>2KiB`, false},
		{`{app="api"}|json|method="POST" and size>2KiB or n=3`, false},
		{`{app="api"}|json|method="POST" and size>2KiB or n=2`, true},
	} {
		if got := run(t, tc.q, e).Retained; got != tc.want {
			t.Fatalf("%s retained=%v want %v", tc.q, got, tc.want)
		}
	}
}

func TestJSONExtractionPathValidation(t *testing.T) {
	p := testProfile(t)
	for _, path := range []string{`a.b`, `a[0]`, `a[\"b\"]`, `a[\"b.c\"]`, `a[\"b\"][1].c`} {
		tree, err := Parse(`{app="api"}|json x="`+path+`"`, p)
		if err == nil {
			_, _, err = Check(tree, p)
		}
		if err != nil {
			t.Fatalf("valid path %s rejected: %v", path, err)
		}
	}
	for _, path := range []string{`payload[\"a]b\"]`, `[\"]\"]`} {
		tree, err := Parse(`{app="api"}|json x="`+path+`"`, p)
		if err == nil {
			_, _, err = Check(tree, p)
		}
		var diagnostic *syntax.LanguageError
		if !errors.As(err, &diagnostic) || diagnostic.Code != "syntax.unexpected-token" {
			t.Fatalf("path %s: err=%v", path, err)
		}
	}
}
