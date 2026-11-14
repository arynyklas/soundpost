// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// Hand-authored from the obligation rule text and the Go text/template, time and
// strconv documentation; see release_logql_families_test.go.

func relTemplateCases(t *testing.T, in TemplateInput, cases []struct{ source, want string }) {
	t.Helper()
	for _, c := range cases {
		if got, err := templateRender(t, c.source, in); err != nil || got != c.want {
			t.Fatalf("%s: got %q err %v want %q", c.source, got, err, c.want)
		}
	}
}
func relTemplateFails(t *testing.T, in TemplateInput, sources ...string) {
	t.Helper()
	for _, s := range sources {
		if got, err := templateRender(t, s, in); err == nil {
			t.Fatalf("%s rendered %q", s, got)
		}
	}
}

func TestReleaseLogQLTemplateCapabilities(t *testing.T) {
	in := TemplateInput{Line: "line", Labels: model.Labels{{Name: "level", Value: "warn"}}}
	relTemplateCases(t, in, []struct{ source, want string }{
		{`{{and true (not false)}}/{{or false "x"}}/{{not true}}`, "true/x/false"},
		{`{{eq .level "warn"}}/{{ne 1 2}}/{{lt 1 2}}/{{le 2 2}}/{{gt 3 2}}/{{ge 2 3}}`, "true/true/true/true/true/false"},
		{`{{len .level}}/{{slice .level 1 3}}/{{index (fromJson "[10,20]") 1}}`, "4/ar/20"},
		{`{{print "a" 1}}/{{printf "%05.1f|%q" 3.14159 .level}}`, `a1/003.1|"warn"`},
		{`{{println "a" 1}}`, "a 1\n"},
		{`{{html "<a&b>"}}/{{urlquery "a b&c"}}/{{js "'x'"}}`, `&lt;a&amp;b&gt;/a+b%26c/\'x\'`},
		{`{{with .level}}{{.}}!{{end}}/{{if eq .level "warn"}}w{{else}}o{{end}}`, "warn!/w"},
		{`{{$m := fromJson "{\"a\":[1,2]}"}}{{range $k, $v := $m}}{{$k}}{{index $v 1}}{{end}}`, "a2"},
		{`{{$x := 3}}{{if gt $x 2}}big{{else}}small{{end}}`, "big"},
		{`{{and false (div 1 0)}}/{{or "yes" (div 1 0)}}`, "false/yes"},
	})
	// No environment, network, filesystem, randomness or crypto helpers exist, and a
	// function-valued call target is never supplied.
	relTemplateFails(t, in,
		`{{env "HOME"}}`, `{{expandenv "$HOME"}}`, `{{getHostByName "localhost"}}`, `{{readFile "/etc/passwd"}}`,
		`{{randAlphaNum 3}}`, `{{sha256sum "x"}}`, `{{call .level}}`)
}

func TestReleaseLogQLPrimitiveTemplateVersion(t *testing.T) {
	in := TemplateInput{Line: "line", Labels: model.Labels{{Name: "level", Value: "warn"}}}
	relTemplateCases(t, in, []struct{ source, want string }{
		{`{{range 3}}{{.}}{{end}}`, "012"},
		{`{{.missing}}/{{if .missing}}bad{{else}}zero{{end}}`, "/zero"},
		{`{{and false (div 1 0)}}/{{or "yes" (div 1 0)}}`, "false/yes"},
		{`{{slice "abc" 1 2}}/{{index "abc" 1}}`, "b/98"},
		{`{{$m := fromJson "{\"a\":{\"b\":[1,2,3]}}"}}{{range $i, $v := $m.a.b}}{{$i}}{{$v}};{{end}}`, "01;12;23;"},
	})
	relTemplateFails(t, in,
		`{{range $i, $v := 3}}{{$v}}{{end}}`,       // range over an integer permits one variable
		`{{(fromJson "{}").missing.child}}`,        // nil intermediate access
		`{{index (fromJson "[1]") 5}}`,             // builtin index out of range
		`{{slice "abc" 2 1}}`,                      // builtin slice with inverted bounds
		`{{eq 1 1.5}}`,                             // incompatible comparison kinds
		`{{div 1 0}}`,                              // helper return error
		`{{template "absent"}}`,                    // undefined template
		`{{break}}`,                                // control action outside a loop
		`{{range 3}}{{end}}{{.level.nope.deeper}}`, // field of a string
	)
}

func TestReleaseLogQLPrimitiveTimeSemantics(t *testing.T) {
	// 1700000000s is 2023-11-14T22:13:20Z, a Tuesday.
	in := TemplateInput{Timestamp: 1700000000123456789, Labels: model.Labels{{Name: "level", Value: "warn"}}}
	relTemplateCases(t, in, []struct{ source, want string }{
		{`{{(__timestamp__).UnixNano}}/{{(__timestamp__).Year}}/{{(__timestamp__).Month.String}}/{{(__timestamp__).Weekday}}`, "1700000000123456789/2023/November/Tuesday"},
		{`{{date "2006-01-02T15:04:05.000000000Z07:00" __timestamp__}}`, "2023-11-14T22:13:20.123456789Z"},
		{`{{date "Mon Jan 2" (toDate "2006-01-02" "2024-02-29")}}`, "Thu Feb 29"},
		{`{{toDate "2006-01-02" "nonsense"}}`, "0001-01-01 00:00:00 +0000 UTC"},
		{`{{date "15:04 MST" (toDateInZone "2006-01-02 15:04" "Nowhere/Land" "2024-06-01 12:00")}}`, "12:00 UTC"},
		{`{{date "2006-01-02T15:04:05Z07:00" (toDateInZone "2006-01-02 15:04:05" "UTC" "2024-02-29 12:30:45")}}`, "2024-02-29T12:30:45Z"},
	})
	// Before the epoch the nanoseconds stay exact.
	pre := TemplateInput{Timestamp: -1}
	relTemplateCases(t, pre, []struct{ source, want string }{
		{`{{date "2006-01-02T15:04:05.000000000Z07:00" __timestamp__}}`, "1969-12-31T23:59:59.999999999Z"},
	})
}
