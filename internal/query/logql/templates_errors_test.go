// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/query/value"
)

func TestTemplateLanguageDetailsAreNotDefaultDiagnostics(t *testing.T) {
	c, e := CompileTemplate(`{{duration "private-marker"}}`, templateTestProfile(), templateTestRuntime())
	if e != nil {
		t.Fatal(e)
	}
	got, e := c.Execute(context.Background(), TemplateInput{}, value.NewBoundedAccount(64<<20))
	var formatting *TemplateError
	if !errors.As(e, &formatting) || got != "" {
		t.Fatalf("expected formatting error, got=%q err=%v", got, e)
	}
	want := `template: line:1:2: executing "line" at <duration "private-marker">: error calling duration: time: invalid duration "private-marker"`
	if formatting.LanguageDetail() != want {
		t.Fatalf("language detail=%q want=%q", formatting.LanguageDetail(), want)
	}
	encoded, jerr := json.Marshal(formatting)
	if jerr != nil || strings.Contains(string(encoded), "private-marker") || strings.Contains(formatting.Error(), "private-marker") {
		t.Fatal("query-language detail leaked into safe default diagnostic/JSON")
	}
}
func TestTemplateNativeErrorFramesAndArityOrder(t *testing.T) {
	cases := []struct{ source, want string }{
		{`{{div 1 0}}`, `template: line:1:2: executing "line" at <div 1 0>: error calling div: runtime error: integer divide by zero`},
		{`{{upper 1}}`, `template: line:1:8: executing "line" at <1>: expected string; found 1`},
		{`{{upper "x" "y"}}`, `template: line:1:2: executing "line" at <upper>: wrong number of args for upper: want 1 got 2`},
		{`{{index "abc" 99}}`, `template: line:1:2: executing "line" at <index "abc" 99>: error calling index: index out of range: 99`},
		{`{{unixToTime "123"}}`, `template: line:1:2: executing "line" at <unixToTime "123">: error calling unixToTime: unable to parse time '123': %!w(<nil>)`},
	}
	for _, c := range cases {
		_, e := templateRender(t, c.source, TemplateInput{})
		var formatting *TemplateError
		if !errors.As(e, &formatting) || formatting.LanguageDetail() != c.want {
			t.Fatalf("%s: err=%v detail=%q want=%q", c.source, e, func() string {
				if formatting == nil {
					return ""
				}
				return formatting.LanguageDetail()
			}(), c.want)
		}
	}
	calls := 0
	runtime := TemplateRuntime{Now: func() time.Time { calls++; return time.Unix(0, 0) }, Location: time.UTC}
	c, e := CompileTemplate(`{{upper "x" (now)}}`, templateTestProfile(), runtime)
	if e != nil {
		t.Fatal(e)
	}
	_, e = c.Execute(context.Background(), TemplateInput{}, value.NewBoundedAccount(1<<20))
	if e == nil || calls != 0 {
		t.Fatalf("arity failure executed argument clock: %v calls=%d", e, calls)
	}
}
func TestTemplateLabelRootIsNativeLabel(t *testing.T) {
	c, e := compileLabelTemplate(`{{div 1 0}}`, templateTestProfile(), templateTestRuntime())
	if e != nil {
		t.Fatal(e)
	}
	_, e = c.Execute(context.Background(), TemplateInput{}, value.NewBoundedAccount(64<<20))
	var formatting *TemplateError
	want := `template: label:1:2: executing "label" at <div 1 0>: error calling div: runtime error: integer divide by zero`
	if !errors.As(e, &formatting) || formatting.LanguageDetail() != want {
		t.Fatalf("label detail=%v/%v want=%q", e, formatting, want)
	}
	c, e = compileLabelTemplate(`{{define "line"}}bad{{end}}`, templateTestProfile(), templateTestRuntime())
	if e != nil {
		t.Fatal(e)
	}
	got, e := c.Execute(context.Background(), TemplateInput{}, value.NewBoundedAccount(64<<20))
	if e != nil || got != "" {
		t.Fatalf("root definitions changed label execution: %q %v", got, e)
	}
}
func TestTemplateDetailAllocationFailsClosed(t *testing.T) {
	c, e := CompileTemplate(strings.Repeat(" ", 10000)+`{{div 1 0}}`, templateTestProfile(), templateTestRuntime())
	if e != nil {
		t.Fatal(e)
	}
	account := value.NewBoundedAccount(65536)
	got, e := c.Execute(context.Background(), TemplateInput{}, account)
	var limit *TemplateLimitError
	if !errors.As(e, &limit) || got != "" || account.Used() != 0 {
		t.Fatalf("detail memory failure downgraded/truncated: %q %v held=%d", got, e, account.Used())
	}
}

func TestTemplateComparisonNanUsesPinnedBuiltins(t *testing.T) {
	got, e := templateRender(t, `{{$n:=float64 "NaN"}}{{lt $n 1.0}}/{{le $n 1.0}}/{{gt $n 1.0}}/{{ge $n 1.0}}/{{eq nil 1}}`, TemplateInput{})
	if e != nil || got != "false/false/true/true/false" {
		t.Fatalf("pinned comparison definitions: %q %v", got, e)
	}
}
func TestTemplateNowPreservesClockValue(t *testing.T) {
	stamp := time.Now()
	c, e := CompileTemplate(`{{(now).String}}`, templateTestProfile(), TemplateRuntime{Now: func() time.Time { return stamp }, Location: time.UTC})
	if e != nil {
		t.Fatal(e)
	}
	got, e := c.Execute(context.Background(), TemplateInput{}, value.NewBoundedAccount(1<<20))
	if e != nil || got != stamp.String() {
		t.Fatalf("clock location/monotonic value was rewritten: %q %v want=%q", got, e, stamp.String())
	}
}

func TestTemplateClosedByteAndCastEdges(t *testing.T) {
	cases := []struct{ source, want string }{
		{`{{index "a" 0 | int}}/{{index "a" 0 | float64}}`, "97/97"},
		{`{{int " 1 "}}/{{float64 " 1 "}}/{{int "1."}}/{{int "1.0."}}`, "0/0/0/1"},
		{`{{int "9223372036854775808"}}/{{float64 "1e999"}}/{{int (float64 "NaN")}}`, "0/0/-9223372036854775808"},
		{`{{printf "%x" (trunc 1 "é")}}/{{printf "%x" (substr 1 2 "é")}}`, "c3/a9"},
		{`{{range (__timestamp__).AppendFormat nil "ab"}}{{int .}};{{end}}`, "97;98;"},
		{`{{eq nil ((__timestamp__).AppendFormat nil "")}}`, "true"},
	}
	for _, c := range cases {
		got, e := templateRender(t, c.source, TemplateInput{})
		if e != nil || got != c.want {
			t.Fatalf("closed scalar edge: %q %v want=%q", got, e, c.want)
		}
	}
	for _, source := range []string{`{{bytes " 1 KB"}}`, `{{bytes "1 unknown"}}`} {
		_, e := templateRender(t, source, TemplateInput{})
		var formatting *TemplateError
		if !errors.As(e, &formatting) || formatting.LanguageDetail() == "" || strings.Contains(formatting.LanguageDetail(), "LogQL template execution failed") {
			t.Fatalf("primitive detail was not preserved: %v", e)
		}
	}
}

// Parent native round1 observed -1ns -> -1ms, not truncating division's zero.
func TestTemplateUnixEpochMillisUsesFloor(t *testing.T) {
	for _, c := range []struct{ source, want string }{
		{`{{(__timestamp__).Add -1 | unixEpochMillis}}`, "-1"},
		{`{{unixToTime "9999999999" | unixEpochMillis}}`, "9999999999000"},
		{`{{(__timestamp__).Add -1000001 | unixEpochMillis}}`, "-2"},
		{`{{(__timestamp__).Add -1000000 | unixEpochMillis}}`, "-1"},
		{`{{(__timestamp__).Add 999999 | unixEpochMillis}}`, "0"},
	} {
		got, e := templateRender(t, c.source, TemplateInput{})
		if e != nil || got != c.want {
			t.Fatalf("millisecond floor %s: %q %v want=%q", c.source, got, e, c.want)
		}
	}
}
func TestTemplateMissingMapChildPreservesTypedNil(t *testing.T) {
	source := `{{index . "missing"}}/{{(fromJson "{}").missing.child}}`
	_, e := templateRender(t, source, TemplateInput{})
	var formatting *TemplateError
	want := `template: line:1:34: executing "line" at <"{}">: nil pointer evaluating interface {}.child`
	if !errors.As(e, &formatting) || formatting.LanguageDetail() != want || formatting.SemanticCode() != "template.field-method" {
		t.Fatalf("missing-map chain err=%v detail=%v want=%q", e, formatting, want)
	}
	for _, source := range []string{`{{(fromJson "{\"x\":null}").x.child}}`, `{{(fromJson "{}").missing.child "unused"}}`} {
		_, e := templateRender(t, source, TemplateInput{})
		if !errors.As(e, &formatting) || !strings.Contains(formatting.LanguageDetail(), "nil pointer evaluating interface {}.child") {
			t.Fatalf("typed nil chain accepted: %s %v", source, e)
		}
	}
	for _, c := range []struct{ source, want string }{{`{{.missing}}`, ""}, {`{{(fromJson "{}").missing}}`, "<no value>"}, {`{{(fromJson "null").child}}`, "<no value>"}, {`{{$v := (fromJson "{}").missing}}{{$v.child}}`, "<no value>"}} {
		got, e := templateRender(t, c.source, TemplateInput{})
		if e != nil || got != c.want {
			t.Fatalf("nil boundary %s: %q %v want=%q", c.source, got, e, c.want)
		}
	}
}
