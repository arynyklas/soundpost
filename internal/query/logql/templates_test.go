// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"soundpost/internal/model"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/value"
)

func templateTestProfile() profile.Profile {
	return profile.Profile{ID: "logql-loki-3.5.2", Commit: "257d2f62bf8a81b44dea6fe88968d1d28c8e01e7", Identity: "unit", ConfigurationHash: "unit"}
}
func templateTestRuntime() TemplateRuntime {
	return TemplateRuntime{Now: func() time.Time { return time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC) }, Location: time.UTC}
}
func templateRender(t *testing.T, source string, input TemplateInput) (string, error) {
	t.Helper()
	c, e := CompileTemplate(source, templateTestProfile(), templateTestRuntime())
	if e != nil {
		return "", e
	}
	return c.Execute(context.Background(), input, value.NewBoundedAccount(64<<20))
}

// Omitting or accidentally enabling a helper must fail independently of its implementation.
func TestTemplateCatalogEqualsInventory(t *testing.T) {
	data, e := os.ReadFile("../../../conformance/query/audits/logql-template-evidence.json")
	if e != nil {
		t.Fatal(e)
	}
	var inventory struct {
		Whitelist []string `json:"whitelist"`
	}
	if e = json.Unmarshal(data, &inventory); e != nil {
		t.Fatal(e)
	}
	var names []string
	for _, s := range TemplateFunctions(templateTestProfile()) {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	sort.Strings(inventory.Whitelist)
	if strings.Join(names, "|") != strings.Join(inventory.Whitelist, "|") {
		t.Fatalf("catalog differs: %v", names)
	}
}
func TestTemplateControlAndPipelines(t *testing.T) {
	input := TemplateInput{Labels: model.Labels{{Name: "level", Value: "warn"}}}
	cases := []struct{ source, want string }{
		{`{{if eq .level "warn"}}{{.level | upper}}{{else}}ok{{end}}`, "WARN"},
		{`{{$x := "abc"}}{{with $x}}{{. | upper}}{{end}}`, "ABC"},
		{`{{range $k,$v := fromJson "{\"b\":2,\"a\":1}"}}{{$k}}={{$v}};{{end}}`, "a=1;b=2;"},
		{`{{range fromJson "[]"}}bad{{else}}empty{{end}}`, "empty"},
		{`{{.missing}}/{{if .missing}}bad{{else}}zero{{end}}`, "/zero"},
		{`{{"<tag>"}}`, "<tag>"},
		{`{{and false (div 1 0)}}/{{or "yes" (div 1 0)}}`, "false/yes"},
		{`{{range fromJson "[1,2,3]"}}{{if eq . 2.0}}{{continue}}{{end}}{{.}}{{if eq . 3.0}}{{break}}{{end}}{{end}}`, "13"},
		{`{{template "child" "x"}}{{define "child"}}{{. | upper}}{{end}}`, "X"},
	}
	for _, c := range cases {
		t.Run(c.source, func(t *testing.T) {
			got, e := templateRender(t, c.source, input)
			if e != nil || got != c.want {
				t.Fatalf("got %q error %v, want %q", got, e, c.want)
			}
		})
	}
}
func TestCurrentLineBuiltin(t *testing.T) {
	first, e := templateRender(t, `{{__line__ | upper}}`, TemplateInput{Line: "original"})
	if e != nil {
		t.Fatal(e)
	}
	got, e := templateRender(t, `{{__line__}}/{{__timestamp__ | unixEpochNanos}}`, TemplateInput{Line: first, Timestamp: model.UnixNano(-1)})
	if e != nil || got != "ORIGINAL/-1" {
		t.Fatalf("got %q error %v", got, e)
	}
}
func TestTemplateNowIsWallClock(t *testing.T) {
	got, e := templateRender(t, `{{now | date "2006-01-02"}}/{{__timestamp__ | date "2006-01-02"}}`, TemplateInput{Timestamp: model.UnixNano(978307200000000000)})
	if e != nil || got != "2026-11-03/2001-01-01" {
		t.Fatalf("got %q error %v", got, e)
	}
}
func TestTemplateCapabilitiesDenied(t *testing.T) {
	for _, name := range []string{"env", "expandenv", "readFile", "getHostByName", "dict", "list", "randAlphaNum", "dateInZone", "toJson", "uuidv4"} {
		if _, e := CompileTemplate("{{"+name+` "secret"}}`, templateTestProfile(), templateTestRuntime()); e == nil {
			t.Fatalf("enabled %s", name)
		}
	}
	for _, source := range []string{`{{.line.Method}}`, `{{call .level}}`, `{{(now).UnmarshalText "x"}}`} {
		got, e := templateRender(t, source, TemplateInput{Labels: model.Labels{{Name: "level", Value: "x"}, {Name: "line", Value: "private"}}})
		if e == nil || got != "" {
			t.Fatalf("capability executed: %q %v", got, e)
		}
		if strings.Contains(e.Error(), "private") {
			t.Fatal("raw input leaked")
		}
	}
}
func TestTemplateBudgetStopsWorkWithoutPartialLine(t *testing.T) {
	c, e := CompileTemplate(`prefix{{repeat 1000000000 "x"}}`, templateTestProfile(), templateTestRuntime())
	if e != nil {
		t.Fatal(e)
	}
	account := value.NewBoundedAccount(4096)
	got, e := c.Execute(context.Background(), TemplateInput{}, account)
	var limit *TemplateLimitError
	if !errors.As(e, &limit) || got != "" || account.Used() != 0 {
		t.Fatalf("got len=%d err=%v held=%d", len(got), e, account.Used())
	}
	c, e = CompileTemplate(`{{$a:=fromJson "[1,2,3,4,5,6,7,8,9,10]"}}{{range $a}}{{range $a}}{{range $a}}{{range $a}}{{range $a}}{{range $a}}{{range $a}}x{{end}}{{end}}{{end}}{{end}}{{end}}{{end}}{{end}}`, templateTestProfile(), templateTestRuntime())
	if e != nil {
		t.Fatal(e)
	}
	account = value.NewBoundedAccount(64 << 20)
	got, e = c.Execute(context.Background(), TemplateInput{}, account)
	if !errors.As(e, &limit) || got != "" || account.Used() != 0 {
		t.Fatalf("range not stopped: len=%d err=%v held=%d", len(got), e, account.Used())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, e = c.Execute(ctx, TemplateInput{}, account)
	if !errors.Is(e, context.Canceled) || got != "" {
		t.Fatalf("cancel: %q %v", got, e)
	}
}
func TestTemplateUnicodeEdition(t *testing.T) {
	got, e := templateRender(t, `{{upper "𐵰"}}/{{count "\\p{L}" "𐵰"}}`, TemplateInput{})
	if e != nil || got != "𐵰/0" {
		t.Fatalf("host Unicode escaped pin: %q %v", got, e)
	}
}
