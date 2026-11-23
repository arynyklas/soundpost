// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package gitlab

import (
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

const hostile = "<img src=x onerror=alert(1)> [click](https://evil.example) *bold* _it_ `tick` # head | cell | \\ ![i](x)\nnext line\r\n- list\x00\x1b"

func TestLineEscapesEveryMarkupCharacterAndFlattensNewlines(t *testing.T) {
	got := Line(hostile)
	if strings.ContainsAny(got, "\n\r\x00\x1b") {
		t.Fatalf("control or newline survived: %q", got)
	}
	// Every markup character is preceded by a backslash.
	for i := range len(got) {
		if strings.IndexByte(escapes, got[i]) >= 0 && got[i] != '\\' {
			if i == 0 || got[i-1] != '\\' {
				t.Fatalf("unescaped %q at %d in %q", got[i], i, got)
			}
		}
	}
	for _, escaped := range []string{`\<img`, `\[click\]\(`, `\*bold\*`, "\\`tick\\`", `\| cell \|`, `\!`} {
		if !strings.Contains(got, escaped) {
			t.Errorf("%q not escaped in %q", escaped, got)
		}
	}
	if Line("plain text 42") != "plain text 42" {
		t.Errorf("plain text changed: %q", Line("plain text 42"))
	}
	if Line("\xff\xfe") == "\xff\xfe" {
		t.Error("invalid UTF-8 survived")
	}
}

func TestQuoteKeepsEveryLineInsideTheBlock(t *testing.T) {
	got := Quote("first\n# heading\r\n<script>x</script>\n\n- item")
	for i, l := range strings.Split(got, "\n") {
		if !strings.HasPrefix(l, "> ") {
			t.Fatalf("line %d escaped the quote: %q in %q", i, l, got)
		}
	}
	if strings.Contains(got, "<script>") || strings.Contains(got, "> # heading") {
		t.Fatalf("raw markup: %q", got)
	}
}

func TestCodeSpanCannotBeClosed(t *testing.T) {
	if got := Code("a`b\nc"); got != "`abc`" {
		t.Fatalf("%q", got)
	}
}

func TestDescriptionHasIdentifiersOnly(t *testing.T) {
	f := Facts{Kind: KindIncident, ID: testIncA, Project: testProject, Severity: "critical", Status: "open", Related: []Ref{{Kind: KindIssue, ID: testIssue}, {Kind: "service", ID: testIncB}}}
	link, ok := Link("https://console.example.test/", testOrg, KindIncident, testProject, testIncA)
	if !ok {
		t.Fatal("no link")
	}
	d := Description(f, link)
	for _, want := range []string{testIncA.String(), testProject.String(), "critical", "open", testIssue.String(), "[Open in Soundpost](https://console.example.test/#view=incidents&org="} {
		if !strings.Contains(d, want) {
			t.Errorf("lacks %q:\n%s", want, d)
		}
	}
	if d2 := Description(f, ""); strings.Contains(d2, "Open in Soundpost") {
		t.Errorf("link without an origin: %s", d2)
	}
	// A hostile link cannot break out of the Markdown link target.
	if d3 := Description(f, "https://x.example/a) [b](javascript:alert(1)"); strings.Contains(d3, "](javascript") || strings.Count(d3, "(") != 1 {
		t.Errorf("link target broken out: %s", d3)
	}
	if got := WithMarker(d, "soundpost-ref-aa"); !strings.HasSuffix(got, "Soundpost reference: soundpost-ref-aa\n") {
		t.Errorf("marker line: %q", got)
	}
	// The description has no field for user text: nothing in it can be a trigger.
	for _, bad := range []string{"@", "#1", "~", "$", "[["} {
		if strings.Contains(strings.SplitN(d, "[Open in Soundpost]", 2)[0], bad) {
			t.Errorf("trigger %q in the identifier part:\n%s", bad, d)
		}
	}
}

func TestLinkFormsAndOrigin(t *testing.T) {
	l, ok := Link("https://console.example.test", testOrg, KindIssue, testProject, testIssue)
	want := "https://console.example.test/#view=issues&org=" + testOrg.String() + "&projects=" + testProject.String() + "&target=" + testProject.String() + ":" + testIssue.String()
	if !ok || l != want {
		t.Fatalf("%q %v", l, ok)
	}
	for _, o := range []string{"", "http://console.example.test", "https://u:p@console.example.test", "https://console.example.test/path", "https://console.example.test/?q=1", "not a url"} {
		if _, ok := Link(o, testOrg, KindIncident, testProject, testIncA); ok {
			t.Errorf("origin %q accepted", o)
		}
	}
}

func TestHasMarkerMatchesWholeMarkerOnly(t *testing.T) {
	m := model.ExternalMarker(testOrg, KindIncident, testIncA)
	cases := map[string]bool{
		"Soundpost reference: " + m + "\n": true,
		m:                                  true,
		"x" + m + " y":                     true,
		m + "00":                           false,
		m[:len(m)-1]:                       false,
		"":                                 false,
		m + "0 and again " + m + ".":       true,
		model.ExternalMarker(testOrg, KindIncident, testIncB): false,
	}
	for text, want := range cases {
		if got := HasMarker(text, m); got != want {
			t.Errorf("HasMarker(%q) = %v", text, got)
		}
	}
}

func TestValidators(t *testing.T) {
	if !ValidTitle("Checkout fails") || ValidTitle("") || ValidTitle("  ") || ValidTitle("a\nb") || ValidTitle(strings.Repeat("é", 128)) || ValidTitle("\xff") {
		t.Error("title validation")
	}
	if !ValidTitle(strings.Repeat("a", 255)) || ValidTitle(strings.Repeat("a", 256)) {
		t.Error("title bounds")
	}
	if !ValidDescription("line one\n\tline two") || ValidDescription("") || ValidDescription("bad\x00") || ValidDescription("SoundPost-Ref-abc") || ValidDescription(strings.Repeat("a", 8001)) {
		t.Error("description validation")
	}
	if !ValidLabels(nil) || !ValidLabels([]string{"a", "b c"}) || ValidLabels([]string{"a,b"}) || ValidLabels([]string{""}) || ValidLabels(make([]string, 11)) {
		t.Error("label validation")
	}
	for _, p := range []string{"shop/web", "123", "a.b-c_d/e"} {
		if !ValidProject(p) {
			t.Errorf("%q refused", p)
		}
	}
	for _, p := range []string{"", "/a", "a/", "a//b", "a b", "a?x=1", "a%2Fb", strings.Repeat("a", 201)} {
		if ValidProject(p) {
			t.Errorf("%q accepted", p)
		}
	}
}

const hostileTriggers = "@user @group @all #123 !45 &6 %milestone ~label ~\"two words\" $snippet [[wiki]] /close group/project#1 group/project!1 " +
	"deadbeef1234567890abcdef1234567890abcdef abc1234 https://evil.example/x http://a.b www.evil.example user@example.com <!-- hidden -->"

func TestLineAndQuoteDefuseEveryGitLabTrigger(t *testing.T) {
	for name, got := range map[string]string{"line": Line(hostileTriggers), "slash first": Line("/close now"), "quote": Quote("first\n/assign @me\n" + hostileTriggers)} {
		for _, bad := range []string{"@u", "@g", "@a", "@e", "@m", "#1", "!4", "&6", "%m", "~l", "~\"", "$s", "[[", "group/project#", "group/project!", "deadbeef1234", "abc1234", "://", "www.e", "<!--"} {
			if strings.Contains(got, bad) {
				t.Errorf("%s: trigger %q survives in %q", name, bad, got)
			}
		}
		if strings.HasPrefix(got, "/") || strings.Contains(got, "\n/") {
			t.Errorf("%s: a quick action starts a line: %q", name, got)
		}
	}
}
