// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// Literal expectations below are authored from the inventory's behavioral rules,
// not captured or translated upstream test tables. These remain unverified until
// the integration owner exercises both this suite and the locked native oracle.
func TestTemplateEveryHelper(t *testing.T) {
	cases := []struct{ name, expression, want, boundary, boundaryWant string }{
		{"Replace", `Replace "a-a-a" "a" "b" 2`, "b-b-a", `Replace "a" "a" "b" 0`, "a"},
		{"ToLower", `ToLower "ÄBC"`, "äbc", `ToLower ""`, ""},
		{"ToUpper", `ToUpper "äbc"`, "ÄBC", `ToUpper "𐵰"`, "𐵰"},
		{"Trim", `Trim "abVALUEba" "ab"`, "VALUE", `Trim "abc" ""`, "abc"},
		{"TrimLeft", `TrimLeft "aaXaa" "a"`, "Xaa", `TrimLeft "" "a"`, ""},
		{"TrimPrefix", `TrimPrefix "abXab" "ab"`, "Xab", `TrimPrefix "Xab" "ab"`, "Xab"},
		{"TrimRight", `TrimRight "aaXaa" "a"`, "aaX", `TrimRight "abc" "z"`, "abc"},
		{"TrimSpace", `TrimSpace "\t X\u00a0"`, "X", `TrimSpace ""`, ""},
		{"TrimSuffix", `TrimSuffix "abXab" "ab"`, "abX", `TrimSuffix "abX" "ab"`, "abX"},
		{"__line__", `__line__`, "line", `__line__ | len`, "4"},
		{"__timestamp__", `__timestamp__ | unixEpochNanos`, "-1", `(__timestamp__).Nanosecond`, "999999999"},
		{"add", `add "2" 3 true`, "6", `add`, "0"},
		{"addf", `addf "0.1" "0.2"`, "0.3", `addf`, "0"},
		{"alignLeft", `alignLeft 4 "éx"`, "éx  ", `alignLeft 1 "éx"`, "é"},
		{"alignRight", `alignRight 4 "éx"`, "  éx", `alignRight 1 "éx"`, "x"},
		{"b64dec", `b64dec "aGk="`, "hi", `b64dec "!"`, "illegal base64 data at input byte 0"},
		{"b64enc", `b64enc "hi"`, "aGk=", `b64enc ""`, ""},
		{"bytes", `bytes "1.5 KiB"`, "1536", `bytes "0"`, "0"},
		{"ceil", `ceil "1.2"`, "2", `ceil "-1.2"`, "-1"},
		{"contains", `contains "bc" "abcd"`, "true", `contains "" ""`, "true"},
		{"count", `count "a+" "aa ba"`, "2", `count "" "ab"`, "3"},
		{"date", `date "2006-01-02" 0`, "1970-01-01", `date "2006-01-02" "unsupported"`, "2026-11-03"},
		{"default", `default "fallback" "given"`, "given", `default "fallback" false "ignored"`, "fallback"},
		{"div", `div -7 2`, "-3", `div "bad" 2`, "0"},
		{"divf", `divf 1 3`, "0.3333333333333333", `divf 2`, "2"},
		{"duration", `duration "1m30s"`, "90", `duration "-1ns"`, "-1e-09"},
		{"duration_seconds", `duration_seconds "1.5s"`, "1.5", `duration_seconds "0"`, "0"},
		{"float64", `float64 true`, "1", `float64 "bad"`, "0"},
		{"floor", `floor "1.9"`, "1", `floor "-1.2"`, "-2"},
		{"fromJson", `index (fromJson "{\"x\":[2]}") "x" 0`, "2", `fromJson "invalid"`, "<no value>"},
		{"hasPrefix", `hasPrefix "ab" "abc"`, "true", `hasPrefix "z" "abc"`, "false"},
		{"hasSuffix", `hasSuffix "bc" "abc"`, "true", `hasSuffix "" "abc"`, "true"},
		{"indent", `indent 2 "a\nb"`, "  a\n  b", `indent 0 ""`, ""},
		{"int", `int 2.9`, "2", `int "invalid"`, "0"},
		{"lower", `lower "ÄBC"`, "äbc", `lower ""`, ""},
		{"max", `max -2 "8" 3`, "8", `max -2`, "-2"},
		{"maxf", `maxf -2 "8.5" 3`, "8.5", `maxf "NaN" 2`, "NaN"},
		{"min", `min -2 "8" 3`, "-2", `min 3`, "3"},
		{"minf", `minf -2 "8.5" 3`, "-2", `minf "-0" 0`, "-0"},
		{"mod", `mod -7 2`, "-1", `mod 0 2`, "0"},
		{"mul", `mul 2 "3" 4`, "24", `mul 7`, "7"},
		{"mulf", `mulf 0.1 0.2`, "0.02", `mulf 7`, "7"},
		{"nindent", `nindent 2 "a\nb"`, "\n  a\n  b", `nindent 0 ""`, "\n"},
		{"now", `now | date "2006-01-02"`, "2026-11-03", `now | unixEpoch`, "1793707200"},
		{"regexReplaceAll", `regexReplaceAll "(a)" "aba" "${1}x"`, "axbax", `regexReplaceAll "z" "abc" "x"`, "abc"},
		{"regexReplaceAllLiteral", `regexReplaceAllLiteral "a" "aba" "$1"`, "$1b$1", `regexReplaceAllLiteral "z" "abc" "x"`, "abc"},
		{"repeat", `repeat 3 "ab"`, "ababab", `repeat 0 "ab"`, ""},
		{"replace", `replace "a" "x" "aba"`, "xbx", `replace "" "x" "a"`, "xax"},
		{"round", `round "1.25" 1`, "1.3", `round "-1.25" 1`, "-1.3"},
		{"sub", `sub 9 4`, "5", `sub "bad" 3`, "-3"},
		{"subf", `subf 0.3 0.1`, "0.2", `subf 8`, "8"},
		{"substr", `substr 1 3 "abcd"`, "bc", `substr -1 2 "abcd"`, "ab"},
		{"title", `title "hello_world hello-world"`, "Hello_world Hello-World", `title ""`, ""},
		{"toDate", `toDate "2006-01-02" "2001-01-01" | unixEpoch`, "978307200", `(toDate "2006" "bad").IsZero`, "true"},
		{"toDateInZone", `toDateInZone "2006-01-02 15:04 -0700" "UTC" "2001-01-01 01:00 +0100" | unixEpoch`, "978307200", `toDateInZone "2006" "Not/A_Zone" "2001" | date "2006"`, "2001"},
		{"trim", `trim "\n abc\t"`, "abc", `trim ""`, ""},
		{"trimAll", `trimAll "ab" "abXba"`, "X", `trimAll "" "abc"`, "abc"},
		{"trimPrefix", `trimPrefix "ab" "abXab"`, "Xab", `trimPrefix "z" "abc"`, "abc"},
		{"trimSuffix", `trimSuffix "ab" "abXab"`, "abX", `trimSuffix "z" "abc"`, "abc"},
		{"trunc", `trunc 2 "abcd"`, "ab", `trunc -2 "abcd"`, "cd"},
		{"unixEpoch", `unixEpoch (__timestamp__)`, "-1", `unixEpoch (toDate "2006" "2001")`, "978307200"},
		{"unixEpochMillis", `unixEpochMillis (__timestamp__)`, "-1", `unixEpochMillis (toDate "2006" "2001")`, "978307200000"},
		{"unixEpochNanos", `unixEpochNanos (__timestamp__)`, "-1", `unixEpochNanos (toDate "2006" "2001")`, "978307200000000000"},
		{"unixToTime", `unixToTime "1000000000" | unixEpoch`, "1000000000", `unixToTime "00001" | unixEpoch`, "86400"},
		{"upper", `upper "äbc"`, "ÄBC", `upper ""`, ""},
		{"urldecode", `urldecode "a%2Bb+c"`, "a+b c", `urldecode ""`, ""},
		{"urlencode", `urlencode "a+b c"`, "a%2Bb+c", `urlencode ""`, ""},
	}
	input := TemplateInput{Line: "line", Timestamp: model.UnixNano(-1)}
	covered := map[string]bool{}
	for _, c := range cases {
		covered[c.name] = true
		t.Run(c.name, func(t *testing.T) {
			for _, check := range []struct{ expr, want string }{{c.expression, c.want}, {c.boundary, c.boundaryWant}} {
				got, e := templateRender(t, "{{"+check.expr+"}}", input)
				if e != nil || got != check.want {
					t.Fatalf("%s: got %q err=%v want=%q", check.expr, got, e, check.want)
				}
			}
		})
	}
	for _, spec := range TemplateFunctions(templateTestProfile()) {
		if !covered[spec.Name] {
			t.Errorf("missing helper behavior %s", spec.Name)
		}
	}
}

func TestTemplateInvalidHelperArguments(t *testing.T) {
	bad := []string{`upper 1`, `ToLower true`, `Replace "a" "b" "c"`, `Replace "a" "b" "c" "1"`, `Trim 2 "a"`, `TrimLeft "a" 2`, `TrimRight true "a"`, `TrimPrefix "a"`, `TrimSuffix "a"`, `TrimSpace 1`, `__line__ 1`, `__timestamp__ 1`, `alignLeft "2" "abc"`, `alignRight 2 3`, `b64dec 1`, `b64enc false`, `bytes "18446744073709551616 B"`, `bytes "not bytes"`, `ceil`, `contains 1 "a"`, `count "[" "a"`, `date 1 0`, `default`, `div 1 0`, `divf 1 0`, `duration "nonsense"`, `duration_seconds "nonsense"`, `float64`, `floor`, `fromJson false`, `hasPrefix "a" 2`, `hasSuffix 2 "a"`, `indent -1 "x"`, `int`, `lower 1`, `max`, `maxf`, `min`, `minf`, `mod 1 0`, `mul`, `mulf`, `nindent -1 "x"`, `now 1`, `regexReplaceAll "[" "x" "y"`, `regexReplaceAllLiteral "[" "x" "y"`, `repeat -1 "x"`, `replace "a" "b"`, `round 1 "2"`, `round 1 2 "0.5"`, `sub 1`, `subf`, `substr 4 1 "abc"`, `title 1`, `toDate "2006" 1`, `toDateInZone "2006" "UTC" 1`, `trim 1`, `trimAll "a" 1`, `trimPrefix 1 "a"`, `trimSuffix "a" false`, `trunc "1" "abc"`, `unixEpoch "1"`, `unixEpochMillis 1`, `unixEpochNanos "1"`, `unixToTime "123"`, `upper false`, `urldecode "%Q0"`, `urlencode 1`}
	for _, expr := range bad {
		t.Run(expr, func(t *testing.T) {
			got, e := templateRender(t, "prefix{{"+expr+"}}", TemplateInput{})
			if e == nil || got != "" {
				t.Fatalf("invalid helper returned %q err=%v", got, e)
			}
		})
	}
	for _, expr := range []string{`add (fromJson "{}")`, `addf false`, `addf (fromJson "{}")`} {
		got, e := templateRender(t, "{{"+expr+"}}", TemplateInput{})
		if e != nil || got != "0" {
			t.Fatalf("any helper must coerce invalid type to zero: %q %v", got, e)
		}
	}
}
func TestTemplateSafeTimeMethods(t *testing.T) {
	cases := []struct{ expr, want string }{
		{`(__timestamp__).UnixNano`, "-1"}, {`(__timestamp__).Year`, "1969"}, {`(__timestamp__).Month.String`, "December"}, {`(__timestamp__).UTC.Format "2006-01-02"`, "1969-12-31"},
		{`((__timestamp__).Add 1).UnixNano`, "0"}, {`((__timestamp__).Sub (__timestamp__)).String`, "0s"}, {`(now).Location.String`, "UTC"},
		{`eq (now).Month 11`, "true"}, {`printf "%T/%T" (now).Month (index "a" 0)`, "time.Month/uint8"},
	}
	for _, c := range cases {
		got, e := templateRender(t, "{{"+c.expr+"}}", TemplateInput{Timestamp: model.UnixNano(-1)})
		if e != nil || got != c.want {
			t.Fatalf("%s: %q %v want %q", c.expr, got, e, c.want)
		}
	}
	for _, expr := range []string{`(now).Zone`, `(now).Date`, `(now).Clock`, `(now).ISOWeek`, `(now).UnmarshalJSON "x"`, `(now).Add (len "x")`} {
		got, e := templateRender(t, "{{"+expr+"}}", TemplateInput{})
		if e == nil || got != "" {
			t.Fatalf("invalid native method: %s got=%q err=%v", expr, got, e)
		}
	}
}
func TestTemplateExplicitZoneAndClockRollover(t *testing.T) {
	runtime := TemplateRuntime{Now: func() time.Time { return time.Date(2026, 11, 3, 23, 59, 59, 999999999, time.UTC) }, Location: time.FixedZone("east", 3600)}
	c, e := CompileTemplate(`{{now | date "2006-01-02 15:04:05.999999999 -0700"}}`, templateTestProfile(), runtime)
	if e != nil {
		t.Fatal(e)
	}
	got, e := c.Execute(context.Background(), TemplateInput{}, value.NewBoundedAccount(1<<20))
	if e != nil || got != "2026-11-04 00:59:59.999999999 +0100" {
		t.Fatalf("explicit zone: %q %v", got, e)
	}
}
func TestTemplateAccountChecksStopWork(t *testing.T) {
	denied := errors.New("authorization revoked")
	account := &templateDenyAccount{BoundedAccount: value.NewBoundedAccount(1 << 20), after: 20, denied: denied}
	c, e := CompileTemplate(`{{range fromJson "[1,2,3,4,5,6,7,8,9]"}}x{{end}}`, templateTestProfile(), templateTestRuntime())
	if e != nil {
		t.Fatal(e)
	}
	got, e := c.Execute(context.Background(), TemplateInput{}, account)
	if !errors.Is(e, denied) || got != "" || account.Used() != 0 {
		t.Fatalf("revocation: %q %v used=%d", got, e, account.Used())
	}
}

type templateDenyAccount struct {
	*value.BoundedAccount
	after  int
	denied error
}

func (a *templateDenyAccount) Check(ctx context.Context) error {
	a.after--
	if a.after <= 0 {
		return a.denied
	}
	return ctx.Err()
}
func TestTemplatePrintfAdmission(t *testing.T) {
	expressions := []string{
		`printf "` + strings.Repeat("%1000000s", 20) + `"` + strings.Repeat(` "x"`, 20),
		`printf "` + strings.Repeat("%*s", 20) + `"` + strings.Repeat(` 1000000 "x"`, 20),
		`printf "` + strings.Repeat("%.*f", 20) + `"` + strings.Repeat(` 1000000 1.0`, 20),
		`printf "%1000000v" (fromJson "{\"a\":\"x\",\"b\":\"y\",\"c\":\"z\"}")`,
	}
	for _, expr := range expressions {
		got, e := templateRender(t, "prefix{{"+expr+"}}", TemplateInput{})
		var limit *TemplateLimitError
		if !errors.As(e, &limit) || got != "" {
			t.Fatalf("unbounded fmt: len=%d %v", len(got), e)
		}
	}
}
func TestTemplatePipelineArgumentOrder(t *testing.T) {
	got, e := templateRender(t, `{{"ab" | replace "a" "x"}}/{{Replace "ab" "a" "x" -1}}/{{" abc " | trim}}/{{"ab" | contains "a"}}`, TemplateInput{})
	if e != nil || got != "xb/xb/abc/true" {
		t.Fatalf("pipeline order: %q %v", got, e)
	}
}
func TestTemplateDiagnosticsExcludeSource(t *testing.T) {
	_, e := templateRender(t, `prefix-secret{{div 3 0}}`, TemplateInput{Line: "private-record"})
	if e == nil || strings.Contains(e.Error(), "secret") || strings.Contains(e.Error(), "private") {
		t.Fatalf("unsafe error: %v", e)
	}
}

func TestTemplateStandardPrimitives(t *testing.T) {
	cases := []struct{ source, want string }{
		{`{{len .}}/{{index . "missing"}}/{{printf "%T" .}}`, "1//map[string]string"},
		{`{{index "abc" 1}}/{{slice "abcd" 1 3}}/{{slice "abcd" 2}}`, "98/bc/cd"},
		{`{{eq 1 1 2}}/{{ne 1 2}}/{{lt 1 2}}/{{le 2 2}}/{{gt 2 1}}/{{ge 2 2}}`, "true/true/true/true/true/true"},
		{`{{not ""}}/{{and true "x"}}/{{or "" 2}}`, "true/x/2"},
		{`{{print "a" 1}}/{{println "a" 1}}/{{printf "%04d" 2}}`, "a1/a 1\n/0002"},
		{`{{html "<b>"}}/{{js "<b>"}}/{{urlquery "a+b c"}}`, "&lt;b&gt;/\\u003Cb\\u003E/a%2Bb+c"},
		{`{{printf "%s" (now).MarshalText}}`, "2026-11-03T12:00:00Z"},
		{`{{printf "%s" ((now).AppendText nil)}}`, "2026-11-03T12:00:00Z"},
		{`{{printf "%s" ((now).AppendFormat nil "2006")}}`, "2026"},
	}
	for _, c := range cases {
		got, e := templateRender(t, c.source, TemplateInput{Labels: model.Labels{{Name: "level", Value: "warn"}}})
		if e != nil || got != c.want {
			t.Fatalf("%s: got=%q error=%v want=%q", c.source, got, e, c.want)
		}
	}
	for _, source := range []string{`{{index "a" 2}}`, `{{slice "a" 0 2}}`, `{{lt true false}}`, `{{eq 1 "1"}}`, `{{len nil}}`, `{{call "x"}}`, `{{repeat (len "x") 1}}`} {
		got, e := templateRender(t, source, TemplateInput{})
		if e == nil || got != "" {
			t.Fatalf("invalid primitive: %q %v", got, e)
		}
	}
}
func TestTemplateTypedFieldsRemainClosed(t *testing.T) {
	var n, flag, text model.Scalar
	if n.UnmarshalJSON([]byte("7")) != nil || flag.UnmarshalJSON([]byte("true")) != nil || text.UnmarshalJSON([]byte(`"abc"`)) != nil {
		t.Fatal("scalar fixture rejected")
	}
	got, e := templateRender(t, `{{add .number 2}}/{{if .flag}}yes{{end}}/{{.text | upper}}`, TemplateInput{Fields: []TypedField{{Name: "number", Value: n}, {Name: "flag", Value: flag}, {Name: "text", Value: text}}})
	if e != nil || got != "9/yes/ABC" {
		t.Fatalf("typed fields: %q %v", got, e)
	}
}
func TestTemplateVariableAssignmentsAndRangeScopes(t *testing.T) {
	source := `{{$x := ""}}{{range $i,$v := fromJson "[1,2,3]"}}{{$x = printf "%s%v" $x $v}}{{end}}{{$x}}/{{range .}}{{.}}{{end}}`
	got, e := templateRender(t, source, TemplateInput{Labels: model.Labels{{Name: "a", Value: "A"}, {Name: "b", Value: "B"}}})
	if e != nil || got != "123/AB" {
		t.Fatalf("assignment or root map range: %q %v", got, e)
	}
}
func TestTemplateRepeatedFormatArgumentIsAdmitted(t *testing.T) {
	source := `{{$s:=repeat 4096 "x"}}{{printf "` + strings.Repeat("%[1]s", 4096) + `" $s}}`
	got, e := templateRender(t, source, TemplateInput{})
	var limit *TemplateLimitError
	if !errors.As(e, &limit) || got != "" {
		t.Fatalf("repeated format expansion unbounded: len=%d err=%v", len(got), e)
	}
}

func TestTemplatePinnedIntegerRange(t *testing.T) {
	// Go 1.24 introduced integer template ranges; negative ranges are empty.
	for _, c := range []struct{ source, want string }{{`{{range 3}}{{.}}{{end}}`, "012"}, {`{{range -1}}bad{{else}}empty{{end}}`, "empty"}, {`{{$x:=9}}{{range $x = 3}}{{$x}}{{end}}/{{$x}}`, "012/2"}, {`{{range add 2 1}}{{.}}{{end}}`, "012"}} {
		got, e := templateRender(t, c.source, TemplateInput{})
		if e != nil || got != c.want {
			t.Fatalf("integer range %s: %q %v", c.source, got, e)
		}
	}
	got, e := templateRender(t, `{{range $i,$v := 3}}{{$v}}{{end}}`, TemplateInput{})
	if e == nil || got != "" {
		t.Fatalf("integer range accepted two variables: %q %v", got, e)
	}
	c, e := CompileTemplate(`prefix{{range 1000000000}}{{end}}`, templateTestProfile(), templateTestRuntime())
	if e != nil {
		t.Fatal(e)
	}
	account := value.NewBoundedAccount(1 << 20)
	got, e = c.Execute(context.Background(), TemplateInput{}, account)
	var limit *TemplateLimitError
	if !errors.As(e, &limit) || got != "" || account.Used() != 0 {
		t.Fatalf("empty-body integer range not metered: %q %v used=%d", got, e, account.Used())
	}
}

func TestTemplatePinnedQuotingAndIdentifiers(t *testing.T) {
	got, e := templateRender(t, `{{printf "%q" "𐵰"}}/{{js "𐵰"}}`, TemplateInput{})
	if e != nil || got != `"\U00010d70"/\u10D70` {
		t.Fatalf("host quoting classes escaped profile: %q %v", got, e)
	}
	for _, source := range []string{`{{.𐵰}}`, `{{$𐵰 := "x"}}{{$𐵰}}`} {
		if _, e := CompileTemplate(source, templateTestProfile(), templateTestRuntime()); e == nil {
			t.Fatalf("host lexer broadened identifiers: %s", source)
		}
	}
	if got, e = templateRender(t, `{{upper "𐵰"}}`, TemplateInput{}); e != nil || got != "𐵰" {
		t.Fatalf("payload text must not be identifier-filtered: %q %v", got, e)
	}
}
func TestTemplateClockCallsAreIndependent(t *testing.T) {
	calls := int64(0)
	runtime := TemplateRuntime{Now: func() time.Time { stamp := time.Unix(calls, 0); calls++; return stamp }, Location: time.UTC}
	c, e := CompileTemplate(`{{now | unixEpoch}}/{{now | unixEpoch}}/{{date "2006" 0}}`, templateTestProfile(), runtime)
	if e != nil {
		t.Fatal(e)
	}
	got, e := c.Execute(context.Background(), TemplateInput{}, value.NewBoundedAccount(1<<20))
	if e != nil || got != "0/1/1970" || calls != 2 {
		t.Fatalf("clock was frozen/eager: %q %v calls=%d", got, e, calls)
	}
	calls = 0
	if _, e = CompileTemplate(`{{env "PATH"}}`, templateTestProfile(), runtime); e == nil || calls != 0 {
		t.Fatalf("denied compile called runtime: err=%v calls=%d", e, calls)
	}
}
func TestTemplateEmptyRangeDeclarationValue(t *testing.T) {
	got, e := templateRender(t, `{{range $x := fromJson "[]"}}bad{{else}}{{printf "%T" $x}}{{end}}`, TemplateInput{})
	if e != nil || got != "[]interface {}" {
		t.Fatalf("empty range declaration: %q %v", got, e)
	}
}

func TestTemplateTimestampOverflowAndMapIdentity(t *testing.T) {
	got, e := templateRender(t, `{{unixToTime "9999999999999" | unixEpochNanos}}/{{eq (printf "%p" .) (printf "%p" .)}}`, TemplateInput{Labels: model.Labels{{Name: "level", Value: "warn"}}})
	if e != nil || got != "-8446744073710551616/true" {
		t.Fatalf("conversion overflow or map identity: %q %v", got, e)
	}
}

func TestTemplateZeroAllocationAndNonfiniteHelpers(t *testing.T) {
	got, e := templateRender(t, `{{repeat 1000000000 ""}}`, TemplateInput{})
	if e != nil || got != "" {
		t.Fatalf("empty repeat invented work: %q %v", got, e)
	}
	for _, source := range []string{`{{ToUpper 1}}`, `{{addf "NaN"}}`, `{{mulf "Inf"}}`, `{{nil}}`} {
		got, e = templateRender(t, source, TemplateInput{})
		if e == nil || got != "" {
			t.Fatalf("invalid helper succeeded: %q %v", got, e)
		}
	}
}

func TestTemplateRegexAccountRevocationStaysFatal(t *testing.T) {
	denied := errors.New("authorization revoked during regexp")
	account := &templateOnceDenyAccount{BoundedAccount: value.NewBoundedAccount(64 << 20), remaining: 100, denied: denied}
	c, e := CompileTemplate(`prefix{{count "a" (repeat 1000 "a")}}`, templateTestProfile(), templateTestRuntime())
	if e != nil {
		t.Fatal(e)
	}
	got, e := c.Execute(context.Background(), TemplateInput{}, account)
	var formatting *TemplateError
	if !errors.Is(e, denied) || errors.As(e, &formatting) || got != "" || account.Used() != 0 {
		t.Fatalf("regex downgraded account failure: %q %v held=%d", got, e, account.Used())
	}
}

type templateOnceDenyAccount struct {
	*value.BoundedAccount
	remaining int
	denied    error
}

func (a *templateOnceDenyAccount) Check(ctx context.Context) error {
	a.remaining--
	if a.remaining == 0 {
		return a.denied
	}
	return ctx.Err()
}

func TestTemplatePrintfStarAndIndexOrder(t *testing.T) {
	cases := []struct{ source, want string }{
		{`{{printf "%*s/%d" 1 "x" 1000000000}}`, "x/1000000000"},
		{`{{printf "%[3]*.[2]*[1]f" 1.25 1 5}}`, "  1.2"},
		{`{{printf "%[2]s/%[1]d" 7 "x"}}`, "x/7"},
		{`{{printf "%-3s" "x"}}`, "x  "},
	}
	for _, c := range cases {
		got, e := templateRender(t, c.source, TemplateInput{})
		if e != nil || got != c.want {
			t.Fatalf("star/index order: %q %v want=%q", got, e, c.want)
		}
	}
}

func TestTemplateNamedZonesUsePinnedData(t *testing.T) {
	for _, c := range []struct{ source, want string }{
		{`{{toDateInZone "2006-01-02 15:04" "America/New_York" "2026-01-01 00:00" | unixEpoch}}`, "1767243600"},
		{`{{toDateInZone "2006-01-02 15:04" "America/New_York" "2026-07-01 00:00" | unixEpoch}}`, "1782878400"},
		{`{{toDateInZone "2006-01-02 15:04" "Not/A_Zone" "2001-01-01 00:00" | unixEpoch}}`, "978307200"},
	} {
		got, e := templateRender(t, c.source, TemplateInput{})
		if e != nil || got != c.want {
			t.Fatalf("pinned named zone: %q %v want=%q", got, e, c.want)
		}
	}
	runtime := TemplateRuntime{Now: time.Now, Location: time.FixedZone("east", 3600)}
	c, e := CompileTemplate(`{{toDateInZone "2006-01-02 15:04" "Local" "2001-01-01 00:00" | unixEpoch}}`, templateTestProfile(), runtime)
	if e != nil {
		t.Fatal(e)
	}
	got, e := c.Execute(context.Background(), TemplateInput{}, value.NewBoundedAccount(64<<20))
	if e != nil || got != "978303600" {
		t.Fatalf("Local escaped explicit location: %q %v", got, e)
	}
}
