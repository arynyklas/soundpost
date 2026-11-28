// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"errors"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPipelineLineFilterAlternativesAndPatterns(t *testing.T) {
	for _, tc := range []struct {
		query, line string
		want        bool
	}{
		{`{app="api"}|="request" or "response"`, "response finished", true},
		{`{app="api"}|="request" or "response"`, "unrelated", false},
		{`{app="api"}|="request" !="noise"`, "request noise", false},
		{`{app="api"}|>"<_> request <_> completed"`, "worker request 42 completed", true},
		{`{app="api"}|>"request <_>"`, "prefix request completed", false},
		{`{app="api"}!>"<_> request <_>"`, "prefix request completed", false},
		{`{app="api"}|~"(?s)left.right"`, "left\nright", true},
	} {
		if got := run(t, tc.query, entry(tc.line)).Retained; got != tc.want {
			t.Fatalf("%s %q: %v", tc.query, tc.line, got)
		}
	}
}
func TestPipelineIPFilters(t *testing.T) {
	for _, tc := range []struct {
		q, line string
		want    bool
	}{
		{`{app="api"}|=ip("192.0.2.0/24")`, "peer=192.0.2.44 connected", true},
		{`{app="api"}!=ip("192.0.2.0/24")`, "peer=192.0.2.44 connected", false},
		{`{app="api"}|=ip("2001:db8::/32")`, "peer=[2001:db8::44]", true},
		{`{app="api"}|=ip("192.0.2.8-192.0.2.12")`, "192.0.2.11", true},
		{`{app="api"}|=ip("192.0.2.8-192.0.2.12")`, "192.0.2.13", false},
		{`{app="api"}|json|peer=ip("192.0.2.0/24")`, `{"peer":"192.0.2.4"}`, true},
	} {
		if got := run(t, tc.q, entry(tc.line)).Retained; got != tc.want {
			t.Fatalf("IP mismatch %s: %v", tc.q, got)
		}
	}
	r := run(t, `{app="api"}|json|peer=ip("192.0.2.0/24")`, entry(`{"peer":"unknown"}`))
	if r.Retained {
		t.Fatal("invalid IP value was not a nonmatch")
	}
}
func TestPipelineTypedFiltersAndLeftToRightGrouping(t *testing.T) {
	e := entry(`{"n":"2","d":"300ms","b":"1KiB","method":"POST"}`)
	if !run(t, `{app="api"}|json|n=2 d<1s,b>=1000B`, e).Retained {
		t.Fatal("typed comparisons or implicit conjunction failed")
	}
	if !run(t, `{app="api"}|json|n=2 or method="GET" and b>2KiB`, e).Retained {
		t.Fatal("and must bind tighter than or, as observed in the reference")
	}
	if !run(t, `{app="api"}|json|n=2 or (method="GET" and b>2KiB)`, e).Retained {
		t.Fatal("explicit grouping ignored")
	}
	if !run(t, `{app="api"}|json|b=1B`, entry(`{"b":"1.9B"}`)).Retained {
		t.Fatal("byte conversion rounded instead of truncating")
	}
}
func TestPipelineUnwrapConversions(t *testing.T) {
	for _, tc := range []struct {
		conversion, v string
		want          float64
	}{{"", "2.5", 2.5}, {"bytes", "2KiB", 2048}, {"bytes", "1.9B", 1}, {"duration", "250ms", 0.25}, {"duration_seconds", "2s", 2}} {
		q := `sum_over_time({app="api"}|json|unwrap `
		if tc.conversion == "" {
			q += "n"
		} else {
			q += tc.conversion + "(n)"
		}
		q += `[1m])`
		p := testProfile(t)
		tree, err := Parse(q, p)
		if err != nil {
			t.Fatal(err)
		}
		typed, _, err := Check(tree, p)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := BuildPlan(typed, value.Evaluation{}, p)
		if err != nil {
			t.Fatal(err)
		}
		r, err := RunPipeline(context.Background(), plan.Pipelines[0], entry(`{"n":"`+tc.v+`"}`), value.NewBoundedAccount(1<<20))
		if err != nil || r.Unwrapped == nil || *r.Unwrapped != tc.want {
			t.Fatalf("unwrap %s: %+v %v", tc.conversion, r, err)
		}
		if labelPresent(r.Labels, "n") || lookup(r.Labels, "app") != "api" {
			t.Fatalf("unwrap %q left the unwrapped label in the result: %v", tc.conversion, r.Labels)
		}
	}
}
func TestPipelineTemplateHooksSnapshotAndErrors(t *testing.T) {
	p := testPlan(t, `{app="api"}|label_format a="{{ .b }}",b="changed"|line_format "{{ .a }}"`)
	p, err := p.WithTemplateRuntime(TemplateRuntime{Location: time.UTC, Now: func() time.Time { return time.Unix(99, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	e := entry("original")
	e.StructuredMetadata = model.Labels{{Name: "b", Value: "input"}}
	r, err := RunPipeline(context.Background(), p, e, value.NewBoundedAccount(16<<20))
	if err != nil || r.Entry.Line != "input" {
		t.Fatalf("template snapshot: %+v %v", r, err)
	}
	r = run(t, `{app="api"}|line_format "{{ div 1 0 }}"|label_format x="after"`, entry("original"))
	if r.Entry.Line != "original" || lookup(r.Labels, "__error__") != "TemplateFormatErr" || lookup(r.Labels, "x") != "after" {
		t.Fatal("formatter error semantics")
	}
	r = run(t, `{app="api"}|line_format "{{ __line__ | upper }}"|line_format "{{ __line__ }}"`, entry("current"))
	if r.Entry.Line != "CURRENT" {
		t.Fatal("__line__ did not observe preceding mutation")
	}
	r = run(t, `{app="api"}|label_format failed="{{ div 1 0 }}",good="continued"|line_format "{{ .good }}"`, entry("original"))
	if r.Entry.Line != "continued" || lookup(r.Labels, "__error__") != "TemplateFormatErr" {
		t.Fatal("label formatter failure stopped later assignment")
	}
	r = run(t, `{app="api"}|line_format "changed"|line_format "{{ div 1 0 }}"`, entry("original"))
	if r.Entry.Line != "changed" {
		t.Fatal("line formatter failure restored admission line instead of current stage line")
	}
}
func TestPipelineKeepEmptyAndParserDuplicates(t *testing.T) {
	r := run(t, `{app="api"}|logfmt --keep-empty`, entry(`empty= code=first code=last`))
	if !labelPresent(r.Labels, "empty") || lookup(r.Labels, "code") != "last" {
		t.Fatal("empty retention or repeated-key replacement lost")
	}
	r = run(t, `{app="api"}|json`, entry(`{"code":"first","code":"last","a-b":1,"a.b":2}`))
	if lookup(r.Labels, "code") != "last" || lookup(r.Labels, "a_b") != "1" {
		t.Fatal("exact-key replacement or sanitized collision mismatch")
	}
}

func TestPipelineTemplateDetailIsAuthorizedDataNotSafeDiagnostic(t *testing.T) {
	source := `{{ index "private-marker" 99 }}`
	p := testProfile(t)
	compiled, err := CompileTemplate(source, p, defaultTemplateRuntime())
	if err != nil {
		t.Fatal(err)
	}
	_, err = compiled.Execute(context.Background(), TemplateInput{Line: "current", Timestamp: 123, Labels: model.Labels{{Name: "app", Value: "api"}}}, value.NewBoundedAccount(16<<20))
	var language *TemplateError
	if !errors.As(err, &language) || language.LanguageDetail() == "" {
		t.Fatalf("missing language detail: %v", err)
	}
	if strings.Contains(language.Error(), "private-marker") {
		t.Fatal("authorized language detail leaked into safe diagnostic")
	}
	r := run(t, `{app="api"}|line_format `+strconv.Quote(source), entry("current"))
	if !r.Retained || r.Entry.Line != "current" || lookup(r.Labels, "__error__") != "TemplateFormatErr" || lookup(r.Labels, "__error_details__") != language.LanguageDetail() {
		t.Fatal("pipeline replaced or lost authorized language detail")
	}
	if _, ok := templateFailureDetail(&TemplateLimitError{Resource: "memory", Cause: language}); ok {
		t.Fatal("resource failure became language label")
	}
	if _, ok := templateFailureDetail(context.Canceled); ok {
		t.Fatal("cancellation became language label")
	}
}

func TestPipelineLabelTemplateUsesNativeLabelRootDetail(t *testing.T) {
	source := `{{ index "private-marker" 99 }}`
	p := testProfile(t)
	compiled, err := compileLabelTemplate(source, p, defaultTemplateRuntime())
	if err != nil {
		t.Fatal(err)
	}
	_, err = compiled.Execute(context.Background(), TemplateInput{Line: "current", Timestamp: 123, Labels: model.Labels{{Name: "app", Value: "api"}}}, value.NewBoundedAccount(16<<20))
	var language *TemplateError
	if !errors.As(err, &language) || language.LanguageDetail() == "" {
		t.Fatalf("missing label-root detail: %v", err)
	}
	result := run(t, `{app="api"}|label_format failed=`+strconv.Quote(source)+`,good="after"`, entry("current"))
	if lookup(result.Labels, "__error_details__") != language.LanguageDetail() || lookup(result.Labels, "good") != "after" {
		t.Fatal("label root detail or later assignment differs")
	}
}

func TestPipelineConversionDetailsPreservePrimitiveErrors(t *testing.T) {
	_, numberErr := strconv.ParseFloat("private-marker", 64)
	_, durationErr := time.ParseDuration("private-marker")
	_, bytesErr := parseByteQuantity(" 1B")
	for _, tc := range []struct{ query, line, category, detail string }{
		{`{app="api"}|json|n>0`, `{"n":"private-marker"}`, "LabelFilterErr", numberErr.Error()},
		{`{app="api"}|json|n>1ms`, `{"n":"private-marker"}`, "LabelFilterErr", durationErr.Error()},
		{`{app="api"}|json|n>1B`, `{"n":" 1B"}`, "LabelFilterErr", bytesErr.Error()},
		{`sum_over_time({app="api"}|json|unwrap n[1m])`, `{"n":"private-marker"}`, "SampleExtractionErr", numberErr.Error()},
	} {
		result := run(t, tc.query, entry(tc.line))
		if !result.Retained || lookup(result.Labels, "__error__") != tc.category || lookup(result.Labels, "__error_details__") != tc.detail {
			t.Fatal("conversion detail replaced with generic diagnostic")
		}
	}
}

// The unwrapped label is consumed only when extraction yields a sample value.
// A failed conversion keeps the label next to the extraction error (pinned
// reference behaviour for both outcomes).
func TestUnwrapConsumesLabelOnlyOnSuccessfulExtraction(t *testing.T) {
	for _, tc := range []struct {
		name, query, line string
		consumed          bool
		failed            bool
	}{
		{"number ok", `sum_over_time({app="api"}|json|unwrap n[1m])`, `{"n":"2.5"}`, true, false},
		{"bytes ok", `sum_over_time({app="api"}|json|unwrap bytes(n)[1m])`, `{"n":"2KiB"}`, true, false},
		{"duration ok", `sum_over_time({app="api"}|json|unwrap duration(n)[1m])`, `{"n":"250ms"}`, true, false},
		{"number fails", `sum_over_time({app="api"}|json|unwrap n[1m])`, `{"n":"invalid"}`, false, true},
		{"bytes fails", `sum_over_time({app="api"}|json|unwrap bytes(n)[1m])`, `{"n":"nope"}`, false, true},
		{"duration fails", `sum_over_time({app="api"}|json|unwrap duration(n)[1m])`, `{"n":"nope"}`, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := run(t, tc.query, entry(tc.line))
			if !result.Retained {
				t.Fatal("entry unexpectedly dropped")
			}
			if present := labelPresent(result.Labels, "n"); present == tc.consumed {
				t.Fatalf("label n present=%v, want consumed=%v", present, tc.consumed)
			}
			if failed := lookup(result.Labels, "__error__") == "SampleExtractionErr"; failed != tc.failed {
				t.Fatalf("extraction failed=%v, want %v", failed, tc.failed)
			}
			if result.Unwrapped == nil {
				t.Fatal("unwrapped sample value missing")
			}
		})
	}
}

func TestPipelinePinnedNegativeAlternativesAndPartialPattern(t *testing.T) {
	for _, line := range []string{"one", "two", "one two"} {
		if run(t, `{app="api"}!="one" or "two"`, entry(line)).Retained {
			t.Fatal("negated alternatives did not complement their union")
		}
	}
	if !run(t, `{app="api"}!="one" or "two"`, entry("neither")).Retained {
		t.Fatal("negative alternatives rejected a nonmatch")
	}
	result := run(t, `{app="api"}|pattern "<first> ok <second> end"`, entry("a ok b missing"))
	if !result.Retained || lookup(result.Labels, "first") != "a" || lookup(result.Labels, "second") != "b missing" {
		t.Fatal("partial pattern captures were discarded")
	}
}
func TestPipelinePinnedUnpackCommitAndParserDetails(t *testing.T) {
	for _, line := range []string{`{"region":"north"}`, `{"_entry":1,"region":"north"}`} {
		result := run(t, `{app="api"}|unpack`, entry(line))
		if !result.Retained || result.Entry.Line != line || labelPresent(result.Labels, "region") {
			t.Fatal("unpack committed without a string entry")
		}
	}
	result := run(t, `{app="api"}|unpack`, entry("{"))
	if lookup(result.Labels, "__error__") != "JSONParserErr" || lookup(result.Labels, "__error_details__") != "Malformed JSON error" {
		t.Fatal("unpack malformed detail mismatch")
	}
	result = run(t, `{app="api"}|logfmt --strict`, entry(`code=first bad="unterminated`))
	if lookup(result.Labels, "code") != "first" || lookup(result.Labels, "__error_details__") != "logfmt syntax error at pos 29 : unterminated quoted value" {
		t.Fatal("strict logfmt partial extraction or exact detail lost")
	}
}
func TestPipelinePinnedTypedMissingAndExistingError(t *testing.T) {
	for _, query := range []string{`{app="api"}|json|n>1`, `{app="api"}|json|n>1s`} {
		if run(t, query, entry("{")).Retained {
			t.Fatal("missing typed label became retained parser error")
		}
	}
	input := entry("{")
	input.StreamLabels = append(input.StreamLabels, model.Label{Name: "n", Value: "bad"})
	result := run(t, `{app="api"}|json|n>1`, input)
	if !result.Retained || lookup(result.Labels, "__error__") != "JSONParserErr" || lookup(result.Labels, "__error_details__") != "Malformed JSON error" {
		t.Fatal("conversion overwrote the existing parser error")
	}
}

func TestPipelineReservedDetailsRemainOutputAndTemplateData(t *testing.T) {
	source := `{app="api"}|line_format ` + "`" + `{{duration "private-marker"}}` + "`"
	filtered := run(t, source+`|__error_details__=~".*private-marker.*"`, entry("current"))
	if filtered.Retained {
		t.Fatal("ordinary label lookup exposed reserved generated detail state")
	}
	result := run(t, source+`|__error__="TemplateFormatErr"|label_format copied="{{ .__error_details__ }}"`, entry("current"))
	if !result.Retained || result.Entry.Line != "current" || !strings.Contains(lookup(result.Labels, "__error_details__"), "private-marker") || lookup(result.Labels, "copied") != lookup(result.Labels, "__error_details__") {
		t.Fatal("generated detail was masked from authorized output/template map or stage flow stopped")
	}
	ordinary := run(t, `{app="api"}|label_format __error_details__="ordinary"|__error_details__="ordinary"`, entry("current"))
	if !ordinary.Retained {
		t.Fatal("ordinary assigned label was confused with reserved generated state")
	}
}
func TestPipelineAndEvaluatesRightHandLanguageEffects(t *testing.T) {
	result := run(t, `{app="api"}|json|m=1 and n>2 or app="api"`, entry(`{"m":"0","n":"bad"}`))
	if !result.Retained || lookup(result.Labels, "__error__") != "LabelFilterErr" {
		t.Fatal("AND skipped its right-hand language effects before outer OR")
	}
}
