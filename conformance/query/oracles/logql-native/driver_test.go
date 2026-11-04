//go:build soundpost_logql_oracle

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/grafana/loki/v3/pkg/logproto"
	native "github.com/grafana/loki/v3/pkg/logql"
	"github.com/grafana/loki/v3/pkg/logql/syntax"
	"github.com/grafana/loki/v3/pkg/logqlmodel"
	"github.com/grafana/loki/v3/pkg/querier/plan"
	"github.com/prometheus/prometheus/model/labels"
)

// Dropping selector checks or multiplicity expansion must change real native
// iterator observations; no expected answers are obtained from case fixtures.
func TestNativeLogQLInputSelectionPreservesMultiplicity(t *testing.T) {
	expr, e := syntax.ParseExpr(`{app="api"}|="keep"`)
	if e != nil {
		t.Fatal(e)
	}
	q := &fixtureQuerier{entries: []entry{{Timestamp: "1", Multiplicity: "2", Line: "keep", Labels: []label{{"app", "api"}}}, {Timestamp: "1", Multiplicity: "1", Line: "keep", Labels: []label{{"app", "other"}}}, {Timestamp: "2", Multiplicity: "1", Line: "keep", Labels: []label{{"app", "api"}}}}}
	start, _ := number("1")
	end, _ := number("2")
	p := native.SelectLogParams{QueryRequest: &logproto.QueryRequest{Start: time.Unix(0, start), End: time.Unix(0, end), Direction: logproto.FORWARD, Plan: &plan.QueryPlan{AST: expr}}}
	it, e := q.SelectLogs(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
	defer it.Close()
	n := 0
	for it.Next() {
		n++
		if it.At().Timestamp.UnixNano() != 1 || it.At().Line != "keep" {
			t.Fatal(it.At())
		}
	}
	if e = it.Err(); e != nil {
		t.Fatal(e)
	}
	if n != 2 {
		t.Fatalf("got %d entries; want two actual distinct multiplicity observations", n)
	}
}
func TestNativeLogQLTemplateCallsActualHelpersAndCurrentLine(t *testing.T) {
	c := testCase{ID: "helper", Phase: "logql-template", Source: `{{upper (__line__)}}/{{ __timestamp__ | unixEpoch }}`, Line: "original", Timestamp: "1000000001", Timezone: "UTC"}
	o, e := observe(context.Background(), input{}, c)
	if e != nil {
		t.Fatal(e)
	}
	if o.Error != nil || o.Output != "ORIGINAL/1" {
		t.Fatalf("actual helper observation %#v", o)
	}
}
func TestNativeLogQLPipelineKindExecutesWholeQuery(t *testing.T) {
	c := testCase{ID: "stages", Phase: "logql-template", Kind: "pipeline", Source: `WRONG-SOURCE-ONLY`, PipelineQuery: `{app="api"}|line_format "first"|line_format "{{ __line__ }}-second"`, Line: "original", Timestamp: "1", Labels: []label{{"app", "api"}}, Timezone: "UTC"}
	o, e := observe(context.Background(), input{}, c)
	if e != nil {
		t.Fatal(e)
	}
	if o.Error != nil || o.Pipeline == nil || !o.Pipeline.Retained || o.Pipeline.Line != "first-second" {
		t.Fatalf("full native pipeline not executed: %#v", o)
	}
}
func TestNativeLogQLErrorDoesNotInventParserRange(t *testing.T) {
	expr, e := syntax.ParseExpr(`{app="api"}|unknown_stage`)
	_ = expr
	if e == nil {
		t.Fatal("expected native rejection")
	}
	o := projectError(e)
	if o.Start != nil || o.End != nil || o.CategoryExposed {
		t.Fatal("unexposed native parser API positions/categories invented")
	}
}
func TestNativeLogQLParserStartConvertsActualCharacterColumn(t *testing.T) {
	err := logqlmodel.NewParseError("syntax error: unexpected IDENTIFIER", 2, 2)
	o := projectError(err, "é\nøx")
	if o.Start == nil || *o.Start != 5 || o.End != nil || o.CategoryExposed {
		t.Fatalf("genuine start/end/category projection incorrect: %#v", o)
	}
}
func TestNativeLogQLProjectsParseStageFamiliesWithoutInventedPositions(t *testing.T) {
	for text, want := range map[string]string{
		`parse error : stage '|> "<a> done"' : named captures are not allowed: found '<a>'`: "pattern.invalid",
		`parse error : stage '|= ip("192.0.2.900")' : ip: invalid pattern: "192.0.2.900"`:   "ip.pattern-invalid",
		`parse error : stage '|~ ip("192.0.2.1")' : ip: invalid operation`:                  "ip.operator-invalid",
	} {
		o := projectError(errors.New(text), "unused")
		if o.Semantic != want || o.Start != nil || o.End != nil || o.CategoryExposed || o.Message != text {
			t.Fatalf("%q projected as %#v, want family %q with no position", text, o, want)
		}
	}
	o := projectError(errors.New(`parse error at line 0, col 17: empty duration string`), `rate({app="api"}[])`)
	if o.Semantic != "syntax.duration" || o.Start == nil || *o.Start != 17 || o.End != nil || o.CategoryExposed {
		t.Fatalf("duration lexer error projected as %#v", o)
	}
}
func TestNativeLogQLSourceRetainsOriginalHashAfterLabelMutation(t *testing.T) {
	expr, e := syntax.ParseExpr(`{app="api"}|drop host`)
	if e != nil {
		t.Fatal(e)
	}
	q := &fixtureQuerier{entries: []entry{{Timestamp: "1", Multiplicity: "1", Line: "line", Labels: []label{{"app", "api"}, {"host", "z"}}}}}
	request := native.SelectLogParams{QueryRequest: &logproto.QueryRequest{Start: time.Unix(0, 0), End: time.Unix(0, 2), Direction: logproto.FORWARD, Plan: &plan.QueryPlan{AST: expr}}}
	it, e := q.SelectLogs(context.Background(), request)
	if e != nil {
		t.Fatal(e)
	}
	defer it.Close()
	if !it.Next() {
		t.Fatal("missing actual native row")
	}
	if it.StreamHash() != labels.FromStrings("app", "api", "host", "z").Hash() {
		t.Fatal("native source lineage hash replaced with zero or mutated labels")
	}
	if it.Labels() != `{app="api"}` {
		t.Fatalf("query label mutation not executed: %s", it.Labels())
	}
}
func TestNativeLogQLTemplateProjectsSpecificActualFailureOrigins(t *testing.T) {
	cases := []struct{ source, semantic string }{
		{`{{range $i,$v := 3}}x{{end}}`, "template.execution"},
		{`{{ (now).Zone }}`, "template.field-method"},
		{`{{ (now).Clock }}`, "template.field-method"},
		{`{{nil}}`, "template.execution"},
	}
	for _, c := range cases {
		o, e := observe(context.Background(), input{}, testCase{ID: "origin", Phase: "logql-template", Source: c.source, Timezone: "UTC"})
		if e != nil {
			t.Fatal(e)
		}
		if o.Error == nil || o.Error.Semantic != c.semantic || o.Error.Message == "" {
			t.Fatalf("actual source %q error %#v, want %s", c.source, o.Error, c.semantic)
		}
	}
}
func TestNativeLogQLApproximationUsesActualPlannerAndEvaluator(t *testing.T) {
	in := input{Enabled: []string{"approx_topk"}, Lookback: "30000000000", SketchHeap: 10000}
	c := testCase{ID: "approx-planner", Phase: "logql-metric", Kind: "instant", Time: "1000000000", Query: `approx_topk(1,count_over_time({app="api"}[1s]))`, Entries: []entry{{ID: "00000000000000000000000000000001", Timestamp: "1000000000", Multiplicity: "1", Line: "one", Labels: []label{{"app", "api"}}}}}
	o, e := observe(context.Background(), in, c)
	if e != nil {
		t.Fatal(e)
	}
	if o.Error != nil || !o.Accepted || o.Type != "vector" || len(o.Values) != 1 || o.Values[0].Bits != "3ff0000000000000" {
		t.Fatalf("actual approximation observation %#v", o)
	}
}
func TestNativeLogQLApproximationDisabledUsesActualPlannerRejection(t *testing.T) {
	in := input{Lookback: "30000000000", SketchHeap: 10000}
	c := testCase{ID: "approx-disabled", Phase: "logql-metric", Kind: "instant", Time: "1000000000", Query: `approx_topk(1,count_over_time({app="api"}[1s]))`}
	o, e := observe(context.Background(), in, c)
	if e != nil {
		t.Fatal(e)
	}
	if o.Accepted || o.Error == nil || o.Error.Semantic != "function.feature-disabled" {
		t.Fatalf("disabled native planner observation %#v", o)
	}
}
