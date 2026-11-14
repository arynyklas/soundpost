// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/value"
	"math"
	"testing"
)

func entry(line string) LogEntry {
	return LogEntry{ID: model.NewID(), Timestamp: 123, Multiplicity: 1, Line: line, StreamLabels: model.Labels{{Name: "app", Value: "api"}}}
}
func run(t *testing.T, q string, e LogEntry) PipelineResult {
	t.Helper()
	r, err := RunPipeline(context.Background(), testPlan(t, q), e, value.NewBoundedAccount(16<<20))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func lookup(ls model.Labels, n string) string {
	for _, l := range ls {
		if l.Name == n {
			return l.Value
		}
	}
	return ""
}
func TestPipelineMutationOrder(t *testing.T) {
	e := entry(`{"n":"2"}`)
	a := run(t, `{app="api"}|json|n="2"`, e)
	b := run(t, `{app="api"}|n="2"|json`, e)
	if !a.Retained || b.Retained || a.Entry.Line != e.Line {
		t.Fatal("pipeline stages reordered or line changed")
	}
}
func TestParserErrorsRemainLabels(t *testing.T) {
	for _, tc := range []struct{ q, line, want string }{{`{app="api"}|json`, `{broken`, `JSONParserErr`}, {`{app="api"}|logfmt --strict`, `x="unterminated`, `LogfmtParserErr`}, {`{app="api"}|json|n>2`, `{"n":"no"}`, `LabelFilterErr`}, {`{app="api"}|json|n>2ms`, `{"n":"no"}`, `LabelFilterErr`}, {`{app="api"}|json|n>2KiB`, `{"n":"no"}`, `LabelFilterErr`}} {
		r := run(t, tc.q, entry(tc.line))
		if !r.Retained || lookup(r.Labels, "__error__") != tc.want {
			t.Fatalf("missing error label: %+v", r)
		}
	}
	r := run(t, `{app="api"}|json|__error__=""`, entry(`{broken`))
	if r.Retained {
		t.Fatal("explicit error filter did not remove record")
	}
}
func TestNewlineSelectorAndExtractionCollision(t *testing.T) {
	e := entry(`{"level":"parsed","nested":{"a-b":2}}`)
	e.StreamLabels = append(e.StreamLabels, model.Label{Name: "level", Value: "stream"}, model.Label{Name: "multiline", Value: "a\nb"})
	r := run(t, `{multiline=~"a.b"}|json|level_extracted="parsed"`, e)
	if !r.Retained || lookup(r.Labels, "level") != "stream" || lookup(r.Labels, "level_extracted") != "parsed" || lookup(r.Labels, "nested_a_b") != "2" {
		t.Fatal("anchoring, dot newline or collision mismatch")
	}
	if !run(t, `{app="api"}|missing=""`, e).Retained || run(t, `{app="api"}|missing!=""`, e).Retained {
		t.Fatal("missing labels not empty")
	}
	if run(t, `{app="api"}|~"a.b"`, entry("a\nb")).Retained {
		t.Fatal("line dot unexpectedly matched newline")
	}
}
func TestStageOrderErrorFilterAndMetadata(t *testing.T) {
	e := entry("{broken")
	e.StructuredMetadata = model.Labels{{Name: "region", Value: "north"}}
	r := run(t, `{app="api"}|json|label_format old=region|keep old`, e)
	if !r.Retained || lookup(r.Labels, "old") != "north" || lookup(r.Labels, "__error__") != "JSONParserErr" || lookup(r.Labels, "region") != "" {
		t.Fatal("metadata rename or error keep behavior")
	}
	if run(t, `{app="api"}|json|label_format old=region|__error__=""`, e).Retained {
		t.Fatal("error vanished through mutation")
	}
	if run(t, `{region="north"}`, e).Retained {
		t.Fatal("metadata promoted to selector")
	}
	if len(e.StructuredMetadata) != 1 || e.StructuredMetadata[0].Name != "region" || e.Line != "{broken" {
		t.Fatal("borrowed entry mutated")
	}
}
func TestPipelineParsersAndStableIdentity(t *testing.T) {
	for _, tc := range []struct{ q, line, label, want string }{{`{app="api"}|logfmt --keep-empty`, `code=201 empty= user="a b"`, "user", "a b"}, {`{app="api"}|json x="items[1].name"`, `{"items":[{}, {"name":"second"}]}`, "x", "second"}, {`{app="api"}|regexp "(?P<code>[0-9]+)"`, "code 201", "code", "201"}, {`{app="api"}|pattern "<verb> <_> <code>"`, "GET /example 201", "code", "201"}, {`{app="api"}|unpack`, `{"_entry":"safe","region":"north"}`, "region", "north"}} {
		e := entry(tc.line)
		e.Multiplicity = 7
		r := run(t, tc.q, e)
		if !r.Retained || lookup(r.Labels, tc.label) != tc.want || r.Entry.ID != e.ID || r.Entry.Timestamp != e.Timestamp || r.Entry.Multiplicity != 7 {
			t.Fatalf("parser or identity mismatch: %+v", r)
		}
	}
}
func TestPipelineCancellationAndMemoryAreErrors(t *testing.T) {
	p := testPlan(t, `{app="api"}|json`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunPipeline(ctx, p, entry(`{}`), value.NewBoundedAccount(1<<20)); err == nil {
		t.Fatal("cancellation became success")
	}
	if _, err := RunPipeline(context.Background(), p, entry(`{"n":"2"}`), value.NewBoundedAccount(1)); err == nil {
		t.Fatal("memory exhaustion became success")
	}
}

func TestPipelineAuthoredConformanceCases(t *testing.T) {
	for _, c := range authoredCases(t) {
		if c.Phase != "pipeline" {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			in := c.Input.Entry
			e := LogEntry{Timestamp: in.Timestamp, ID: in.ID, Multiplicity: in.Multiplicity, Line: in.Line, StreamLabels: in.StreamLabels, StructuredMetadata: in.StructuredMetadata, Fields: in.Fields}
			account := value.NewBoundedAccount(16 << 20)
			r, err := RunPipeline(context.Background(), testPlan(t, c.Input.Expression), e, account)
			if err != nil {
				t.Fatal(err)
			}
			if r.Retained != c.Expected.Retained {
				t.Fatalf("retained=%v want=%v", r.Retained, c.Expected.Retained)
			}
			if r.Retained {
				if r.Entry.Line != c.Expected.Line {
					t.Fatal("unexpected pipeline line")
				}
				for _, want := range c.Expected.LabelsSubset {
					if !labelPresent(r.Labels, want.Name) || lookup(r.Labels, want.Name) != want.Value {
						t.Fatalf("label %s mismatch", want.Name)
					}
				}
				for _, n := range c.Expected.AbsentLabels {
					if labelPresent(r.Labels, n) {
						t.Fatalf("label %s unexpectedly retained", n)
					}
				}
				if c.Expected.UnwrappedBits != nil && (r.Unwrapped == nil || model.FloatBits(math.Float64bits(*r.Unwrapped)) != *c.Expected.UnwrappedBits) {
					t.Fatal("unwrapped float bits mismatch")
				}
				if r.Entry.ID != e.ID || r.Entry.Timestamp != e.Timestamp || r.Entry.Multiplicity != e.Multiplicity {
					t.Fatal("entry identity mutated")
				}
				account.Release(r.Bytes)
			}
			if account.Used() != 0 {
				t.Fatal("pipeline account leaked")
			}
		})
	}
}

func TestPipelineStoredProjectionNeverRerendersOrPromotesFields(t *testing.T) {
	var number, region model.Scalar
	if json.Unmarshal([]byte(`7`), &number) != nil || json.Unmarshal([]byte(`"north"`), &region) != nil {
		t.Fatal("invalid scalar fixture")
	}
	row := scan.LogRow{ID: model.NewID(), Source: model.NewID(), Timestamp: 9007199254740993, Multiplicity: 7, Record: model.LogRecord{Line: "immutable admitted rendering", TemplateID: "retired-revision", TemplateRevision: 1, Fields: map[string]model.Scalar{"number": number}, Metadata: map[string]model.Scalar{"region": region}, StreamLabels: model.Labels{{Name: "app", Value: "api"}}}}
	account := value.NewBoundedAccount(1 << 20)
	r, err := RunLogRow(context.Background(), testPlan(t, `{app="api"}|region="north"|number=""`), row, account)
	if err != nil || !r.Retained {
		t.Fatalf("stored projection: %v", err)
	}
	if r.Entry.Line != row.Record.Line || r.Entry.Timestamp != row.Timestamp || r.Entry.Multiplicity != 7 || r.Entry.ID != row.ID || len(r.Entry.Fields) != 1 || lookup(r.Entry.StreamLabels, "region") != "" || lookup(r.Entry.StructuredMetadata, "region") != "north" {
		t.Fatal("stored safe rendering, identity or categories lost")
	}
	account.Release(r.Bytes)
	if account.Used() != 0 {
		t.Fatal("stored projection accounting leaked")
	}
	r, err = RunLogRow(context.Background(), testPlan(t, `{region="north"}`), row, account)
	if err != nil || r.Retained {
		t.Fatal("metadata promoted to stream selector")
	}
}

type parserDenyAccount struct {
	*value.BoundedAccount
	checks  int
	failure error
}

func (a *parserDenyAccount) Check(ctx context.Context) error {
	a.checks++
	if a.checks >= 4 {
		return a.failure
	}
	return a.BoundedAccount.Check(ctx)
}
func TestPipelineRevalidationDuringParserIsQueryError(t *testing.T) {
	for _, tc := range []struct{ query, line string }{{`{app="api"}|json`, `{"a":1,"b":2}`}, {`{app="api"}|logfmt`, `a=1 b=2`}, {`{app="api"}|unpack`, `{"_entry":"safe","a":"1"}`}} {
		failure := errors.New("scope revoked")
		account := &parserDenyAccount{BoundedAccount: value.NewBoundedAccount(1 << 20), failure: failure}
		r, err := RunPipeline(context.Background(), testPlan(t, tc.query), entry(tc.line), account)
		if !errors.Is(err, failure) || r.Retained || len(r.Labels) != 0 {
			t.Fatalf("parser hid revalidation failure: %+v %v", r, err)
		}
		if account.Used() != 0 {
			t.Fatal("interrupted parser leaked accounting")
		}
	}
}

func TestPipelineOriginalOutputCategoriesSurviveMutation(t *testing.T) {
	input := entry("safe")
	input.StreamLabels = append(input.StreamLabels, model.Label{Name: "level", Value: "initial"})
	input.StructuredMetadata = model.Labels{{Name: "region", Value: "north"}}
	account := value.NewBoundedAccount(1 << 20)
	result, err := RunPipeline(context.Background(), testPlan(t, `{app="api"}|label_format area=region|drop level|keep area`), input, account)
	if err != nil || !result.Retained {
		t.Fatal(err)
	}
	if len(result.Entry.StreamLabels) != 0 || len(result.Entry.StructuredMetadata) != 0 || lookup(result.Labels, "area") != "north" {
		t.Fatal("query category mutation missing")
	}
	if lookup(result.OriginalStreamLabels, "app") != "api" || lookup(result.OriginalStreamLabels, "level") != "initial" || lookup(result.OriginalStructuredMetadata, "region") != "north" {
		t.Fatal("original category snapshot mutated")
	}
	result.OriginalStreamLabels[0].Value = "changed"
	result.OriginalStructuredMetadata[0].Value = "changed"
	if lookup(input.StreamLabels, "app") != "api" || lookup(input.StructuredMetadata, "region") != "north" || lookup(result.Labels, "area") != "north" {
		t.Fatal("snapshot backing storage aliases input or query labels")
	}
	account.Release(result.Bytes)
	if account.Used() != 0 {
		t.Fatal("original snapshot accounting leaked")
	}
}

func TestPipelineExtractionCollisionUsesAdmissionNamespace(t *testing.T) {
	input := entry(`{"level":"parsed"}`)
	input.StreamLabels = append(input.StreamLabels, model.Label{Name: "level", Value: "admitted"})
	result := run(t, `{app="api"}|drop level|json`, input)
	if !result.Retained || lookup(result.Labels, "level") != "" || lookup(result.Labels, "level_extracted") != "parsed" || lookup(result.OriginalStreamLabels, "level") != "admitted" {
		t.Fatal("drop changed the immutable extraction collision namespace")
	}
}
