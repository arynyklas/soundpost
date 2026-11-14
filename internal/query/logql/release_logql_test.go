// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// Loki 3.5.2 hoists every line filter to the head of its stage segment, where a
// segment ends at a line_format or unpack stage (the two stages it knows rewrite
// the line). decolorize rewrites the line but does not end a segment, so a line
// filter written after it is matched against the original, still colored line.
func TestReleaseLogQLLineFilterHoistsOverDecolorize(t *testing.T) {
	colored := "\x1b[31merror\x1b[0m: ok"
	if r := run(t, `{app="api"}|decolorize|="error: ok"`, entry(colored)); r.Retained {
		t.Fatalf("filter after decolorize matched the decolorized line: %q", r.Entry.Line)
	}
	if r := run(t, `{app="api"}|decolorize!="\x1b"`, entry(colored)); r.Retained {
		t.Fatal("negated filter after decolorize did not see the original escape bytes")
	}
	r := run(t, `{app="api"}|decolorize|="\x1b[31merror"`, entry(colored))
	if !r.Retained || r.Entry.Line != "error: ok" {
		t.Fatalf("filter on the original bytes must retain the decolorized line, got %+v", r)
	}
	// line_format ends the segment: a filter after it sees the formatted line.
	r = run(t, `{app="api"}|decolorize|line_format "{{__line__}}"|="error: ok"`, entry(colored))
	if !r.Retained || r.Entry.Line != "error: ok" {
		t.Fatalf("filter after line_format must see the formatted line, got %+v", r)
	}
}

// A disabled multi-variant gate is rejected as a feature failure, not as a type error.
func TestReleaseLogQLVariantsDisabledIsFeatureCategory(t *testing.T) {
	p := testProfile(t)
	typed, err := parseCheck(t, `variants(count_over_time({app="api"}[2m])) of ({app="api"}[2m])`, p)
	if err != nil {
		t.Fatal(err)
	}
	_, err = BuildPlan(typed, value.Evaluation{Instant: true, Time: 2e9}, p)
	var diagnostic *syntax.LanguageError
	if !errors.As(err, &diagnostic) || diagnostic.Code != "function.feature-disabled" || diagnostic.Category != "feature" {
		t.Fatalf("disabled variants gate: %v", err)
	}
}

// approx_topk requires a positive integer k; any other k is an invalid argument
// of the function, the same family topk reports for a bad parameter.
func TestReleaseLogQLApproxTopkParameterIsFunctionArguments(t *testing.T) {
	enabled := profileWithGate(t, "approx_topk")
	for _, source := range []string{`approx_topk(0,vector(1))`, `approx_topk(1.5,vector(1))`} {
		_, err := parseCheck(t, source, enabled)
		if err == nil || languageCode(t, err) != "function.arguments" {
			t.Fatalf("%s: want function.arguments, got %v", source, err)
		}
	}
	if _, err := parseCheck(t, `approx_topk(2,vector(1))`, enabled); err != nil {
		t.Fatalf("positive integer k rejected: %v", err)
	}
	if _, err := parseCheck(t, `approx_topk by (app) (2,vector(1))`, enabled); err == nil || languageCode(t, err) != "grouping.unsupported" {
		t.Fatalf("grouping must be refused: %v", err)
	}
}

// Dropping the error label explicitly handles the failure: its details label
// describes that error and goes with it. keep never removes either.
func TestReleaseLogQLDropErrorLabelClearsDetails(t *testing.T) {
	for _, q := range []string{`{app="api"}|json|drop __error__`, `{app="api"}|json|drop __error__="JSONParserErr"`} {
		r := run(t, q, entry(`{bad`))
		if !r.Retained || lookup(r.Labels, "__error__") != "" || lookup(r.Labels, "__error_details__") != "" {
			t.Fatalf("%s: error labels survived an explicit drop: %+v", q, r.Labels)
		}
	}
	r := run(t, `{app="api"}|json|keep app`, entry(`{bad`))
	if lookup(r.Labels, "__error__") != "JSONParserErr" || lookup(r.Labels, "__error_details__") == "" {
		t.Fatalf("keep removed the error labels: %+v", r.Labels)
	}
}

type releaseRows struct {
	rows []PipelineResult
	at   int
}

func (i *releaseRows) Next(context.Context) (PipelineResult, error) {
	if i.at == len(i.rows) {
		return PipelineResult{}, io.EOF
	}
	r := i.rows[i.at]
	i.at++
	return r, nil
}
func (i *releaseRows) Watermarks() []model.Cursor { return nil }
func (i *releaseRows) Partial() bool              { return false }
func (i *releaseRows) Close() error               { return nil }

func releaseMerged(t *testing.T, order LogOrder, limit uint64, rows ...PipelineResult) []string {
	t.Helper()
	a := value.NewBoundedAccount(32 << 20)
	merged, err := MergeLogs(context.Background(), []EntryIterator{&releaseRows{rows: rows}}, order, limit, a)
	if err != nil {
		t.Fatal(err)
	}
	defer merged.Close()
	var lines []string
	for {
		r, e := merged.Next(context.Background())
		if e == io.EOF {
			return lines
		}
		if e != nil {
			t.Fatal(e)
		}
		for n := model.Uint64(0); n < r.Entry.Multiplicity; n++ {
			lines = append(lines, r.Entry.Line)
		}
		a.Release(r.Bytes)
	}
}

func releaseRow(id byte, at int64, line string, host string) PipelineResult {
	labels := model.Labels{{Name: "app", Value: "api"}, {Name: "host", Value: host}}
	return PipelineResult{Retained: true, Entry: LogEntry{ID: model.ID{id}, Timestamp: model.UnixNano(at), Multiplicity: 1, Line: line}, Labels: labels, OriginalStreamLabels: labels}
}

// Merged log iterators order by timestamp (direction decides), and entries of one
// stream with one timestamp keep the order in which they were encountered in both
// directions, whatever their text; equal text never collapses (owned multiplicity
// is not upstream replica merging).
func TestReleaseLogQLEntryMergeKeepsEncounterOrderOfTies(t *testing.T) {
	same := func(want, got []string) bool {
		if len(want) != len(got) {
			return false
		}
		for i := range want {
			if want[i] != got[i] {
				return false
			}
		}
		return true
	}
	ties := []PipelineResult{releaseRow(1, 1000, "x", "a"), releaseRow(2, 1000, "same", "a"), releaseRow(3, 1000, "same", "a"), releaseRow(4, 2000, "later", "a")}
	if got := releaseMerged(t, Forward, 10, ties...); !same([]string{"x", "same", "same", "later"}, got) {
		t.Fatalf("forward: %v", got)
	}
	if got := releaseMerged(t, Backward, 10, ties...); !same([]string{"later", "x", "same", "same"}, got) {
		t.Fatalf("backward: %v", got)
	}
	// The limit counts accepted entries globally, cutting inside a run of ties.
	if got := releaseMerged(t, Backward, 3, ties...); !same([]string{"later", "x", "same"}, got) {
		t.Fatalf("backward limit: %v", got)
	}
}

// Within one formatter every template renders from one label snapshot taken when
// the first template is evaluated; renames update the builder immediately, so a
// rename that precedes the first template is visible and a rename that follows it
// is not.
func TestReleaseLogQLLabelFormatSnapshotIsTakenAtFirstTemplate(t *testing.T) {
	r := run(t, `{app="api"}|logfmt|label_format x=a,y="{{.a}}"`, entry(`a=1`))
	if lookup(r.Labels, "x") != "1" || lookup(r.Labels, "a") != "" || lookup(r.Labels, "y") != "" {
		t.Fatalf("rename before the first template: %+v", r.Labels)
	}
	r = run(t, `{app="api"}|logfmt|label_format y="{{.a}}",x=a,z="{{.a}}"`, entry(`a=1`))
	if lookup(r.Labels, "x") != "1" || lookup(r.Labels, "a") != "" || lookup(r.Labels, "y") != "1" || lookup(r.Labels, "z") != "1" {
		t.Fatalf("rename after the first template: %+v", r.Labels)
	}
}
