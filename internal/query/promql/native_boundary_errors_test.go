// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/regexcompat"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
)

func TestParseNestingDepthIsBounded(t *testing.T) {
	p := featureProfile(t, "promql-prometheus-3.13.5")
	nest := func(depth int, open, inner, closer string) string {
		return strings.Repeat(open, depth) + inner + strings.Repeat(closer, depth)
	}
	for _, tc := range []struct {
		name  string
		build func(depth int) string
	}{
		{"parentheses", func(d int) string { return nest(d, "(", "m", ")") }},
		{"function calls", func(d int) string { return nest(d, "abs(", "m", ")") }},
		{"unary minus", func(d int) string { return strings.Repeat("-", d) + "m" }},
		{"left associative chain", func(d int) string { return "m" + strings.Repeat(" + m", d) }},
		{"right associative power", func(d int) string { return strings.Repeat("m ^ ", d) + "m" }},
		{"subquery chain", func(d int) string { return "m" + strings.Repeat("[5m:1m]", d) }},
	} {
		// A realistic depth parses.
		if _, err := Parse(tc.build(200), p); err != nil {
			t.Fatalf("%s depth 200: %v", tc.name, err)
		}
		start := time.Now()
		_, err := Parse(tc.build(200_000), p)
		var language *syntax.LanguageError
		if !errors.As(err, &language) || language.Code != "syntax.nesting-too-deep" || language.Category != "syntax" {
			t.Fatalf("%s depth 200000: %+v", tc.name, err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("%s: hostile nesting took %v to reject", tc.name, elapsed)
		}
	}
	// The limit itself is inclusive and exact for parentheses.
	if _, err := Parse(nest(maxParseDepth-1, "(", "m", ")"), p); err != nil {
		t.Fatalf("depth at the limit: %v", err)
	}
	if _, err := Parse(nest(maxParseDepth+1, "(", "m", ")"), p); err == nil {
		t.Fatal("depth past the limit accepted")
	}
}

type failingSource struct{ err error }

func (s failingSource) ProjectID() model.ID { return model.ID{1} }
func (s failingSource) Select(context.Context, scan.MetricSelection) (scan.SeriesIterator, error) {
	return nil, s.err
}

func evaluateWithSource(t *testing.T, ctx context.Context, src scan.MetricSource) error {
	t.Helper()
	p := featureProfile(t, "promql-prometheus-3.13.5")
	e, err := Parse("m", p)
	if err != nil {
		t.Fatal(err)
	}
	typed, _, err := Check(e, p)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(typed, instantAt(10_000), p)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = Evaluate(ctx, plan, src, value.NewBoundedAccount(1<<20))
	return err
}

func TestEvaluateReturnsTypedFaultsForCancellationAndRegexBudget(t *testing.T) {
	series := seriesSource{metricSeries("m", nil, msSample(0, 1))}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		src  scan.MetricSource
		code model.Code
	}{
		{"cancelled context", cancelled, series, model.Cancelled},
		{"expired deadline", expired, series, model.Timeout},
		{"cancellation from the source", context.Background(), failingSource{fmt.Errorf("scan: %w", context.Canceled)}, model.Cancelled},
		{"regex budget from the source", context.Background(), failingSource{fmt.Errorf("matcher: %w", regexcompat.ErrBudget)}, model.Quota},
		{"regex scope from the source", context.Background(), failingSource{regexcompat.ErrScope}, model.Invalid},
	} {
		err := evaluateWithSource(t, tc.ctx, tc.src)
		var fault *model.Fault
		if !errors.As(err, &fault) || fault.Code != tc.code {
			t.Fatalf("%s: %T %v want fault %s", tc.name, err, err, tc.code)
		}
	}
}
