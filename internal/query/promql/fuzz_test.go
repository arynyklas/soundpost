// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// fuzzSeed lists expressions that reach every function family, the native and
// classic histogram paths, extended selectors, subqueries, modifiers and the
// deliberately hostile spellings of the grammar. `go test` runs them as plain
// tests; `go test -fuzz FuzzParseCheckPlanEvaluate` mutates them.
var fuzzSeed = []string{
	`http_requests_total`, `rate(http_requests_total[10s])`, `increase(http_requests_total[10s] smoothed)`,
	`sum by (job) (rate(http_requests_total[10s]))`, `topk(1, http_requests_total)`, `limitk(1, http_requests_total)`,
	`histogram_quantile(0.9, sum by (le) (rate(cb_bucket[10s])))`, `histogram_quantile(0.5, nh_total)`,
	`histogram_fraction(0, 2, nh_total)`, `histogram_stddev(nh_total)`, `histogram_stdvar(nh_total)`,
	`rate(nh_total[10s])`, `irate(nh_total[10s])`, `sum(nh_total) + 1`, `nh_total / on() group_left() gauge_metric`,
	`http_requests_total offset 5s @ 10`, `http_requests_total @ start() offset -5s`, `rate(http_requests_total[5s:1s])`,
	`avg_over_time(gauge_metric[10s:step()])`, `label_replace(http_requests_total, "x", "$1", "job", "(.*)")`,
	`label_join(http_requests_total, "x", "-", "job", "code")`, `{__name__=~"http_.+", job!~""}`, `{"http_requests_total"}`,
	`quantile_over_time(0.5, gauge_metric[10s])`, `predict_linear(gauge_metric[10s], 5)`, `holt_winters(gauge_metric[10s], 0.5, 0.5)`,
	`double_exponential_smoothing(gauge_metric[10s], 0.5, 0.5)`, `count_values("v", gauge_metric)`, `absent(nonexistent)`,
	`scalar(gauge_metric) + vector(1) > bool 0`, `1 + 2 * 3 ^ 2 % 4`, `-(1)`, `foo[(5m)]`, `foo offset min_of(1h, 30m)`,
	`sort_by_label(http_requests_total, "code")`, `info(http_requests_total)`, `clamp(gauge_metric, -1, 1)`, `round(gauge_metric, 0.5)`,
	`timestamp(gauge_metric)`, `time() - 1`, `pi()`, `"string"`, `((((((((((1))))))))))`, `a{b="\xff"}`, "{a=\"\u0000\"}",
}

// fuzzSeries is a small fixed fixture: counter, gauge, native histogram and
// classic buckets. Rebuilt per execution so no run can see another's mutation.
func fuzzSeries() []value.Series {
	job := model.Labels{{Name: "job", Value: "a"}}
	classic := func(le string, count float64) value.Series {
		return metricSeries("cb_bucket", append(model.Labels{{Name: "le", Value: le}}, job...), relFloatSample(10, count), relFloatSample(15, count*2))
	}
	return []value.Series{
		metricSeries("http_requests_total", append(model.Labels{{Name: "code", Value: "200"}}, job...), relFloatSample(5, 1), relFloatSample(10, 2), relFloatSample(15, 4)),
		metricSeries("gauge_metric", job, relFloatSample(5, 3), relFloatSample(10, -1), relFloatSample(15, 2)),
		metricSeries("nh_total", job, relHistSample(10, relExp(6, 1, 4)), relHistSample(15, relExp(9, 1, 6))),
		classic("1", 1), classic("2", 2), classic("+Inf", 3),
	}
}

func fuzzProfiles(tb testing.TB) []profile.Profile {
	return []profile.Profile{
		featureProfile(tb, relP31), featureProfile(tb, relP313),
		featureProfile(tb, relP31, "promql-experimental-functions"), featureProfile(tb, relP313, "promql-experimental-functions"),
	}
}

// Whatever the bytes are, parsing, formatting, checking, planning and
// evaluating under a small budget must not panic or hang, and a formatted
// expression must reparse to the same formatting (Format is canonical).
func FuzzParseCheckPlanEvaluate(f *testing.F) {
	profiles := fuzzProfiles(f)
	for i, q := range fuzzSeed {
		f.Add(q, uint8(i))
	}
	f.Fuzz(func(t *testing.T, query string, which uint8) {
		if len(query) > 1024 {
			return
		}
		p := profiles[int(which)%len(profiles)]
		expr, err := Parse(query, p)
		if err != nil {
			return
		}
		formatted := Format(expr)
		again, err := Parse(formatted, p)
		if err != nil {
			t.Fatalf("Format output does not reparse: %q -> %q: %v", query, formatted, err)
		}
		if second := Format(again); second != formatted {
			t.Fatalf("Format is not canonical: %q -> %q -> %q", query, formatted, second)
		}
		typed, _, err := Check(expr, p)
		if err != nil {
			return
		}
		for _, evaluation := range []value.Evaluation{instantAt(20_000), rangeOf(10_000, 20_000, 5_000)} {
			plan, err := BuildPlan(typed, evaluation, p)
			if err != nil {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			// Any typed error is a legitimate answer; a panic or hang is not.
			_, _, _ = Evaluate(ctx, plan, seriesSource(fuzzSeries()), value.NewBoundedAccount(1<<22))
			cancel()
		}
	})
}

// A hostile deep nesting must be refused or bounded, never exhaust the stack or
// take unbounded time (review 02.03-07 M1, already guarded; pinned here).
func TestFuzzSeedDeepNestingIsBounded(t *testing.T) {
	p := featureProfile(t, relP313)
	deep := strings.Repeat("(", 5000) + "1" + strings.Repeat(")", 5000)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = Parse(deep, p)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("a 5000-deep expression was not parsed or refused within 30 s")
	}
}
