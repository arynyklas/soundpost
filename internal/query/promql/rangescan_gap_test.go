// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// A range evaluation whose step is longer than the window of its selector (a 24 h range at a 10 minute step of
// rate(x[5m]): the shape of the organization query of the Queries gate) was evaluated one storage scan per
// step, because the windows do not touch and the union of them would read what no step reads. 144 steps of
// 10 projects were 1,440 scans, each with its own admission fence, authority reads and release barriers: more
// than half of the CPU of the gate mix. When the windows are not further apart than their own width times
// sharedGapFactor, the union is read once (at most that many times the rows the steps need) and each step
// still cuts its own window out of it: the result, the annotations, the statistics, the errors and the budgets
// are those of the per-step evaluation (TestRangeSharedScansMatchPerStepEvaluation runs this shape).
func TestRangeEvaluationWithGapsBetweenWindowsReadsEachSelectorOnce(t *testing.T) {
	fixture := rangeFixture(3)
	for _, id := range []string{relP31, relP313} {
		p := featureProfile(t, id)
		for _, c := range []struct {
			query     string
			step      int64 // ms
			selectors int
			shared    bool
		}{
			{`sum by (job) (rate(c_total[5m]))`, 600_000, 1, true}, // window 5 m, step 10 m
			{`max_over_time(m[1m])`, 240_000, 1, true},             // window 1 m, step 4 m
			{`rate(c_total[5m]) / rate(c_total[5m] offset 5m)`, 600_000, 2, true},
			{`rate(c_total[1m])`, 3_600_000, 1, false}, // window 1 m, step 1 h: the union would read 60 times what the steps need
		} {
			ev := rangeOf(600_000, 3_600_000-1000, c.step)
			plan := planFor(t, p, c.query, ev)
			steps := int64(len(mustGrid(t, ev)))
			perStep, shared := &scanSource{series: fixture}, &scanSource{series: fixture}
			ref := runPlan(plan, perStep, 1<<28, false)
			got := runPlan(plan, shared, 1<<28, true)
			sameOutcome(t, fmt.Sprintf("%s %s step %d", id, c.query, c.step), ref, got)
			t.Logf("%s %-52s steps=%d per-step: selects=%d rows=%d | shared: selects=%d rows=%d", id, c.query, steps, perStep.calls, perStep.rows, shared.calls, shared.rows)
			if int64(perStep.calls) < steps {
				t.Fatalf("%s %s: the per-step reference made %d selects for %d steps", id, c.query, perStep.calls, steps)
			}
			if c.shared && shared.calls != c.selectors {
				t.Fatalf("%s %s: %d selects with windows %d ms apart, want %d (one per selector)", id, c.query, shared.calls, c.step, c.selectors)
			}
			if !c.shared && int64(shared.calls) < steps {
				t.Fatalf("%s %s: %d selects for %d steps: windows far apart must not be read as one union", id, c.query, shared.calls, steps)
			}
		}
	}
}

// A shared scan is one scan with one cut, the per-step evaluation is one scan per step and each of them takes
// the cut of its own moment, later and later. The answer must still be the same: the cut a query reports is
// the earliest one any of its reads used (the reads of one query are certified at the cut of the first), and
// the rows each step uses are the rows of its own window. The fixture moves the cut by one commit per scan.
func TestRangeSharedScanMatchesPerStepEvaluationWhenTheCutMovesBetweenSteps(t *testing.T) {
	fixture := rangeFixture(3)
	cut := []model.Cursor{{Group: model.ID{2}, Index: 100}, {Group: model.ID{3}, Index: 7}}
	for _, id := range []string{relP31, relP313} {
		p := featureProfile(t, id)
		for _, c := range []struct {
			query string
			step  int64
		}{
			{`sum by (job) (rate(c_total[5m]))`, 600_000}, // windows with gaps
			{`rate(c_total[5m])`, 60_000},                 // overlapping windows
			{`max_over_time(m[1m])`, 240_000},
		} {
			ev := rangeOf(600_000, 3_600_000-1000, c.step)
			plan := planFor(t, p, c.query, ev)
			perStep := &scanSource{series: fixture, cursors: cut, moving: true}
			shared := &scanSource{series: fixture, cursors: cut, moving: true}
			ref := runPlan(plan, perStep, 1<<28, false)
			got := runPlan(plan, shared, 1<<28, true)
			sameOutcome(t, fmt.Sprintf("%s %s step %d moving cut", id, c.query, c.step), ref, got)
			if perStep.calls < 2 || shared.calls >= perStep.calls {
				t.Fatalf("%s %s: per-step %d selects, shared %d: the cut did not move between scans", id, c.query, perStep.calls, shared.calls)
			}
			marks := got.result.Watermarks
			if len(marks) != len(cut) || marks[0].Index != cut[0].Index+1 || marks[1].Index != cut[1].Index+1 {
				t.Fatalf("%s %s: reported cut %v, want the cut of the first scan (one commit past %v)", id, c.query, marks, cut)
			}
		}
	}
}
