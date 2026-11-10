// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"fmt"
	"math"
	"reflect"
	"testing"

	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/query"
)

// manySeries is an instant vector of n series.
func manySeries(project model.ID, n int, value float64) func(query.Request) (query.Result, error) {
	return func(query.Request) (query.Result, error) {
		elems := make([]query.VectorElement, 0, n)
		for i := range n {
			elems = append(elems, elem(value, "instance", fmt.Sprintf("host-%05d.example.test", i), "job", "queue"))
		}
		return vectorResult(project, elems...), nil
	}
}

func schedulerFor(c *ctl, exec QueryExecutor, clock Clock, options ...Option) *Scheduler {
	e := c.evaluator(exec, clock, options...)
	return NewScheduler(e, c.committer(), NewStateStore(c.store), WithSchedulerClock(clock))
}

// An evaluation whose outputs exceed a control command's bound must still commit:
// a rule that can never advance, never record health and never say why is the
// failure this guards. The overflow is a reported outcome (error health with a
// closed reason, effects dropped, rule alive), never a bare Invalid.
func TestAlertWithMoreThanMaxOutputsCommitsAsAReportedError(t *testing.T) {
	c := newCtl(t)
	rule := c.alert(0, 0)
	series := 257
	exec := &fakeExec{fn: func(req query.Request) (query.Result, error) { return manySeries(c.project, series, 1)(req) }}
	clock := newClock(65)
	s := schedulerFor(c, exec, clock)
	lease := c.lease()

	report, err := s.RunOnce(c.ctx, c.reader(), c.admin(), rule, lease)
	if err != nil {
		t.Fatalf("an alert over %d series wedged: %v", series, err)
	}
	if !reflect.DeepEqual(report.Committed, []model.UnixNano{60 * sec}) {
		t.Fatalf("committed %+v", report.Committed)
	}
	state := c.state(rule)
	if state.Revision != 1 || state.Health != HealthError || state.Reason != ReasonTooManyOutputs || len(state.Series) != 0 {
		t.Fatalf("state after the overflowing evaluation: revision=%d health=%s reason=%s series=%d", state.Revision, state.Health, state.Reason, len(state.Series))
	}
	if got := c.outputs(rule, ""); len(got) != 0 {
		t.Fatalf("the dropped effects left %d outputs behind", len(got))
	}
	ev, found, err := NewStateStore(c.store).ReadEvaluation(c.ctx, c.reader(), rule.ID, 1, 60*sec)
	if err != nil || !found || ev.Outcome != OutcomeError || ev.Reason != ReasonTooManyOutputs || len(ev.Conditions) != 0 || len(ev.Members) != 0 {
		t.Fatalf("committed evaluation: %+v %v %v", ev, found, err)
	}

	// The rule is alive: once the result fits, the next grid point evaluates
	// normally, fires, and reports ok health again.
	series = 3
	clock.set(125)
	if report, err = s.RunOnce(c.ctx, c.reader(), c.admin(), rule, lease); err != nil || len(report.Committed) != 1 {
		t.Fatalf("next pass: %+v %v", report, err)
	}
	state = c.state(rule)
	if state.Revision != 2 || state.Health != HealthOK || len(state.Series) != 3 || len(c.outputs(rule, control.RulePhasePending)) != 3 {
		t.Fatalf("state after recovery of the rule: %+v", state)
	}
}

// The bound itself is exact: 256 outputs commit as before.
func TestAlertAtMaxOutputsCommitsNormally(t *testing.T) {
	c := newCtl(t)
	rule := c.alert(0, 0)
	clock := newClock(65)
	s := schedulerFor(c, &fakeExec{fn: manySeries(c.project, 256, 1)}, clock)
	if _, err := s.RunOnce(c.ctx, c.reader(), c.admin(), rule, c.lease()); err != nil {
		t.Fatal(err)
	}
	state := c.state(rule)
	if state.Health != HealthOK || len(state.Series) != 256 || len(c.outputs(rule, control.RulePhasePending)) != 256 {
		t.Fatalf("256 series: health=%s series=%d outputs=%d", state.Health, len(state.Series), len(c.outputs(rule, control.RulePhasePending)))
	}
}

// A recording rule whose committed payload would exceed the command bound is
// reported the same way; below the bound it records.
func TestRecordingPayloadOverflowIsAReportedError(t *testing.T) {
	for _, c := range []struct {
		name   string
		series int
		health Health
		reason string
	}{
		{"within the bound", 1000, HealthOK, ""},
		{"over the bound", 4000, HealthError, ReasonPayloadTooLarge},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newCtl(t)
			rule := f.recording()
			clock := newClock(65)
			s := schedulerFor(f, &fakeExec{fn: manySeries(f.project, c.series, math.Pi)}, clock, WithProducer(producer()))
			report, err := s.RunOnce(f.ctx, f.reader(), f.admin(), rule, f.lease())
			if err != nil || len(report.Committed) != 1 {
				t.Fatalf("%d-series recording rule wedged: %+v %v", c.series, report, err)
			}
			state := f.state(rule)
			if state.Revision != 1 || state.Health != c.health || state.Reason != c.reason {
				t.Fatalf("state: revision=%d health=%s reason=%q", state.Revision, state.Health, state.Reason)
			}
			outputs := f.outputs(rule, "")
			if (c.health == HealthOK) != (len(outputs) > 0) {
				t.Fatalf("%d outputs for health %s", len(outputs), c.health)
			}
		})
	}
}
