// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
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

// An alert whose single tick transitions more series than one control command
// carries must still fire every one of them: the evaluation is committed in
// several commands under one identity (the surplus is staged, the evaluation
// command promotes it), never reported as an error that drops the alerts.
func TestAlertWithMoreThanOneCommandOfOutputsFiresEverySeries(t *testing.T) {
	const series = 600
	c := newCtl(t)
	rule := c.alert(0, 0)
	exec := &fakeExec{fn: manySeries(c.project, series, 1)}
	clock := newClock(65)
	s := schedulerFor(c, exec, clock)

	report, err := s.RunOnce(c.ctx, c.reader(), c.admin(), rule, c.lease())
	if err != nil {
		t.Fatalf("an alert over %d series wedged: %v", series, err)
	}
	if !reflect.DeepEqual(report.Committed, []model.UnixNano{60 * sec}) {
		t.Fatalf("committed %+v", report.Committed)
	}
	state := c.state(rule)
	if state.Revision != 1 || state.Health != HealthOK || state.Reason != "" || len(state.Series) != series {
		t.Fatalf("state after the evaluation: revision=%d health=%s reason=%q series=%d", state.Revision, state.Health, state.Reason, len(state.Series))
	}
	pending := c.outputs(rule, control.RulePhasePending)
	if len(pending) != series {
		t.Fatalf("%d pending outputs for %d transitioning series", len(pending), series)
	}
	ids := map[model.ID]bool{}
	for _, o := range pending {
		ids[o.ID] = true
		if o.Version != rule.Version || o.At != 60*sec {
			t.Fatalf("output %s is not of the evaluation (version %d at %d)", o.ID, o.Version, o.At)
		}
	}
	if len(ids) != series {
		t.Fatalf("%d distinct outputs among %d", len(ids), series)
	}
	if got := c.outputs(rule, control.RulePhaseStaged); len(got) != 0 {
		t.Fatalf("%d outputs are still staged", len(got))
	}
	ev, found, err := NewStateStore(c.store).ReadEvaluation(c.ctx, c.reader(), rule.ID, rule.Version, 60*sec)
	if err != nil || !found || ev.Outcome == OutcomeError || len(ev.Conditions) != series {
		t.Fatalf("committed evaluation: outcome=%s conditions=%d found=%v err=%v", ev.Outcome, len(ev.Conditions), found, err)
	}
}

// A leader that stages part of an evaluation and then fails before the evaluation
// command lands has committed nothing a consumer can see; its retry completes the
// same evaluation, once.
func TestAlertStagedOutputsAreInertUntilTheEvaluationLands(t *testing.T) {
	const series = 600
	c := newCtl(t)
	rule := c.alert(0, 0)
	clock := newClock(65)
	e := c.evaluator(&fakeExec{fn: manySeries(c.project, series, 1)}, clock)
	crash := &dropEvaluation{Control: c.store}
	crash.drop.Store(true)
	s := NewScheduler(e, NewCommitter(crash, c.store.ReplicaGroup()), NewStateStore(c.store), WithSchedulerClock(clock))
	lease := c.lease()

	if _, err := s.RunOnce(c.ctx, c.reader(), c.admin(), rule, lease); err == nil {
		t.Fatal("the evaluation command was dropped but the run reported success")
	}
	if got := c.outputs(rule, ""); len(got) != 0 {
		t.Fatalf("%d outputs of an unfinished evaluation are visible", len(got))
	}
	if got := c.outputs(rule, control.RulePhaseStaged); len(got) != series-control.MaxRuleOutputs {
		t.Fatalf("%d staged outputs, want %d", len(got), series-control.MaxRuleOutputs)
	}
	if state := c.state(rule); state.Revision != 0 {
		t.Fatalf("an unfinished evaluation advanced the state to revision %d", state.Revision)
	}

	crash.drop.Store(false)
	if _, err := s.RunOnce(c.ctx, c.reader(), c.admin(), rule, lease); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if got := c.outputs(rule, control.RulePhasePending); len(got) != series {
		t.Fatalf("%d pending outputs after the retry, want %d", len(got), series)
	}
	if got := c.outputs(rule, control.RulePhaseStaged); len(got) != 0 {
		t.Fatalf("%d staged outputs after the retry", len(got))
	}
	if state := c.state(rule); state.Revision != 1 || state.Health != HealthOK {
		t.Fatalf("state after the retry: revision=%d health=%s", state.Revision, state.Health)
	}
}

// dropEvaluation loses every evaluation command (as a leader that dies between
// its staging commands and the evaluation command would).
type dropEvaluation struct {
	Control
	drop atomic.Bool
}

func (d *dropEvaluation) Transact(ctx context.Context, scope auth.Scope, cmd control.Command) (control.Result, error) {
	var rc control.RuleCommand
	if json.Unmarshal(cmd.Payload, &rc) == nil && rc.Operation == control.RuleOpEvaluation && d.drop.Load() {
		return control.Result{}, model.Fail(model.Unavailable)
	}
	return d.Control.Transact(ctx, scope, cmd)
}

// Beyond the evaluation bound (staged plus finalizing outputs) the overflow is a
// reported outcome: error health with a closed reason, effects dropped, rule alive.
func TestAlertBeyondTheEvaluationBoundCommitsAsAReportedError(t *testing.T) {
	c := newCtl(t)
	rule := c.alert(0, 0)
	series := control.MaxRuleEvaluationOutputs + 1
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
	if got := c.outputs(rule, control.RulePhaseStaged); len(got) != 0 {
		t.Fatalf("the dropped effects left %d staged outputs behind", len(got))
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

// The evaluation payload (1 MiB, it embeds every series' state) is the practical
// ceiling of an alert: 1,500 series fit, 2,000 are reported as payload_too_large
// even though both are under the output bound.
func TestAlertCeilingIsTheEvaluationPayload(t *testing.T) {
	for _, c := range []struct {
		series int
		health Health
		reason string
	}{
		{1500, HealthOK, ""},
		{2000, HealthError, ReasonPayloadTooLarge},
	} {
		f := newCtl(t)
		rule := f.alert(0, 0)
		s := schedulerFor(f, &fakeExec{fn: manySeries(f.project, c.series, 1)}, newClock(65))
		if _, err := s.RunOnce(f.ctx, f.reader(), f.admin(), rule, f.lease()); err != nil {
			t.Fatalf("%d series: %v", c.series, err)
		}
		state := f.state(rule)
		if state.Health != c.health || state.Reason != c.reason || (c.health == HealthOK) != (len(f.outputs(rule, control.RulePhasePending)) == c.series) {
			t.Fatalf("%d series: health=%s reason=%q pending=%d", c.series, state.Health, state.Reason, len(f.outputs(rule, control.RulePhasePending)))
		}
	}
}
