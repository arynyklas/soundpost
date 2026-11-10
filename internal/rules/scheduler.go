// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"context"
	"errors"

	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

// DefaultMaxBackfill bounds how many late grid points one scheduling pass
// evaluates after the newest (live) one.
const DefaultMaxBackfill = 16

// Scheduler drives one rule over its fixed evaluation grid under a lease. The
// grid is the multiples of the rule's interval; a scheduled time is a grid
// point, never the wall clock, and is immutable once committed. The scheduler
// owns no state: what has been evaluated is whatever control has committed.
//
// Evaluation reads with the project-scoped worker's read scope and commits with
// that principal's control scope; both name exactly the rule's project.
type Scheduler struct {
	evaluator   *Evaluator
	committer   *Committer
	store       RuleStateReader
	clock       Clock
	maxBackfill int
}

// SchedulerOption configures a Scheduler.
type SchedulerOption func(*Scheduler)

// WithSchedulerClock injects the clock the grid is cut from.
func WithSchedulerClock(c Clock) SchedulerOption { return func(s *Scheduler) { s.clock = c } }

// WithMaxBackfill bounds the late grid points evaluated per pass.
func WithMaxBackfill(n int) SchedulerOption {
	return func(s *Scheduler) {
		if n >= 0 {
			s.maxBackfill = n
		}
	}
}

// NewScheduler builds a scheduler over an evaluator, a committer and the state
// reader the evaluator reads.
func NewScheduler(e *Evaluator, c *Committer, store RuleStateReader, options ...SchedulerOption) *Scheduler {
	s := &Scheduler{evaluator: e, committer: c, store: store, clock: systemClock{}, maxBackfill: DefaultMaxBackfill}
	for _, option := range options {
		option(s)
	}
	return s
}

// Plan is what one pass should do: record Missed (grid points that passed
// without an on-time evaluation) and evaluate Due in ascending order. Every due
// point but the last is late, hence a backfill; the last is the live point.
type Plan struct {
	Due    []model.UnixNano
	Missed *MissedInterval
}

// PlanGrid computes the pass for rule at now from the committed state. The first
// grid point of a version that has never been evaluated is the newest one: a new
// version starts fresh and invents no history. Points before the newest are
// missed; at most maxBackfill of the most recent are still evaluated, the older
// ones stay unevaluated (recorded as missed, and treated by the reducer as a gap).
func PlanGrid(rule Rule, state State, now model.UnixNano, maxBackfill int) Plan {
	interval := model.UnixNano(rule.Interval)
	if interval <= 0 || now < interval {
		return Plan{}
	}
	newest := now - now%interval
	first := newest
	if state.Version == rule.Version && state.Applied != nil {
		first = state.Applied.At + interval
	}
	if first > newest {
		return Plan{}
	}
	count := uint64((newest-first)/interval) + 1
	var plan Plan
	if count > 1 {
		plan.Missed = &MissedInterval{From: first, To: newest - interval, Count: count - 1}
	}
	keep := uint64(maxBackfill) + 1
	if count > keep {
		first += model.UnixNano(count-keep) * interval
	}
	for at := first; at <= newest; at += interval {
		plan.Due = append(plan.Due, at)
	}
	return plan
}

// RunReport says what one pass did.
type RunReport struct {
	Plan           Plan
	MissedRecorded bool
	// Committed lists the scheduled times committed by this pass (including those
	// that were already committed and returned verbatim).
	Committed []model.UnixNano
}

const maxCommitAttempts = 3

// RunOnce performs one scheduling pass for rule under lease.
func (s *Scheduler) RunOnce(ctx context.Context, readScope, commitScope auth.Scope, rule Rule, lease replica.FenceToken) (RunReport, error) {
	if err := rule.Validate(); err != nil {
		return RunReport{}, err
	}
	state, err := s.store.Read(ctx, readScope, rule.ID)
	if err != nil {
		return RunReport{}, err
	}
	if state.Version > rule.Version {
		return RunReport{}, ruleFault(model.Stale, "rule_version_superseded")
	}
	now := s.clock.Now()
	report := RunReport{Plan: PlanGrid(rule, state, now, s.maxBackfill)}
	if m := report.Plan.Missed; m != nil {
		if _, err = s.committer.RecordMissed(ctx, commitScope, rule, *m, now, lease); err != nil {
			return report, err
		}
		report.MissedRecorded = true
	}
	for _, at := range report.Plan.Due {
		if err = s.commitAt(ctx, readScope, commitScope, rule, at, lease); err != nil {
			return report, err
		}
		report.Committed = append(report.Committed, at)
	}
	return report, nil
}

// commitAt evaluates and commits one grid point. A lost race (another evaluator
// committed first, or the state moved) is resolved by evaluating again, which
// returns whatever was committed first, verbatim.
func (s *Scheduler) commitAt(ctx context.Context, readScope, commitScope auth.Scope, rule Rule, at model.UnixNano, lease replica.FenceToken) error {
	var last error
	for range maxCommitAttempts {
		ev, err := s.evaluator.Evaluate(ctx, readScope, rule, at, lease)
		if err != nil {
			return err
		}
		if _, last = s.committer.Commit(ctx, commitScope, ev, lease); last == nil {
			return nil
		}
		var fault *model.Fault
		if !errors.As(last, &fault) || fault.Code != model.Conflict {
			return last
		}
	}
	return last
}
