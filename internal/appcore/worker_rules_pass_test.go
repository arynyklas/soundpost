// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/rules"
)

// gaugeRules is a rule source that holds each call a moment and remembers how many calls were open at once.
type gaugeRules struct {
	inner byProject
	open  atomic.Int64
	peak  atomic.Int64
}

func (g *gaugeRules) Rules(ctx context.Context, scope auth.Scope, project model.ID) ([]rules.Rule, error) {
	now := g.open.Add(1)
	defer g.open.Add(-1)
	for {
		peak := g.peak.Load()
		if now <= peak || g.peak.CompareAndSwap(peak, now) {
			break
		}
	}
	time.Sleep(20 * time.Millisecond)
	return g.inner.Rules(ctx, scope, project)
}

// TestRuleTickServesTheProjectsWithBoundedConcurrency: one rule pass evaluates the rules of every project once, never more
// than RuleWorkers projects at a time, reports what each step cost, runs no other stage, and a second pass at the same instant
// commits nothing.
func TestRuleTickServesTheProjectsWithBoundedConcurrency(t *testing.T) {
	const projects, workers = 30, 3
	n := newWorkerNode(t)
	gauge := &gaugeRules{inner: n.fleet(projects)}
	w, err := n.app.NewWorkers(n.config(func(c *appcore.WorkerConfig) {
		c.Rules = gauge
		c.MaxProjects = projects
		c.RuleWorkers = workers
	}))
	if err != nil {
		t.Fatal(err)
	}
	rep := w.RuleTick(n.ctx)
	if len(rep.Errors) != 0 || !rep.Leader || rep.Projects != projects || rep.Evaluated != projects {
		t.Fatalf("rule pass: %+v, want %d projects and %d evaluations", rep, projects, projects)
	}
	if peak := gauge.peak.Load(); peak < 2 || peak > workers {
		t.Fatalf("%d projects were served at once, want between 2 and the bound %d", peak, workers)
	}
	if rep.Took <= 0 || rep.Steps.Rules <= 0 || rep.Steps.Evaluate <= 0 || rep.Steps.Commit <= 0 || rep.Steps.Evaluate+rep.Steps.Commit > rep.Steps.Rules {
		t.Fatalf("the pass did not report where its time went: took %s, steps %+v", rep.Took, rep.Steps)
	}
	if rep.Steps.Produce != 0 || rep.Steps.Consume != 0 || rep.Steps.Outbox != 0 {
		t.Fatalf("a rule pass ran a stage beyond the rules: %+v", rep.Steps)
	}
	before, _ := n.commitsByKind()
	if again := w.RuleTick(n.ctx); again.Evaluated != 0 || len(again.Errors) != 0 {
		t.Fatalf("a second rule pass at the same instant: %+v", again)
	}
	if after, _ := n.commitsByKind(); after != before {
		t.Fatalf("a second rule pass at the same instant moved the control revision from %d to %d", before, after)
	}
}

// TestRuleTickOfADeposedLeaderCommitsNothing: the lease is proved before a project is served and by every effect, whichever of
// the concurrent servers meets the loss first.
func TestRuleTickOfADeposedLeaderCommitsNothing(t *testing.T) {
	n := newWorkerNode(t)
	set := n.fleet(8)
	fence := n.fence()
	fence.deposed.Store(true)
	w, err := n.app.NewWorkers(n.config(func(c *appcore.WorkerConfig) { c.Rules = set; c.Fence = fence; c.MaxProjects = 8 }))
	if err != nil {
		t.Fatal(err)
	}
	rep := w.RuleTick(n.ctx)
	if !rep.Leader || !rep.Deposed || rep.Evaluated != 0 {
		t.Fatalf("a deposed rule pass: %+v", rep)
	}
	for _, r := range set {
		if _, found := n.book(r); found {
			t.Fatalf("a deposed leader committed an evaluation of project %s", r.Project)
		}
	}
}
