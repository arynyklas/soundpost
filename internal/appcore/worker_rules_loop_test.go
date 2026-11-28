// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/rules"
)

// fleet adds projects-1 projects to the node and returns one firing rule in each of the projects (the node's own included).
func (n *workerNode) fleet(projects int) byProject {
	n.t.Helper()
	set := byProject{n.alertRule()}
	for range projects - 1 {
		id := model.NewID()
		n.addProject(id)
		set = append(set, n.alertRuleIn(id))
	}
	return set
}

// evaluatedAt is the grid points of the rule's committed evaluations, oldest first.
func (n *workerNode) evaluatedAt(rule rules.Rule) []model.UnixNano {
	n.t.Helper()
	book, found := n.book(rule)
	if !found || len(book.Versions) == 0 {
		return nil
	}
	var out []model.UnixNano
	for _, rec := range book.Versions[0].Recent {
		out = append(out, rec.At)
	}
	return out
}

// rulesAt counts the rules whose newest committed evaluation is the grid point at.
func (n *workerNode) rulesAt(set byProject, at model.UnixNano) int {
	n.t.Helper()
	count := 0
	for _, r := range set {
		if book, found := n.book(r); found && len(book.Versions) > 0 && book.Versions[0].Last != nil && book.Versions[0].Last.At == at {
			count++
		}
	}
	return count
}

func waitFor(t *testing.T, limit time.Duration, what func() string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("after %s: %s", limit, what())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// stallProducer is a producer stage that does not come back until the test ends: the pass that serves the
// stages after the rules is stuck in it, as it is while it commits for the projects ahead of the rest.
type stallProducer struct{ calls atomic.Int64 }

func (p *stallProducer) Produce(ctx context.Context, _ appcore.ProducerScopes, _ replica.FenceToken) (int, error) {
	p.calls.Add(1)
	<-ctx.Done()
	return 0, nil
}

// TestRuleEvaluationDoesNotWaitForTheOtherStagesOfTheProjects: a rule is evaluated at the pace of its own grid, whatever the
// rest of the pass is doing. 100 rules over 100 projects, one grid minute after another on the test clock, while the producer
// stage of the runner never returns: every rule has its evaluation of every minute, so 100 evaluations a minute at least.
// (When the rule step was one step of the serial pass over the projects, the pass never got past the first project's
// producer and evaluated one rule.)
func TestRuleEvaluationDoesNotWaitForTheOtherStagesOfTheProjects(t *testing.T) {
	const projects, minutes = 100, 3
	n := newWorkerNode(t)
	set := n.fleet(projects)
	stall := &stallProducer{}
	w, err := n.app.NewWorkers(n.config(func(c *appcore.WorkerConfig) {
		c.Rules = set
		c.MaxProjects = projects
		c.Producers = []appcore.Producer{stall}
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(n.ctx)
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	for minute := range minutes {
		at := workerGrid + model.UnixNano(minute)*model.UnixNano(time.Minute)
		waitFor(t, 60*time.Second, func() string {
			return fmt.Sprintf("the rules of grid minute %d (point %d) were evaluated for %d of %d projects, the producer stage was entered %d times", minute, at, n.rulesAt(set, at), projects, stall.calls.Load())
		}, func() bool { return n.rulesAt(set, at) == projects })
		n.clock.v.Add(int64(time.Minute))
	}
}

// idSender records every delivery ID it is handed.
type idSender struct {
	mu   sync.Mutex
	sent map[model.ID]int
}

func (s *idSender) Send(_ context.Context, _ auth.Scope, d notify.Delivery) (notify.Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sent == nil {
		s.sent = map[model.ID]int{}
	}
	s.sent[d.ID]++
	return notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: "provider-message-1"}, nil
}

// counts is the distinct deliveries sent and the ones sent more than once.
func (s *idSender) counts() (distinct, repeated int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.sent {
		distinct++
		if c > 1 {
			repeated++
		}
	}
	return distinct, repeated
}

// TestRulesEvaluatedBesideTheDeliveryStagesKeepTheirOrderAndSendOnce: the rule step and the other stages of the runner serve the
// same projects at the same time. Whatever the interleaving, a rule has one committed evaluation of each grid minute, in
// order, none twice and none skipped; each of the conditions the rules fired is decided and sent exactly once.
func TestRulesEvaluatedBesideTheDeliveryStagesKeepTheirOrderAndSendOnce(t *testing.T) {
	const projects, minutes = 12, 4
	n := newWorkerNode(t)
	set := n.fleet(projects)
	sender := &idSender{}
	w, err := n.app.NewWorkers(n.config(func(c *appcore.WorkerConfig) {
		c.Rules = set
		c.MaxProjects = projects
		c.Sender = sender
		c.Routing = hookRouting{binding: appcore.NotificationBinding{Policy: model.ID{0xf1}, Revision: 1, Config: notify.DefaultConfig(), Recipients: []model.ID{n.dest}}}
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(n.ctx)
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			cancel()
			<-done
		}
	}
	t.Cleanup(stop)

	for minute := range minutes {
		at := workerGrid + model.UnixNano(minute)*model.UnixNano(time.Minute)
		waitFor(t, 60*time.Second, func() string {
			return fmt.Sprintf("rules at grid minute %d: %d of %d", minute, n.rulesAt(set, at), projects)
		}, func() bool { return n.rulesAt(set, at) == projects })
		if minute < minutes-1 {
			n.clock.v.Add(int64(time.Minute))
		}
	}
	waitFor(t, 60*time.Second, func() string {
		d, r := sender.counts()
		return fmt.Sprintf("sent %d distinct deliveries, %d repeated, want %d", d, r, projects)
	}, func() bool {
		d, _ := sender.counts()
		return d >= projects
	})
	time.Sleep(time.Second) // a duplicate would be one more pass away
	stop()

	for _, r := range set {
		got := n.evaluatedAt(r)
		if len(got) != minutes {
			t.Fatalf("rule of project %s has %d evaluations %v, want %d", r.Project, len(got), got, minutes)
		}
		for i, at := range got {
			if want := workerGrid + model.UnixNano(i)*model.UnixNano(time.Minute); at != want {
				t.Fatalf("rule of project %s: evaluation %d is at %d, want %d (in order, none twice, none skipped): %v", r.Project, i, at, want, got)
			}
		}
	}
	distinct, repeated := sender.counts()
	if distinct != projects || repeated != 0 {
		t.Fatalf("%d projects fired once: %d distinct deliveries sent, %d of them more than once", projects, distinct, repeated)
	}
	accepted := 0
	for _, r := range set {
		recs, err := n.app.Control.Deliveries(n.ctx, n.adminFor(r.Project), r.Project, control.DeliveryAccepted, n.clock.Now(), 0)
		if err != nil {
			t.Fatal(err)
		}
		accepted += len(recs)
	}
	if accepted != projects {
		t.Fatalf("%d deliveries accepted in control, want %d", accepted, projects)
	}
}
