// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
)

func (r *issueRig) only(producers ...appcore.Producer) *appcore.Workers {
	r.t.Helper()
	w, err := r.app.NewWorkers(r.config(func(c *appcore.WorkerConfig) { c.Producers = producers }))
	if err != nil {
		r.t.Fatal(err)
	}
	return w
}

// resolver is the lifecycle a person resolves an issue through (the graph, fence
// and policy seams are the permissive test ones; the store is the real one).
func (r *issueRig) resolver(now model.UnixNano) *issues.Service {
	r.t.Helper()
	store, err := issues.NewControlStore(r.app.Control)
	if err != nil {
		r.t.Fatal(err)
	}
	svc, err := issues.New(issues.Deps{Store: store, Authorizer: r.app.Auth, Graphs: adminGraphs{r}, Fence: allowFence{}, Policy: allowPolicy{}, Clock: constClock(now), Regression: issues.RegressionPolicy{MinOccurrences: 1}})
	if err != nil {
		r.t.Fatal(err)
	}
	return svc
}

func (r *issueRig) effects() []control.IssueEffect { return r.snapshot().Effects }

// A regression's effect intent stays in the book until its consumer has acted:
// the incident of the new episode must exist before the intent is acknowledged,
// and an acknowledged intent is gone for good.
func TestRegressionEffectIsAcknowledgedOnceItsIncidentExists(t *testing.T) {
	r := newIssueRig(t)
	issuesOnly := r.only(r.app.IssueProducerWithClock(r.clock))
	incidentsOnly := r.only(r.app.IncidentProducerWithClock(r.clock))
	consumer := r.only(r.app.IssueEffectProducer())
	svc := r.resolver(1_000_000)

	r.ingest("TypeError", 5, true, false)
	r.tick(issuesOnly)
	r.tick(incidentsOnly) // the first episode's incident
	issue := r.snapshot().Issues[0]
	if rep := r.tick(consumer); rep.Produced != 0 || len(r.effects()) != 0 {
		t.Fatalf("nothing to consume yet: %+v effects=%d", rep, len(r.effects()))
	}
	if _, err := svc.Act(r.ctx, r.system(auth.IssuesWrite), issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: issue.Revision, IssueID: issue.ID, Kind: "resolve", Reason: "fixed", ResolutionBoundary: 500}); err != nil {
		t.Fatal(err)
	}
	r.ingest("TypeError", 2000, true, false) // after the boundary: a regression
	r.tick(issuesOnly)
	if got := r.effects(); len(got) != 1 || got[0].Kind != "issue_regressed" || got[0].Issue != issue.ID {
		t.Fatalf("the regression's intent: %+v", got)
	}

	// The incident of the new episode does not exist yet: the intent is not
	// acknowledged (it has not been acted on).
	if rep := r.tick(consumer); rep.Produced != 0 || len(r.effects()) != 1 {
		t.Fatalf("an intent was acknowledged before its incident exists: %+v effects=%d", rep, len(r.effects()))
	}
	r.tick(incidentsOnly)
	if len(r.incidentRecords()) != 2 {
		t.Fatalf("setup: incidents %d", len(r.incidentRecords()))
	}
	if rep := r.tick(consumer); rep.Produced != 1 || len(r.effects()) != 0 {
		t.Fatalf("the intent must be acknowledged once its incident exists: %+v effects=%d", rep, len(r.effects()))
	}
	// Acknowledged for good: another pass changes nothing and the issue is untouched.
	before := r.snapshot().Revision
	if rep := r.tick(consumer); rep.Produced != 0 || r.snapshot().Revision != before {
		t.Fatalf("a repeat acknowledged again: %+v", rep)
	}
	if got := r.snapshot().Issues[0]; got.Workflow != "open" || len(got.Occurrences) != 2 {
		t.Fatalf("acknowledging touched the issue: %+v", got)
	}

	// A second regression is the third episode: its intent maps to ITS incident,
	// not to the first regression's.
	issue = r.snapshot().Issues[0]
	if _, err := svc.Act(r.ctx, r.system(auth.IssuesWrite), issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: issue.Revision, IssueID: issue.ID, Kind: "resolve", Reason: "fixed again", ResolutionBoundary: 3000}); err != nil {
		t.Fatal(err)
	}
	r.ingest("TypeError", 4000, true, false)
	r.tick(issuesOnly)
	if rep := r.tick(consumer); rep.Produced != 0 || len(r.effects()) != 1 {
		t.Fatalf("the second regression's intent was acknowledged by the first episode's incident: %+v effects=%d", rep, len(r.effects()))
	}
	r.tick(incidentsOnly)
	if rep := r.tick(consumer); rep.Produced != 1 || len(r.effects()) != 0 || len(r.incidentRecords()) != 3 {
		t.Fatalf("the second regression: %+v effects=%d incidents=%d", rep, len(r.effects()), len(r.incidentRecords()))
	}
}

// Only intents this consumer can act on are acknowledged: an unknown kind stays
// (it would be lost), an intent whose minting evaluation is gone has nothing left
// to act on and is acknowledged.
func TestEffectConsumerAcknowledgesOnlyWhatItCanAct(t *testing.T) {
	r := newIssueRig(t)
	r.ingest("TypeError", 5, true, false)
	r.tick(r.only(r.app.IssueProducerWithClock(r.clock)))
	snap := r.snapshot()
	issue, occurrence := snap.Issues[0], snap.Issues[0].Occurrences[0].OccurrenceID
	store, err := issues.NewControlStore(r.app.Control)
	if err != nil {
		t.Fatal(err)
	}
	write := r.system(auth.IssuesWrite)
	future, orphan := model.NewID(), model.NewID()
	if err = store.Commit(r.ctx, write, r.project, issues.Commit{ExpectedRevision: snap.Revision, Effects: []issues.Effect{
		{ID: future, Kind: "future_kind", IssueID: issue.ID, OccurrenceID: occurrence},
		{ID: orphan, Kind: "issue_regressed", IssueID: issue.ID, OccurrenceID: occurrence}}}); err != nil {
		t.Fatal(err)
	}
	if rep := r.tick(r.only(r.app.IssueEffectProducer())); rep.Produced != 1 {
		t.Fatalf("exactly the orphaned intent is acknowledged: %+v", rep)
	}
	left := r.effects()
	if len(left) != 1 || left[0].ID != future || left[0].Kind != "future_kind" {
		t.Fatalf("the unknown kind must stay: %+v", left)
	}
}

// The book holds at most 256 intents. Without a consumer the regression past the
// bound is refused as quota and the group's checkpoint can never advance; once
// the consumer acknowledges, the regression commits.
func TestEffectCapCannotWedgeRegressionCommits(t *testing.T) {
	r := newIssueRig(t)
	issuesOnly := r.only(r.app.IssueProducerWithClock(r.clock))
	consumer := r.only(r.app.IssueEffectProducer())
	svc := r.resolver(1_000_000)
	r.ingest("TypeError", 5, true, false)
	r.tick(issuesOnly)
	issue := r.snapshot().Issues[0]
	occurrence := issue.Occurrences[0].OccurrenceID
	store, err := issues.NewControlStore(r.app.Control)
	if err != nil {
		t.Fatal(err)
	}
	write := r.system(auth.IssuesWrite)
	// Fill the book to its bound with intents whose evaluations are gone.
	const bound = 256
	for range bound / issues.MaxEffectAck {
		batch := make([]issues.Effect, issues.MaxEffectAck)
		for i := range batch {
			batch[i] = issues.Effect{ID: model.NewID(), Kind: "issue_regressed", IssueID: issue.ID, OccurrenceID: occurrence}
		}
		if err = store.Commit(r.ctx, write, r.project, issues.Commit{ExpectedRevision: r.snapshot().Revision, Effects: batch}); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(r.effects()); got != bound {
		t.Fatalf("intents = %d, want %d", got, bound)
	}
	if _, err = svc.Act(r.ctx, r.system(auth.IssuesWrite), issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: r.snapshot().Issues[0].Revision, IssueID: issue.ID, Kind: "resolve", Reason: "fixed", ResolutionBoundary: 500}); err != nil {
		t.Fatal(err)
	}
	r.ingest("TypeError", 2000, true, false)
	checkpoint := sumCheckpoints(r.snapshot())
	if rep := issuesOnly.Tick(r.ctx); len(rep.Errors) == 0 {
		t.Fatalf("the regression past the bound must be refused: %+v", rep)
	}
	if got := r.snapshot(); len(got.Effects) != bound || sumCheckpoints(got) != checkpoint {
		t.Fatalf("the refused commit changed the book: effects=%d", len(got.Effects))
	}
	for pass := 0; len(r.effects()) > 1; pass++ {
		if pass > 8 {
			t.Fatalf("the consumer never drains the book: %d intents", len(r.effects()))
		}
		if rep := r.tick(consumer); rep.Produced == 0 {
			t.Fatalf("the consumer is stuck: %+v effects=%d", rep, len(r.effects()))
		}
	}
	r.tick(issuesOnly)
	if got := r.snapshot(); got.Issues[0].Workflow != "open" || sumCheckpoints(got) <= checkpoint {
		t.Fatalf("the wedged regression did not commit: %+v", got.Issues[0].Workflow)
	}
}

// An intent of an episode that can no longer receive an incident is acknowledged:
// the incident producer opens one only for the current episode of an open issue.
func TestEffectOfASupersededEpisodeIsAcknowledged(t *testing.T) {
	r := newIssueRig(t)
	issuesOnly := r.only(r.app.IssueProducerWithClock(r.clock))
	incidentsOnly := r.only(r.app.IncidentProducerWithClock(r.clock))
	consumer := r.only(r.app.IssueEffectProducer())
	svc := r.resolver(1_000_000)
	r.ingest("TypeError", 5, true, false)
	r.tick(issuesOnly)
	r.tick(incidentsOnly)
	at := model.UnixNano(100)
	for range 3 { // three regressions before the incident pass runs again
		issue := r.snapshot().Issues[0]
		if _, err := svc.Act(r.ctx, r.system(auth.IssuesWrite), issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: issue.Revision, IssueID: issue.ID, Kind: "resolve", Reason: "fixed", ResolutionBoundary: at}); err != nil {
			t.Fatal(err)
		}
		r.ingest("TypeError", at+10, true, false)
		r.tick(issuesOnly)
		at += 100
	}
	if got := len(r.effects()); got != 3 {
		t.Fatalf("intents = %d", got)
	}
	if rep := r.tick(consumer); rep.Produced != 2 || len(r.effects()) != 1 {
		t.Fatalf("the two superseded episodes are acknowledged, the current one waits: %+v effects=%d", rep, len(r.effects()))
	}
	r.tick(incidentsOnly)
	if rep := r.tick(consumer); rep.Produced != 1 || len(r.effects()) != 0 || len(r.incidentRecords()) != 2 {
		t.Fatalf("the current episode: %+v effects=%d incidents=%d", rep, len(r.effects()), len(r.incidentRecords()))
	}
}
