// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
)

// countingLifecycle is a labelled double of the issue lifecycle read (issues.Service.Get): it answers one fixed issue (or err) for
// any request and records the scopes it was asked under, so the tests can prove whose scope the views read with.
type countingLifecycle struct {
	issue  model.GroupingIssue
	err    error
	scopes []auth.Scope
}

func (c *countingLifecycle) Get(_ context.Context, scope auth.Scope, _, _ model.ID) (issues.Issue, error) {
	c.scopes = append(c.scopes, scope)
	return c.issue, c.err
}

// A project reader is served from the issue lifecycle under her OWN scope and the administrator's registry reader is never asked for
// her; an administrator is still served from the registry and the lifecycle is not asked for her.
func TestEvidenceIssueLifecycleServesAProjectReaderUnderHerOwnScope(t *testing.T) {
	w := newIssueSensWorld(t)
	owner := model.NewID()
	asked := w.issue("open")
	asked.Owner = &owner
	asked.External = []model.ExternalLink{{Provider: "gitlab", State: model.ExternalLinked, Marker: "soundpost-ref-x", Project: "shop/web", IID: 5, URL: "https://git.example.test/shop/web/-/issues/5", Actor: model.NewID(), At: 7}}
	lc := &countingLifecycle{issue: asked}
	registry := &countingIssues{inner: leakyIssues{asked}}
	errs := &fakeErrors{found: true, occ: model.ErrorOccurrence{Class: "Reader"}}
	ev := httpapi.NewEvidence(nil, w.e.app.Releases, registry, httpapi.WithIssueLifecycle(lc), httpapi.WithErrorOccurrences(errs))

	v, err := ev.Issue(w.e.ctx, w.readScope, w.body(asked.ID))
	if err != nil || v.Grouping == nil || v.Grouping.Owner == nil || *v.Grouping.Owner != owner || len(v.Grouping.External) != 1 || v.Grouping.External[0].State != "linked" || v.Grouping.External[0].IID == nil || *v.Grouping.External[0].IID != 5 {
		t.Fatalf("a project reader: %+v %v", v, err)
	}
	if len(lc.scopes) != 1 || lc.scopes[0].Permission() != auth.Read || registry.n != 0 {
		t.Fatalf("the lifecycle was asked %d times (%v), the registry reader %d times", len(lc.scopes), lc.scopes, registry.n)
	}
	if got := issueSensSection(t, v, "occurrence_detail"); got.State != httpapi.StateNotAvailable || got.Reason != httpapi.ReasonOccurrenceNeedsTelemetry {
		t.Fatalf("the stored record is telemetry: %+v", got)
	}
	// With her telemetry-read scope the detail is hers to read, and it is read under that scope alone.
	v, err = ev.IssueWithDetail(w.e.ctx, w.readScope, &w.readScope, w.body(asked.ID))
	if err != nil || issueSensSection(t, v, "occurrence_detail").State != httpapi.StateReady {
		t.Fatalf("a reader with telemetry.read: %+v %v", v, err)
	}
	// An administrator is served from the registry; the lifecycle is not asked.
	if v, err = ev.Issue(w.e.ctx, w.adminScope, w.body(asked.ID)); err != nil || v.Grouping == nil || registry.n != 1 || len(lc.scopes) != 2 {
		t.Fatalf("an administrator: %+v %v (registry %d, lifecycle %d)", v, err, registry.n, len(lc.scopes))
	}
}

// What the lifecycle returns is checked against the request: another organization's, another project's or another ID's issue is
// the one not-found, and a read that fails is not turned into an empty issue.
func TestEvidenceIssueLifecycleAnswerIsCheckedAgainstTheRequest(t *testing.T) {
	w := newIssueSensWorld(t)
	asked := w.issue("open")
	for name, stored := range map[string]model.GroupingIssue{
		"another organization": withIssue(asked, func(g *model.GroupingIssue) { g.Org = model.NewID() }),
		"another project":      withIssue(asked, func(g *model.GroupingIssue) { g.Project = model.NewID() }),
		"another issue ID":     withIssue(asked, func(g *model.GroupingIssue) { g.ID = model.NewID() }),
	} {
		ev := httpapi.NewEvidence(nil, w.e.app.Releases, nil, httpapi.WithIssueLifecycle(&countingLifecycle{issue: stored}))
		if v, err := ev.Issue(w.e.ctx, w.readScope, w.body(asked.ID)); faultCode(err) != model.NotFound || v.Grouping != nil {
			t.Fatalf("%s: %+v %v", name, v, err)
		}
	}
	// A project outside the scope is refused before the lifecycle is asked at all.
	lc := &countingLifecycle{issue: asked}
	ev := httpapi.NewEvidence(nil, w.e.app.Releases, nil, httpapi.WithIssueLifecycle(lc))
	if _, err := ev.Issue(w.e.ctx, w.readScope, httpapi.IssueBody{Org: w.org, Project: model.NewID(), Issue: asked.ID}); faultCode(err) != model.NotFound || len(lc.scopes) != 0 {
		t.Fatalf("a project outside the scope: %v, lifecycle asked %d times", err, len(lc.scopes))
	}
	// The lifecycle's own refusals reach the caller as they are: not found stays not found, a closed project stays unavailable.
	for _, want := range []model.Code{model.NotFound, model.Unavailable} {
		failing := httpapi.NewEvidence(nil, w.e.app.Releases, nil, httpapi.WithIssueLifecycle(&countingLifecycle{err: model.Fail(want)}))
		if v, err := failing.Issue(w.e.ctx, w.readScope, w.body(asked.ID)); faultCode(err) != want || v.Grouping != nil {
			t.Fatalf("a lifecycle %s: %+v %v", want, v, err)
		}
	}
}

// The occurrence view reads through the lifecycle for a reader too, lists only what the issue itself lists and reads the stored
// record under her telemetry scope.
func TestEvidenceOccurrenceLifecycleServesAProjectReader(t *testing.T) {
	w := newIssueSensWorld(t)
	occurrence := model.NewID()
	asked := w.issue("open")
	asked.Occurrences = []model.GroupingEvidence{{OccurrenceID: occurrence, RecordID: model.NewID(), GroupingVersion: 1, Fingerprint: asked.Fingerprint, EventTime: 1234, ArrivalTime: 2000, Ancestry: "unknown", Freshness: "fresh"}}
	lc := &countingLifecycle{issue: asked}
	errs := &fakeErrors{found: true, occ: model.ErrorOccurrence{Occurrence: occurrence, Class: "ReaderSees", Mechanism: "manual", Frames: []model.Frame{}}}
	ev := httpapi.NewEvidence(nil, w.e.app.Releases, nil, httpapi.WithIssueLifecycle(lc), httpapi.WithErrorOccurrences(errs))
	body := httpapi.ErrorOccurrenceBody{Org: w.org, Project: w.project, Issue: asked.ID, Occurrence: occurrence}

	v, err := ev.Occurrence(w.e.ctx, w.readScope, &w.readScope, body)
	if err != nil || v.State != httpapi.StateReady || v.Detail == nil || v.Detail.Class != "ReaderSees" || errs.scope.Permission() != auth.Read || len(lc.scopes) != 1 || lc.scopes[0].Permission() != auth.Read {
		t.Fatalf("a reader's occurrence: %+v %v (record read under %v)", v, err, errs.scope.Permission())
	}
	// Without a telemetry-read scope no stored record is read.
	before := errs.calls.Load()
	if v, err = ev.Occurrence(w.e.ctx, w.readScope, nil, body); err != nil || v.Reason != httpapi.ReasonOccurrenceNeedsTelemetry || v.Detail != nil || errs.calls.Load() != before {
		t.Fatalf("without a read scope: %+v %v", v, err)
	}
	// An occurrence the issue does not list is not reachable by guessing.
	body.Occurrence = model.NewID()
	if _, err = ev.Occurrence(w.e.ctx, w.readScope, &w.readScope, body); faultCode(err) != model.NotFound || errs.calls.Load() != before {
		t.Fatalf("a guessed occurrence: %v", err)
	}
}
