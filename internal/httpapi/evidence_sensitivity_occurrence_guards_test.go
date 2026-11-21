// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

// The stored error occurrence of an issue is read only through an issue that really is the one asked for (same organization, same project,
// same ID), and never for a project outside the caller's scope. The issue reader double answers one fixed issue for any request, so the
// view's own checks are the only thing between a caller and another record (issueSensWorld and leakyIssues: evidence_sensitivity_issue_test.go).
func TestEvidenceSensOccurrenceViewRefusesAnIssueThatIsNotTheOneAskedFor(t *testing.T) {
	w := newIssueSensWorld(t)
	occurrence := model.NewID()
	listed := model.GroupingEvidence{OccurrenceID: occurrence, RecordID: model.NewID(), GroupingVersion: 1, Fingerprint: model.HashCanonical([]byte("sens occurrence guard")), EventTime: 1234, ArrivalTime: 2000, Ancestry: "unknown", Freshness: "fresh"}
	asked := w.issue("open")
	asked.Occurrences = []model.GroupingEvidence{listed}
	errs := &fakeErrors{found: true, occ: model.ErrorOccurrence{Occurrence: occurrence, Class: "SensGuard", Mechanism: "manual", Frames: []model.Frame{}}}
	view := func(issue model.GroupingIssue, body httpapi.ErrorOccurrenceBody) (httpapi.ErrorOccurrenceView, error) {
		ev := httpapi.NewEvidence(nil, w.e.app.Releases, leakyIssues{issue}, httpapi.WithErrorOccurrences(errs))
		return ev.Occurrence(w.e.ctx, w.adminScope, &w.readScope, body)
	}
	body := httpapi.ErrorOccurrenceBody{Org: w.org, Project: w.project, Issue: asked.ID, Occurrence: occurrence}
	if v, err := view(asked, body); err != nil || v.State != httpapi.StateReady || v.Detail == nil {
		t.Fatalf("the honest reader: %+v %v", v, err)
	}
	read := errs.calls.Load()
	other := model.NewID()
	for name, c := range map[string]struct {
		stored model.GroupingIssue
		body   httpapi.ErrorOccurrenceBody
	}{
		"another organization":                 {withIssue(asked, func(g *model.GroupingIssue) { g.Org = model.NewID() }), body},
		"another project":                      {withIssue(asked, func(g *model.GroupingIssue) { g.Project = other }), body},
		"another issue ID":                     {withIssue(asked, func(g *model.GroupingIssue) { g.ID = model.NewID() }), body},
		"a project outside the caller's scope": {withIssue(asked, func(g *model.GroupingIssue) { g.Project = other }), httpapi.ErrorOccurrenceBody{Org: w.org, Project: other, Issue: asked.ID, Occurrence: occurrence}},
	} {
		v, err := view(c.stored, c.body)
		if faultCode(err) != model.NotFound || v.Detail != nil {
			t.Fatalf("%s: view %+v err %v, want the one not-found", name, v, err)
		}
	}
	if errs.calls.Load() != read {
		t.Fatal("a stored error record was read for an issue that is not the one asked for")
	}
}

func withIssue(g model.GroupingIssue, change func(*model.GroupingIssue)) model.GroupingIssue {
	change(&g)
	return g
}

// An installation with no issue evidence reader says that, for the occurrence view too (not that administration or telemetry is missing).
func TestEvidenceSensOccurrenceViewNamesTheReasonNoIssueReaderIsWired(t *testing.T) {
	w := newIssueSensWorld(t)
	ev := httpapi.NewEvidence(nil, w.e.app.Releases, nil, httpapi.WithErrorOccurrences(&fakeErrors{}))
	v, err := ev.Occurrence(w.e.ctx, w.adminScope, &w.readScope, httpapi.ErrorOccurrenceBody{Org: w.org, Project: w.project, Issue: model.NewID(), Occurrence: model.NewID()})
	if err != nil || v.State != httpapi.StateNotAvailable || v.Reason != httpapi.ReasonIssueEvidenceAbsent {
		t.Fatalf("no issue reader wired: %+v %v", v, err)
	}
	// A caller who is not an organization administrator is told so, and the issue reader is not asked.
	calls := &countingIssues{inner: leakyIssues{w.issue("open")}}
	ev = httpapi.NewEvidence(nil, w.e.app.Releases, calls, httpapi.WithErrorOccurrences(&fakeErrors{}))
	v, err = ev.Occurrence(w.e.ctx, w.readScope, &w.readScope, httpapi.ErrorOccurrenceBody{Org: w.org, Project: w.project, Issue: calls.inner.issue.ID, Occurrence: model.NewID()})
	if err != nil || v.State != httpapi.StateNotAvailable || v.Reason != httpapi.ReasonIssueNeedsAdmin || calls.n != 0 {
		t.Fatalf("a non-administrator: %+v %v, reader asked %d times", v, err, calls.n)
	}
}
