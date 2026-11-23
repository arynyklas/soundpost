// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
)

// fakeRegressions is a labelled double of the stored-explanation seam: it records
// the scope the handler reads under and answers exactly the explanations the
// lifecycle is said to have stored. The real lifecycle's explanations over a real
// store and a real browser are exercised by web/e2e/error-release-artifact.spec.ts
// and internal/issues' own tests; what is judged here is that the view shows what
// was stored and nothing else.
type fakeRegressions struct {
	calls   atomic.Int32
	scope   auth.Scope
	project model.ID
	issue   model.ID
	byIssue map[model.ID][]issues.Explanation
	err     error
	allErr  error
}

func (f *fakeRegressions) Explain(_ context.Context, scope auth.Scope, project, issue model.ID) ([]issues.Explanation, error) {
	f.calls.Add(1)
	f.scope, f.project, f.issue = scope, project, issue
	if f.err != nil {
		return nil, f.err
	}
	return f.byIssue[issue], nil
}

func (f *fakeRegressions) ExplainAll(_ context.Context, scope auth.Scope, project model.ID) (map[model.ID][]issues.Explanation, error) {
	f.calls.Add(1)
	f.scope, f.project = scope, project
	if f.allErr != nil {
		return nil, f.allErr
	}
	return f.byIssue, nil
}

func (e *evEnv) serve(t *testing.T, ev *httpapi.Evidence) {
	t.Helper()
	e.srv.Close()
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterEvidenceRoutes(mux, e.app.Auth, ev)
		e.app.RegisterArtifactRoutes(mux)
	}).Handler)
	t.Cleanup(e.srv.Close)
}

func sectionOf(v []httpapi.ViewSection, name string) httpapi.ViewSection {
	for _, s := range v {
		if s.Name == name {
			return s
		}
	}
	return httpapi.ViewSection{}
}

func TestEvidenceIssueShowsOnlyStoredRegressionExplanations(t *testing.T) {
	fi, fr := &fakeIssues{}, &fakeRegressions{byIssue: map[model.ID][]issues.Explanation{}}
	e := newEvEnv(t, nil, fi, true)
	e.serve(t, httpapi.NewEvidence(nil, e.app.Releases, fi, httpapi.WithRegressionExplanations(fr)))
	p := model.NewID()
	org := e.org("evidence regression", p)
	admin := e.user(org, "regression-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	reader := e.user(org, "regression-reader@example.test")
	e.grant(org, reader, p, true, auth.Read)
	stranger := e.user(e.org("evidence regression B"), "regression-stranger@example.test")

	fix, other, later := model.NewID(), model.NewID(), model.NewID()
	fp := model.HashCanonical([]byte("regression fingerprint"))
	resolved := model.UnixNano(100)
	// A resolved issue whose occurrences are all far AFTER its resolution, on releases that look newer: the evidence alone is no verdict.
	ev := func(at model.UnixNano, release *model.ID) model.GroupingEvidence {
		ancestry := "unknown"
		if release != nil {
			ancestry = "known"
		}
		return model.GroupingEvidence{OccurrenceID: model.NewID(), RecordID: model.NewID(), GroupingVersion: 1, Fingerprint: fp, EventTime: at, ArrivalTime: at + 1, ReleaseID: release, Ancestry: ancestry, Freshness: "fresh"}
	}
	fi.issue = model.GroupingIssue{ID: model.NewID(), Org: org, Project: p, GroupingVersion: 1, Fingerprint: fp, Workflow: "resolved", Revision: 5, ResolutionTime: &resolved,
		Occurrences: []model.GroupingEvidence{ev(900_000, &later), ev(900_001, nil)}}
	body := map[string]any{"org": org.String(), "project": p.String(), "issue": fi.issue.ID.String()}
	read := func(who person) httpapi.IssueView {
		t.Helper()
		status, raw := e.post(who, "/api/v1/evidence/issue", body, nil)
		if status != 200 {
			t.Fatalf("issue: %d %s", status, raw)
		}
		var v httpapi.IssueView
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	// Nothing stored: an empty section, an empty list, and no regression is claimed from the late timestamps or the releases.
	v := read(admin)
	if s := sectionOf(v.Sections, "regression"); s.State != httpapi.StateEmpty || s.Reason != httpapi.ReasonNoRegression {
		t.Fatalf("an issue with no stored evaluation is an empty section, not a verdict: %+v", s)
	}
	if v.Regression == nil || v.Regression.Explanations == nil || len(v.Regression.Explanations) != 0 {
		t.Fatalf("regression: %+v", v.Regression)
	}
	if fr.scope.Permission() != auth.OrgAdmin || fr.project != p || fr.issue != fi.issue.ID {
		t.Fatalf("the reader got scope %v project %v issue %v", fr.scope.Permission(), fr.project, fr.issue)
	}

	// Two stored evaluations, oldest first: one not eligible (the release is not the fix or a descendant), one by the explicit time boundary because the ancestry is unknown.
	missFix := issues.Explanation{OccurrenceID: fi.issue.Occurrences[0].OccurrenceID, EvidenceRelease: other, EventTime: 900_000, ResolutionTime: 100, Threshold: 1, Window: 0, Qualifying: 0,
		Decision: issues.RegressionDecision{Eligible: false, Reason: "release is not the fix frontier or a descendant of it", AncestryKnown: true, Frontier: []model.ID{fix}}}
	unknown := issues.Explanation{OccurrenceID: fi.issue.Occurrences[1].OccurrenceID, EventTime: 900_001, ResolutionTime: 100, Threshold: 2, Window: 50, Qualifying: 2, Reopened: true,
		Decision: issues.RegressionDecision{Eligible: true, Reason: "ancestry unknown: event after the explicit resolution boundary", AncestryKnown: false}}
	below := issues.Explanation{OccurrenceID: model.NewID(), EvidenceRelease: fix, EventTime: 900_002, ResolutionTime: 100, Threshold: 2, Qualifying: 1,
		Decision: issues.RegressionDecision{Eligible: true, Reason: "release is the fix frontier or a descendant of it", AncestryKnown: true, Frontier: []model.ID{fix}}}
	fr.byIssue[fi.issue.ID] = []issues.Explanation{missFix, unknown, below}
	v = read(admin)
	got := v.Regression
	if s := sectionOf(v.Sections, "regression"); s.State != httpapi.StateReady || s.Reason != "" || got == nil || len(got.Explanations) != 3 {
		t.Fatalf("stored evaluations: %+v %+v", s, got)
	}
	a, b := got.Explanations[0], got.Explanations[1]
	if a.Occurrence != missFix.OccurrenceID || a.EvidenceRelease == nil || *a.EvidenceRelease != other || a.EventTime != 900_000 || a.ResolutionTime != 100 || a.Eligible || !a.AncestryKnown || a.Reopened ||
		a.Reason != "release is not the fix frontier or a descendant of it" || len(a.Frontier) != 1 || a.Frontier[0] != fix || a.Threshold != 1 || a.Window != 0 || a.Qualifying != 0 {
		t.Fatalf("first evaluation is not what was stored: %+v", a)
	}
	if b.Occurrence != unknown.OccurrenceID || b.EvidenceRelease != nil || !b.Eligible || b.AncestryKnown || !b.Reopened || b.Reason != "ancestry unknown: event after the explicit resolution boundary" || b.Frontier == nil || len(b.Frontier) != 0 || b.Threshold != 2 || b.Window != 50 || b.Qualifying != 2 {
		t.Fatalf("second evaluation is not what was stored (unknown ancestry must stay unknown): %+v", b)
	}
	if c := got.Explanations[2]; c.Occurrence != below.OccurrenceID || !c.Eligible || c.Reopened || c.Qualifying != 1 || c.Threshold != 2 {
		t.Fatalf("an eligible evaluation below the threshold did not reopen and must not be shown as reopened: %+v", c)
	}

	// An evaluation the store does not hold for this issue (another issue's) is never shown here.
	fr.byIssue[model.NewID()] = []issues.Explanation{{OccurrenceID: model.NewID(), EvidenceRelease: later, Decision: issues.RegressionDecision{Eligible: true, Reason: "elsewhere"}, Reopened: true}}
	if v = read(admin); len(v.Regression.Explanations) != 3 {
		t.Fatalf("another issue's evaluation leaked: %+v", v.Regression)
	}

	// A project reader is served by the issue lifecycle, which this environment does not bind: she is told the view is not built and
	// the explanations are not read; a stranger gets the one not-found.
	before := fr.calls.Load()
	status, raw := e.post(reader, "/api/v1/evidence/issue", body, nil)
	var denied httpapi.IssueView
	_ = json.Unmarshal(raw, &denied)
	if status != 200 || denied.Reason != httpapi.ReasonIssueEvidenceAbsent || denied.Regression != nil || fr.calls.Load() != before {
		t.Fatalf("reader: %d %s (explain calls %d -> %d)", status, raw, before, fr.calls.Load())
	}
	if status, _ = e.post(stranger, "/api/v1/evidence/issue", body, nil); status != 404 || fr.calls.Load() != before {
		t.Fatalf("stranger: %d (explain calls %d -> %d)", status, before, fr.calls.Load())
	}

	// No stored evaluation for an issue the lifecycle does not know is an empty section; a read that fails is a typed failure, never an empty list.
	fr.err = model.Fail(model.NotFound)
	if v = read(admin); sectionOf(v.Sections, "regression").State != httpapi.StateEmpty || len(v.Regression.Explanations) != 0 {
		t.Fatalf("not found: %+v", v.Regression)
	}
	fr.err = model.Fail(model.Unavailable)
	if status, raw = e.post(admin, "/api/v1/evidence/issue", body, nil); status < 500 {
		t.Fatalf("a failed read of the explanations: %d %s", status, raw)
	}

	// Without a reader the section says so and no list is claimed.
	e.serve(t, httpapi.NewEvidence(nil, e.app.Releases, fi))
	v = read(admin)
	if s := sectionOf(v.Sections, "regression"); s.State != httpapi.StateNotAvailable || s.Reason != httpapi.ReasonRegressionDetail || v.Regression != nil {
		t.Fatalf("unwired: %+v %+v", s, v.Regression)
	}
}

func TestEvidenceReleaseListsOnlyTheEvaluationsThatRanInIt(t *testing.T) {
	fr := &fakeRegressions{byIssue: map[model.ID][]issues.Explanation{}}
	e := newEvEnv(t, nil, nil, true)
	e.serve(t, httpapi.NewEvidence(nil, e.app.Releases, nil, httpapi.WithRegressionExplanations(fr)))
	p := model.NewID()
	org := e.org("evidence release regression", p)
	admin := e.user(org, "rr-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	reader := e.user(org, "rr-reader@example.test")
	e.grant(org, reader, p, true, auth.Read)
	adminScope, err := e.app.Auth.Authorize(e.ctx, admin.Cred, org, []model.ID{p}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	a, b, c := model.NewID(), model.NewID(), model.NewID()
	mk := func(id model.ID, label string, parents ...model.ID) model.Release {
		return model.Release{ID: id, Org: org, Project: p, BuildID: model.NewID(), Parents: parents, BuildTime: 5, DisplayLabel: label}
	}
	e.register(adminScope, mk(a, "v1"))
	e.register(adminScope, mk(b, "v2", a))
	e.register(adminScope, mk(c, "v3", b))
	i1, i2 := model.NewID(), model.NewID()
	if string(i1[:]) > string(i2[:]) {
		i1, i2 = i2, i1
	}
	explain := func(at model.UnixNano, release model.ID, eligible, reopened bool, reason string) issues.Explanation {
		return issues.Explanation{OccurrenceID: model.NewID(), EvidenceRelease: release, EventTime: at, ResolutionTime: 10, Threshold: 1, Qualifying: 1, Reopened: reopened,
			Decision: issues.RegressionDecision{Eligible: eligible, Reason: reason, AncestryKnown: true, Frontier: []model.ID{b}}}
	}
	onB1 := explain(20, b, true, true, "release is the fix frontier or a descendant of it")
	onA := explain(21, a, false, false, "release is not the fix frontier or a descendant of it")
	onB2 := explain(30, b, false, false, "release is not the fix frontier or a descendant of it")
	noRelease := issues.Explanation{OccurrenceID: model.NewID(), EventTime: 31, ResolutionTime: 10, Decision: issues.RegressionDecision{Eligible: true, Reason: "ancestry unknown: event after the explicit resolution boundary"}}
	fr.byIssue[i2] = []issues.Explanation{onB2, noRelease}
	fr.byIssue[i1] = []issues.Explanation{onA, onB1}
	view := func(release model.ID) httpapi.ReleaseView {
		t.Helper()
		status, raw := e.post(admin, "/api/v1/evidence/release", map[string]any{"org": org.String(), "project": p.String(), "release": release.String()}, nil)
		if status != 200 {
			t.Fatalf("release: %d %s", status, raw)
		}
		return decodeRelease(t, raw)
	}

	v := view(b)
	if s := sectionOf(v.Sections, "regression"); s.State != httpapi.StateReady || s.Reason != "" {
		t.Fatalf("section: %+v", s)
	}
	if len(v.Regressions) != 2 || v.Regressions[0].Issue != i1 || v.Regressions[0].Occurrence != onB1.OccurrenceID || !v.Regressions[0].Eligible || !v.Regressions[0].Reopened ||
		v.Regressions[1].Issue != i2 || v.Regressions[1].Occurrence != onB2.OccurrenceID || v.Regressions[1].Eligible || v.Regressions[1].Reopened {
		t.Fatalf("a release lists exactly the evaluations whose occurrence ran in it, by issue then in stored order: %+v", v.Regressions)
	}
	if fr.scope.Permission() != auth.OrgAdmin || fr.project != p {
		t.Fatalf("the reader got scope %v project %v", fr.scope.Permission(), fr.project)
	}
	// An evaluation with no release is never attributed to one; a release no evaluation ran in has an empty section, not a clean bill.
	if got := view(a); len(got.Regressions) != 1 || got.Regressions[0].Occurrence != onA.OccurrenceID {
		t.Fatalf("release a: %+v", got.Regressions)
	}
	if got := view(c); len(got.Regressions) != 0 || got.Regressions == nil || sectionOf(got.Sections, "regression").State != httpapi.StateEmpty || sectionOf(got.Sections, "regression").Reason != httpapi.ReasonNoRegression {
		t.Fatalf("release c: %+v %+v", got.Regressions, got.Sections)
	}
	// A project reader is told release records need an administrator; the explanations are not read.
	before := fr.calls.Load()
	status, raw := e.post(reader, "/api/v1/evidence/release", map[string]any{"org": org.String(), "project": p.String(), "release": b.String()}, nil)
	if rv := decodeRelease(t, raw); status != 200 || rv.Reason != httpapi.ReasonReleaseNeedsAdmin || len(rv.Regressions) != 0 || fr.calls.Load() != before {
		t.Fatalf("reader: %d %s", status, raw)
	}
	// A failed read of the explanations is a typed failure.
	fr.allErr = model.Fail(model.Unavailable)
	if status, raw = e.post(admin, "/api/v1/evidence/release", map[string]any{"org": org.String(), "project": p.String(), "release": b.String()}, nil); status < 500 {
		t.Fatalf("a failed read: %d %s", status, raw)
	}
	// Without a reader the section is not available and lists nothing.
	e.serve(t, httpapi.NewEvidence(nil, e.app.Releases, nil))
	v = view(b)
	if s := sectionOf(v.Sections, "regression"); s.State != httpapi.StateNotAvailable || s.Reason != httpapi.ReasonRegressionDetail || len(v.Regressions) != 0 {
		t.Fatalf("unwired: %+v %+v", s, v.Regressions)
	}
}

// A view whose every part is readable is ready: a regression section with nothing to evaluate is empty, which is not a degradation.
func TestEvidenceIssueIsReadyWhenEveryPartIsReadableEvenWithNoRegressionToShow(t *testing.T) {
	fi, fr, errs := &fakeIssues{}, &fakeRegressions{byIssue: map[model.ID][]issues.Explanation{}}, &fakeErrors{}
	e := newEvEnv(t, nil, fi, true)
	e.serve(t, httpapi.NewEvidence(nil, e.app.Releases, fi, httpapi.WithErrorOccurrences(errs), httpapi.WithRegressionExplanations(fr)))
	p := model.NewID()
	org := e.org("evidence ready", p)
	analyst := e.user(org, "ready-analyst@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: analyst.ID, Enabled: true})
	e.grant(org, analyst, p, true, auth.Read)
	fp := model.HashCanonical([]byte("ready"))
	fi.issue = model.GroupingIssue{ID: model.NewID(), Org: org, Project: p, GroupingVersion: 1, Fingerprint: fp, Workflow: "open", Revision: 1,
		Occurrences: []model.GroupingEvidence{{OccurrenceID: model.NewID(), RecordID: model.NewID(), GroupingVersion: 1, Fingerprint: fp, EventTime: 5, ArrivalTime: 6, Ancestry: "unknown", Freshness: "fresh"}}}
	status, raw := e.post(analyst, "/api/v1/evidence/issue", map[string]any{"org": org.String(), "project": p.String(), "issue": fi.issue.ID.String()}, nil)
	var v httpapi.IssueView
	if err := json.Unmarshal(raw, &v); err != nil || status != 200 || v.State != httpapi.StateReady || v.Reason != "" || sectionOf(v.Sections, "regression").State != httpapi.StateEmpty {
		t.Fatalf("every part readable, nothing evaluated: %d %s", status, raw)
	}
}
