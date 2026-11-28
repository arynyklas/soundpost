// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
)

// These tests pin the issue evidence view (POST /api/v1/evidence/issue, Evidence.IssueWithDetail) field by field and rule by rule: the
// mutation review of evidence.go found that the older tests left each of these facts free to change. They call the view directly with
// scopes derived from the real authority; the readers are the labelled doubles of evidence_test.go and evidence_occurrence_test.go.

// issueSensWorld is one organization and project with an administrator who also holds telemetry.read and one who holds nothing else.
type issueSensWorld struct {
	e                                *evEnv
	org, project                     model.ID
	adminScope, readScope, bareScope auth.Scope
}

func newIssueSensWorld(t *testing.T) *issueSensWorld {
	t.Helper()
	e := newEvEnv(t, nil, nil, true)
	p := model.NewID()
	org := e.org("evidence sens issue", p)
	admin := e.user(org, "sens-issue-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	e.grant(org, admin, p, true, auth.Read)
	bare := e.user(org, "sens-issue-bare@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: bare.ID, Enabled: true})
	w := &issueSensWorld{e: e, org: org, project: p}
	var err error
	if w.adminScope, err = e.scope(admin, org, p, auth.OrgAdmin); err != nil {
		t.Fatal(err)
	}
	if w.readScope, err = e.scope(admin, org, p, auth.Read); err != nil {
		t.Fatal(err)
	}
	if w.bareScope, err = e.scope(bare, org, p, auth.OrgAdmin); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *issueSensWorld) body(issue model.ID) httpapi.IssueBody {
	return httpapi.IssueBody{Org: w.org, Project: w.project, Issue: issue}
}

func (w *issueSensWorld) issue(workflow string) model.GroupingIssue {
	return model.GroupingIssue{ID: model.NewID(), Org: w.org, Project: w.project, GroupingVersion: 1, Fingerprint: model.HashCanonical([]byte("sens issue " + workflow)), Workflow: workflow, Revision: 1}
}

func issueSensSection(t *testing.T, v httpapi.IssueView, name string) httpapi.ViewSection {
	t.Helper()
	for _, s := range v.Sections {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no %q section in %+v", name, v.Sections)
	return httpapi.ViewSection{}
}

// Every stored fact of the issue reaches the view as stored: grouping identity and workflow, the resolution facts, every list of release
// IDs, and every field of an occurrence and of a late-history item (event and arrival time kept apart).
func TestEvidenceSensIssueViewCarriesEveryStoredFact(t *testing.T) {
	w := newIssueSensWorld(t)
	fp, occFP, lateFP := model.HashCanonical([]byte("sens issue fp")), model.HashCanonical([]byte("sens occ fp")), model.HashCanonical([]byte("sens late fp"))
	frontier, observed, fixed, migration := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	build, release, lateBuild := model.NewID(), model.NewID(), model.NewID()
	resolved := model.UnixNano(123456)
	occ := model.GroupingEvidence{OccurrenceID: model.NewID(), RecordID: model.NewID(), GroupingVersion: 6, Fingerprint: occFP, EventTime: 1111, ArrivalTime: 2222, BuildID: &build, ReleaseID: &release, Ancestry: "known", Freshness: "stale"}
	late := model.GroupingEvidence{OccurrenceID: model.NewID(), RecordID: model.NewID(), GroupingVersion: 5, Fingerprint: lateFP, EventTime: 3333, ArrivalTime: 4444, BuildID: &lateBuild, Ancestry: "unknown", Freshness: "fresh"}
	fi := &fakeIssues{issue: model.GroupingIssue{ID: model.NewID(), Org: w.org, Project: w.project, GroupingVersion: 7, Fingerprint: fp, Workflow: "resolved", Revision: 11, ResolutionTime: &resolved,
		ResolutionFrontier: []model.ID{frontier}, ObservedReleases: []model.ID{observed}, FixedDescendants: []model.ID{fixed}, MigrationLinks: []model.ID{migration},
		Occurrences: []model.GroupingEvidence{occ}, LateHistory: []model.GroupingEvidence{late}}}
	v, err := httpapi.NewEvidence(nil, w.e.app.Releases, fi).Issue(w.e.ctx, w.adminScope, w.body(fi.issue.ID))
	if err != nil {
		t.Fatal(err)
	}
	g := v.Grouping
	if g == nil || g.Version != 7 || g.Fingerprint != fp || g.Workflow != "resolved" || g.Revision != 11 || g.ResolutionTime == nil || *g.ResolutionTime != 123456 {
		t.Fatalf("grouping identity and resolution time: %+v", g)
	}
	for name, got := range map[string][]model.ID{"frontier": g.ResolutionFrontier, "observed releases": g.ObservedReleases, "fixed descendants": g.FixedDescendants, "migration links": g.MigrationLinks} {
		if len(got) != 1 {
			t.Fatalf("%s: %v", name, got)
		}
	}
	if g.ResolutionFrontier[0] != frontier || g.ObservedReleases[0] != observed || g.FixedDescendants[0] != fixed || g.MigrationLinks[0] != migration {
		t.Fatalf("the release ID lists are not the stored ones: %+v", g)
	}
	wantOcc := httpapi.OccurrenceEvidenceView{OccurrenceID: occ.OccurrenceID, RecordID: occ.RecordID, GroupingVersion: 6, Fingerprint: occFP, EventTime: 1111, ArrivalTime: 2222, BuildID: &build, ReleaseID: &release, Ancestry: "known", Freshness: "stale"}
	if !reflect.DeepEqual(v.Occurrences, []httpapi.OccurrenceEvidenceView{wantOcc}) {
		t.Fatalf("occurrence evidence: got %+v want %+v", v.Occurrences, wantOcc)
	}
	wantLate := httpapi.OccurrenceEvidenceView{OccurrenceID: late.OccurrenceID, RecordID: late.RecordID, GroupingVersion: 5, Fingerprint: lateFP, EventTime: 3333, ArrivalTime: 4444, BuildID: &lateBuild, Ancestry: "unknown", Freshness: "fresh", Late: true}
	if !reflect.DeepEqual(v.LateHistory, []httpapi.OccurrenceEvidenceView{wantLate}) {
		t.Fatalf("late history evidence: got %+v want %+v", v.LateHistory, wantLate)
	}
}

// An occurrence whose stored ancestry says "known" but names no release is unknown, and a stored word other than known or unknown is
// unknown: the view never states ancestry the evidence does not carry.
func TestEvidenceSensIssueAncestryIsKnownOnlyWithAReleaseAndTheWordKnown(t *testing.T) {
	w := newIssueSensWorld(t)
	release := model.NewID()
	ev := func(ancestry string, release *model.ID) model.GroupingEvidence {
		return model.GroupingEvidence{OccurrenceID: model.NewID(), RecordID: model.NewID(), GroupingVersion: 1, Fingerprint: model.HashCanonical([]byte("ancestry")), EventTime: 1, ArrivalTime: 2, ReleaseID: release, Ancestry: ancestry, Freshness: "fresh"}
	}
	fi := &fakeIssues{issue: w.issue("open")}
	fi.issue.Occurrences = []model.GroupingEvidence{ev("known", &release), ev("known", nil), ev("unknown", &release), ev("partial", &release)}
	v, err := httpapi.NewEvidence(nil, w.e.app.Releases, fi).Issue(w.e.ctx, w.adminScope, w.body(fi.issue.ID))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, o := range v.Occurrences {
		got = append(got, o.Ancestry)
	}
	if want := []string{"known", "unknown", "unknown", "unknown"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ancestry %v, want %v", got, want)
	}
}

// The evidence window and the folded counts: only occurrences folded, only late history folded, or nothing folded. The counts are the
// stored ones, the evidence section is incomplete exactly when something was folded, and the whole view says that reason first.
func TestEvidenceSensIssueViewStatesWhatWasFoldedAndOnlyThat(t *testing.T) {
	w := newIssueSensWorld(t)
	wired := func(fi *fakeIssues) *httpapi.Evidence {
		return httpapi.NewEvidence(nil, w.e.app.Releases, fi, httpapi.WithErrorOccurrences(&fakeErrors{}), httpapi.WithRegressionExplanations(&fakeRegressions{byIssue: map[model.ID][]issues.Explanation{}}))
	}
	for _, c := range []struct {
		name                 string
		occurrences, lateOld model.Uint64
	}{{"only occurrences folded", 9, 0}, {"only late history folded", 0, 3}, {"both folded", 4, 2}, {"nothing folded", 0, 0}} {
		fi := &fakeIssues{issue: w.issue("open")}
		if c.occurrences > 0 {
			fi.issue.Compacted = &model.GroupingCompaction{Count: c.occurrences, FirstEvent: 1, LastEvent: 8, FirstArrival: 2, LastArrival: 9}
		}
		if c.lateOld > 0 {
			fi.issue.LateCompacted = &model.GroupingCompaction{Count: c.lateOld, FirstEvent: 1, LastEvent: 8, FirstArrival: 2, LastArrival: 9}
		}
		v, err := wired(fi).IssueWithDetail(w.e.ctx, w.adminScope, &w.readScope, w.body(fi.issue.ID))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if v.Grouping == nil || v.Grouping.CompactedOccurrences != c.occurrences || v.Grouping.CompactedLate != c.lateOld {
			t.Fatalf("%s: folded counts %+v", c.name, v.Grouping)
		}
		evidence := issueSensSection(t, v, "evidence")
		if c.occurrences+c.lateOld > 0 {
			if evidence.State != httpapi.StateIncomplete || evidence.Reason != httpapi.ReasonEvidenceCompacted || v.State != httpapi.StateIncomplete || v.Reason != httpapi.ReasonEvidenceCompacted {
				t.Fatalf("%s: evidence %+v, view %s %q", c.name, evidence, v.State, v.Reason)
			}
		} else if evidence.State != httpapi.StateReady || v.State != httpapi.StateReady || v.Reason != "" {
			// Everything is wired and an issue with no stored evaluation has an EMPTY regression section: that is not a missing part.
			t.Fatalf("%s: evidence %+v, view %s %q, sections %+v", c.name, evidence, v.State, v.Reason, v.Sections)
		}
	}
}

// The stored occurrence detail section says exactly why it is not ready: no reader wired, no telemetry.read for this caller; it is ready
// only when both exist.
func TestEvidenceSensIssueOccurrenceDetailSectionNamesItsMissingPart(t *testing.T) {
	w := newIssueSensWorld(t)
	fi := &fakeIssues{issue: w.issue("open")}
	body := w.body(fi.issue.ID)
	detail := func(ev *httpapi.Evidence, read *auth.Scope) httpapi.ViewSection {
		t.Helper()
		v, err := ev.IssueWithDetail(w.e.ctx, w.adminScope, read, body)
		if err != nil {
			t.Fatal(err)
		}
		return issueSensSection(t, v, "occurrence_detail")
	}
	unwired := httpapi.NewEvidence(nil, w.e.app.Releases, fi)
	wired := httpapi.NewEvidence(nil, w.e.app.Releases, fi, httpapi.WithErrorOccurrences(&fakeErrors{}))
	if s := detail(unwired, &w.readScope); s.State != httpapi.StateNotAvailable || s.Reason != httpapi.ReasonOccurrenceDetail {
		t.Fatalf("no reader wired, telemetry.read held: %+v", s)
	}
	if s := detail(unwired, nil); s.State != httpapi.StateNotAvailable || s.Reason != httpapi.ReasonOccurrenceDetail {
		t.Fatalf("no reader wired, no telemetry.read: %+v", s)
	}
	if s := detail(wired, nil); s.State != httpapi.StateNotAvailable || s.Reason != httpapi.ReasonOccurrenceNeedsTelemetry {
		t.Fatalf("reader wired, no telemetry.read: %+v", s)
	}
	if s := detail(wired, &w.readScope); s.State != httpapi.StateReady || s.Reason != "" {
		t.Fatalf("reader wired, telemetry.read held: %+v", s)
	}
}

// leakyIssues is a labelled double of an issue reader that does NOT check what it is asked: it answers one fixed issue for any request,
// so the view's own identity checks are the only thing between a caller and another record.
type leakyIssues struct{ issue model.GroupingIssue }

func (l leakyIssues) GroupingIssue(context.Context, auth.Scope, model.ID, model.ID) (model.GroupingIssue, error) {
	return l.issue, nil
}

// A record the reader returns that is not the one asked for (another organization's, another project's, another ID) is the one not-found:
// its content is never shown. A request for a project outside the caller's scope is refused before the reader is asked at all.
func TestEvidenceSensIssueViewRefusesARecordThatIsNotTheOneAskedFor(t *testing.T) {
	w := newIssueSensWorld(t)
	asked := w.issue("open")
	foreign := func(change func(*model.GroupingIssue)) model.GroupingIssue {
		g := asked
		change(&g)
		return g
	}
	for name, stored := range map[string]model.GroupingIssue{
		"another organization": foreign(func(g *model.GroupingIssue) { g.Org = model.NewID() }),
		"another project":      foreign(func(g *model.GroupingIssue) { g.Project = model.NewID() }),
		"another issue ID":     foreign(func(g *model.GroupingIssue) { g.ID = model.NewID() }),
	} {
		v, err := httpapi.NewEvidence(nil, w.e.app.Releases, leakyIssues{stored}).Issue(w.e.ctx, w.adminScope, w.body(asked.ID))
		if faultCode(err) != model.NotFound || v.Grouping != nil {
			t.Fatalf("%s: view %+v err %v, want the one not-found", name, v, err)
		}
	}
	other := model.NewID()
	outside := asked
	outside.Project = other
	calls := &countingIssues{inner: leakyIssues{outside}}
	v, err := httpapi.NewEvidence(nil, w.e.app.Releases, calls).Issue(w.e.ctx, w.adminScope, httpapi.IssueBody{Org: w.org, Project: other, Issue: asked.ID})
	if faultCode(err) != model.NotFound || v.Grouping != nil || calls.n != 0 {
		t.Fatalf("a project outside the scope: view %+v err %v, reader asked %d times", v, err, calls.n)
	}
}

type countingIssues struct {
	inner leakyIssues
	n     int
}

func (c *countingIssues) GroupingIssue(ctx context.Context, scope auth.Scope, project, id model.ID) (model.GroupingIssue, error) {
	c.n++
	return c.inner.GroupingIssue(ctx, scope, project, id)
}

// An installation with no issue evidence reader says that (not that the caller lacks administration). A project reader is served by
// the issue lifecycle (D92): with none bound she is told the view is not built, and the administrator's registry reader is not asked.
func TestEvidenceSensIssueViewNamesTheReasonItIsNotAvailable(t *testing.T) {
	w := newIssueSensWorld(t)
	asked := w.issue("open")
	v, err := httpapi.NewEvidence(nil, w.e.app.Releases, nil).Issue(w.e.ctx, w.adminScope, w.body(asked.ID))
	if err != nil || v.State != httpapi.StateNotAvailable || v.Reason != httpapi.ReasonIssueEvidenceAbsent {
		t.Fatalf("no reader wired: %+v %v", v, err)
	}
	calls := &countingIssues{inner: leakyIssues{asked}}
	v, err = httpapi.NewEvidence(nil, w.e.app.Releases, calls).Issue(w.e.ctx, w.readScope, w.body(asked.ID))
	if err != nil || v.State != httpapi.StateNotAvailable || v.Reason != httpapi.ReasonIssueEvidenceAbsent || v.Grouping != nil || calls.n != 0 {
		t.Fatalf("a project reader with no lifecycle bound: %+v %v, registry reader asked %d times", v, err, calls.n)
	}
}
