// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package issues_test

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/releases"
	"reflect"
	"sync"
	"testing"
)

// fakeStore is an in-memory stand-in for the C05 control store: one atomic
// Commit with an optimistic revision, plus crash injection around it.
type fakeStore struct {
	mu           sync.Mutex
	states       map[string]*issues.State
	commits      []issues.Commit
	effects      []issues.Effect
	audits       []model.ControlAudit
	loads        int
	failBefore   error // returned before anything is applied
	failAfter    error // applied, then the acknowledgement is lost
	tear         bool  // applies records/effects but not the checkpoint, then crashes
	denyGap      bool
	beforeCommit func()
}

func newFakeStore() *fakeStore { return &fakeStore{states: map[string]*issues.State{}} }
func key(scope auth.Scope, project model.ID) string {
	return scope.OrgID().String() + ":" + project.String()
}
func (s *fakeStore) state(scope auth.Scope, project model.ID) *issues.State {
	k := key(scope, project)
	if s.states[k] == nil {
		s.states[k] = &issues.State{Issues: map[model.ID]issues.Record{}, Occurrences: map[model.ID]model.ID{}, Checkpoints: map[model.ID]model.Uint64{}, Commands: map[model.ID]issues.CommandRecord{}}
	}
	return s.states[k]
}
func (s *fakeStore) Load(_ context.Context, scope auth.Scope, project model.ID) (issues.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loads++
	var buf bytes.Buffer
	if e := gob.NewEncoder(&buf).Encode(s.state(scope, project)); e != nil {
		return issues.State{}, e
	}
	var out issues.State
	if e := gob.NewDecoder(&buf).Decode(&out); e != nil {
		return issues.State{}, e
	}
	if out.Issues == nil {
		out.Issues = map[model.ID]issues.Record{}
	}
	if out.Occurrences == nil {
		out.Occurrences = map[model.ID]model.ID{}
	}
	if out.Checkpoints == nil {
		out.Checkpoints = map[model.ID]model.Uint64{}
	}
	if out.Commands == nil {
		out.Commands = map[model.ID]issues.CommandRecord{}
	}
	return out, nil
}
func (s *fakeStore) Commit(_ context.Context, scope auth.Scope, project model.ID, c issues.Commit) error {
	if hook := s.beforeCommit; hook != nil {
		s.beforeCommit = nil
		hook()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state(scope, project)
	if s.failBefore != nil {
		return s.failBefore
	}
	if c.Gap != nil && s.denyGap {
		return model.Fail(model.Forbidden)
	}
	if c.ExpectedRevision != st.Revision {
		return model.Fail(model.Conflict)
	}
	for _, r := range c.Records {
		st.Issues[r.Issue.ID] = r
	}
	for occ, issue := range c.Occurrences {
		st.Occurrences[occ] = issue
	}
	s.effects = append(s.effects, c.Effects...)
	s.audits = append(s.audits, c.Audits...)
	if c.Command != nil {
		st.Commands[c.CommandID] = *c.Command
	}
	st.Revision++
	s.commits = append(s.commits, c)
	if s.tear {
		return errors.New("crash between evidence apply and checkpoint")
	}
	if c.Checkpoint != nil {
		st.Checkpoints[c.Checkpoint.Group] = c.Checkpoint.Index
	}
	if c.Gap != nil {
		st.Gaps = append(st.Gaps, *c.Gap)
	}
	return s.failAfter
}
func (s *fakeStore) regressEffects() int {
	n := 0
	for _, e := range s.effects {
		if e.Kind == "issue_regressed" {
			n++
		}
	}
	return n
}

type fakeClock struct{ at model.UnixNano }

func (c *fakeClock) Now() model.UnixNano { return c.at }

type fakeGraphs struct {
	mu    sync.Mutex
	graph releases.Graph
	calls int
}

func (g *fakeGraphs) Graph(context.Context, auth.Scope, model.ID) (releases.Graph, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	return g.graph, nil
}

type fakeFence struct{ err error }

func (f *fakeFence) Admit(context.Context, auth.Scope, model.ID) error { return f.err }

type fakePolicy struct{ err error }

func (f *fakePolicy) AuthorizePolicyWrite(context.Context, auth.Scope, model.ID) error { return f.err }

type fakeMigrator struct {
	calls   []model.GroupingMigration
	command []model.ID
}

func (m *fakeMigrator) MigrateGrouping(_ context.Context, _ auth.Scope, mig model.GroupingMigration, command model.ID) error {
	m.calls = append(m.calls, mig)
	m.command = append(m.command, command)
	return nil
}

type fx struct {
	t                  *testing.T
	app                *appcore.App
	dir                string
	org, project       model.ID
	org2, project2     model.ID
	writer, reader     auth.Scope
	otherWriter        auth.Scope
	store              *fakeStore
	clock              *fakeClock
	graphs             *fakeGraphs
	fence              *fakeFence
	policy             *fakePolicy
	migrator           *fakeMigrator
	svc                *issues.Service
	group              model.ID
	occ                map[uint64]model.ID
	next               uint64
	A, B, C, D, U, gap model.ID
}

func (f *fx) revision() model.Revision {
	var r model.Revision
	if e := f.app.Control.View(context.Background(), func(st model.ControlState) error { r = st.Revision; return nil }); e != nil {
		f.t.Fatal(e)
	}
	return r
}
func (f *fx) admin(actor auth.Credential, org model.ID, kind string, p auth.AdminPayload) {
	f.t.Helper()
	p.Reason = "issues behavior fixture"
	raw, e := json.Marshal(p)
	if e != nil {
		f.t.Fatal(e)
	}
	if _, e = f.app.Auth.AdminCommand(context.Background(), actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: f.revision(), OrgID: org, Kind: kind, Payload: raw}); e != nil {
		f.t.Fatalf("%s: %v", kind, e)
	}
}
func (f *fx) scopeFor(email, password string, org model.ID, projects []model.ID, permission auth.Permission) auth.Scope {
	f.t.Helper()
	login, e := f.app.Auth.Login(context.Background(), email, password, "")
	if e != nil {
		f.t.Fatal(e)
	}
	cred, e := f.app.Auth.Authenticate(context.Background(), login.Token)
	if e != nil {
		f.t.Fatal(e)
	}
	scope, e := f.app.Auth.Authorize(context.Background(), cred, org, projects, permission)
	if e != nil {
		f.t.Fatal(e)
	}
	return scope
}

func newFx(t *testing.T) *fx {
	t.Helper()
	f := &fx{t: t, dir: t.TempDir(), org: model.NewID(), project: model.NewID(), org2: model.NewID(), project2: model.NewID(), group: model.NewID(), occ: map[uint64]model.ID{}}
	var e error
	f.app, e = appcore.Open(f.dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.app.Close() })
	ctx := context.Background()
	bootstrap, e := f.app.Control.BootstrapToken()
	if e != nil {
		t.Fatal(e)
	}
	session, e := f.app.Auth.Bootstrap(ctx, bootstrap, "issues@example.test", "issues fixture password 2026")
	if e != nil {
		t.Fatal(e)
	}
	actor, e := f.app.Auth.Authenticate(ctx, session.Token)
	if e != nil {
		t.Fatal(e)
	}
	f.admin(actor, f.org, "create_org", auth.AdminPayload{Name: "issues"})
	f.admin(actor, f.org, "create_project", auth.AdminPayload{ID: f.project, Name: "application"})
	f.admin(actor, f.org2, "create_org", auth.AdminPayload{Name: "other"})
	f.admin(actor, f.org2, "create_project", auth.AdminPayload{ID: f.project2, Name: "other application"})
	writerID, readerID, otherID := model.NewID(), model.NewID(), model.NewID()
	for _, u := range []struct {
		id    model.ID
		email string
	}{{writerID, "writer@example.test"}, {readerID, "reader@example.test"}, {otherID, "other@example.test"}} {
		f.admin(actor, f.org, "create_user", auth.AdminPayload{ID: u.id, Email: u.email, Password: "issues fixture password 2026"})
	}
	f.admin(actor, f.org, "membership", auth.AdminPayload{UserID: writerID, Enabled: true})
	f.admin(actor, f.org, "grant", auth.AdminPayload{UserID: writerID, ProjectID: f.project, Permissions: []string{"telemetry.read", "issues.write"}, Enabled: true})
	f.admin(actor, f.org, "membership", auth.AdminPayload{UserID: readerID, Enabled: true})
	f.admin(actor, f.org, "grant", auth.AdminPayload{UserID: readerID, ProjectID: f.project, Permissions: []string{"telemetry.read"}, Enabled: true})
	f.admin(actor, f.org2, "membership", auth.AdminPayload{UserID: otherID, Enabled: true})
	f.admin(actor, f.org2, "grant", auth.AdminPayload{UserID: otherID, ProjectID: f.project2, Permissions: []string{"telemetry.read", "issues.write"}, Enabled: true})
	pw := "issues fixture password 2026"
	f.writer = f.scopeFor("writer@example.test", pw, f.org, []model.ID{f.project}, auth.Permission("issues.write"))
	f.reader = f.scopeFor("reader@example.test", pw, f.org, []model.ID{f.project}, auth.Read)
	f.otherWriter = f.scopeFor("other@example.test", pw, f.org2, []model.ID{f.project2}, auth.Permission("issues.write"))

	f.A, f.B, f.C, f.D, f.U, f.gap = model.NewID(), model.NewID(), model.NewID(), model.NewID(), model.NewID(), model.NewID()
	rel := func(id model.ID, parents ...model.ID) releases.Release {
		return releases.Release{ID: id, Org: f.org, Project: f.project, BuildID: id, Parents: parents}
	}
	f.graphs = &fakeGraphs{graph: releases.Graph{f.A: rel(f.A), f.B: rel(f.B, f.A), f.C: rel(f.C, f.B), f.D: rel(f.D, f.A), f.U: rel(f.U, f.gap)}}
	f.store, f.clock, f.fence, f.policy, f.migrator = newFakeStore(), &fakeClock{at: 100}, &fakeFence{}, &fakePolicy{}, &fakeMigrator{}
	f.svc = f.service(issues.RegressionPolicy{MinOccurrences: 1})
	return f
}
func (f *fx) service(p issues.RegressionPolicy) *issues.Service {
	svc, e := issues.New(issues.Deps{Store: f.store, Authorizer: f.app.Auth, Graphs: f.graphs, Fence: f.fence, Policy: f.policy, Migrator: f.migrator, Clock: f.clock, Regression: p})
	if e != nil {
		f.t.Fatal(e)
	}
	return svc
}

// ev builds evidence at the next durable cursor index.
func (f *fx) ev(fp byte, release model.ID, event model.UnixNano) issues.Evidence {
	f.next++
	return f.evAt(f.next, fp, release, event)
}
func (f *fx) evAt(index uint64, fp byte, release model.ID, event model.UnixNano) issues.Evidence {
	if f.occ[index] == (model.ID{}) {
		f.occ[index] = model.NewID()
	}
	e := issues.Evidence{OccurrenceID: f.occ[index], RecordID: model.NewID(), Origin: model.Cursor{Group: f.group, Index: model.Uint64(index)}, GroupingVersion: 1, Fingerprint: model.Hash{fp}, EventTime: event, ArrivalTime: event + 1000, ReleaseID: &release, Ancestry: "known", Freshness: "fresh", Ordinal: model.Uint64(index)}
	if release == f.U {
		e.Ancestry = "unknown"
	}
	return e
}
func (f *fx) apply(es ...issues.Evidence) {
	f.t.Helper()
	last := es[len(es)-1].Origin
	for _, e := range es {
		if e.Origin.Index > last.Index {
			last = e.Origin
		}
	}
	if e := f.svc.ApplyThrough(context.Background(), f.writer, last, es); e != nil {
		f.t.Fatal(e)
	}
}
func (f *fx) projectState() issues.State {
	st, e := f.store.Load(context.Background(), f.writer, f.project)
	if e != nil {
		f.t.Fatal(e)
	}
	return st
}
func (f *fx) issueFor(fp byte) issues.Issue {
	f.t.Helper()
	for _, r := range f.projectState().Issues {
		if r.Issue.Fingerprint == (model.Hash{fp}) {
			return r.Issue
		}
	}
	f.t.Fatalf("no issue for fingerprint %d", fp)
	return issues.Issue{}
}
func (f *fx) act(kind string, i issues.Issue, mutate func(*issues.IssueAction)) (issues.Issue, error) {
	a := issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: i.Revision, IssueID: i.ID, Kind: kind, Reason: "reviewed by on-call"}
	if mutate != nil {
		mutate(&a)
	}
	return f.svc.Act(context.Background(), f.writer, a)
}
func (f *fx) resolve(fp byte, fixed ...model.ID) issues.Issue {
	f.t.Helper()
	f.clock.at = 100
	got, e := f.act("resolve", f.issueFor(fp), func(a *issues.IssueAction) { a.FixedDescendantFrontier = fixed })
	if e != nil {
		f.t.Fatal(e)
	}
	return got
}
func (f *fx) explain(i issues.Issue) []issues.Explanation {
	f.t.Helper()
	out, e := f.svc.Explain(context.Background(), f.writer, f.project, i.ID)
	if e != nil {
		f.t.Fatal(e)
	}
	return out
}
func code(e error) model.Code {
	var fault *model.Fault
	if errors.As(e, &fault) {
		return fault.Code
	}
	return ""
}

func TestIssueLateDedupAndRegression(t *testing.T) {
	t.Run("fixed descendant frontier", func(t *testing.T) {
		f := newFx(t)
		first := f.ev(1, f.A, 50)
		f.apply(first)
		resolved := f.resolve(1, f.B)
		if resolved.Workflow != "resolved" || resolved.ResolutionTime == nil || *resolved.ResolutionTime != 100 || !reflect.DeepEqual(resolved.ResolutionFrontier, []model.ID{f.A}) || !reflect.DeepEqual(resolved.FixedDescendants, []model.ID{f.B}) {
			t.Fatalf("resolution not recorded: %+v", resolved)
		}
		// A retry of the same durable occurrence, at the same or a later cursor, never counts twice.
		f.apply(first)
		retry := first
		retry.ArrivalTime += 9999
		f.apply(retry)
		after := f.issueFor(1)
		if s := issues.Summarize(after); s.Count != 1 || after.Revision != resolved.Revision || after.Workflow != "resolved" {
			t.Fatalf("duplicate changed the issue: %+v summary %+v", after, s)
		}
		if after.Occurrences[0].ArrivalTime != first.ArrivalTime {
			t.Fatal("a retry rewrote the receipt time")
		}
		// The same occurrence ID claiming a different durable origin is corruption, not a duplicate.
		conflicting := first
		conflicting.Origin.Index = 7
		if e := f.svc.ApplyThrough(context.Background(), f.writer, model.Cursor{Group: f.group, Index: 7}, []issues.Evidence{conflicting}); code(e) != model.Conflict {
			t.Fatalf("occurrence identity reuse accepted: %v", e)
		}
		// Late history: an older-release occurrence at event time 90 is appended, never reopens.
		late := f.evAt(3, 1, f.A, 90)
		f.next = 3
		f.apply(late)
		afterLate := f.issueFor(1)
		s := issues.Summarize(afterLate)
		if afterLate.Workflow != "resolved" || len(afterLate.LateHistory) != 1 || len(afterLate.Occurrences) != 1 || s.Count != 2 || s.Late != 1 || s.FirstSeen != 50 || s.LastSeen != 90 || s.LastArrival != 1090 {
			t.Fatalf("late history not appended or recomputed: %+v %+v", afterLate, s)
		}
		// Post-boundary occurrences in releases that do not contain the fix do not reopen.
		f.apply(f.ev(1, f.A, 110))
		f.apply(f.ev(1, f.D, 115))
		if got := f.issueFor(1); got.Workflow != "resolved" {
			t.Fatal("release without the fix reopened the issue")
		}
		explained := f.explain(afterLate)
		if len(explained) != 2 || explained[0].Decision.Eligible || explained[0].Decision.Reason == "" || !reflect.DeepEqual(explained[0].Decision.Frontier, []model.ID{f.B}) {
			t.Fatalf("ineligible evaluations not recorded: %+v", explained)
		}
		// A new occurrence in a descendant of the fix reopens, with a reconstructible explanation.
		descendant := f.ev(1, f.C, 120)
		f.apply(descendant)
		reopened := f.issueFor(1)
		if reopened.Workflow != "open" || reopened.ResolutionTime != nil || len(reopened.FixedDescendants) != 0 {
			t.Fatalf("descendant did not reopen: %+v", reopened)
		}
		explained = f.explain(reopened)
		last := explained[len(explained)-1]
		if !last.Reopened || !last.Decision.Eligible || !last.Decision.AncestryKnown || last.OccurrenceID != descendant.OccurrenceID || last.ResolutionTime != 100 || last.Threshold != 1 || last.Qualifying != 1 || !reflect.DeepEqual(last.Decision.Frontier, []model.ID{f.B}) || last.EvidenceRelease != f.C {
			t.Fatalf("regression explanation not reconstructible: %+v", last)
		}
		if f.store.regressEffects() != 1 {
			t.Fatalf("regression effects %d", f.store.regressEffects())
		}
		// Replaying the regressing occurrence must not regress or notify again.
		f.apply(descendant)
		if f.store.regressEffects() != 1 || f.issueFor(1).Revision != reopened.Revision {
			t.Fatal("replay re-applied the regression")
		}
	})
	t.Run("unknown ancestry follows the explicit event-time boundary", func(t *testing.T) {
		f := newFx(t)
		f.apply(f.ev(2, f.A, 50))
		resolved := f.resolve(2)
		f.apply(f.ev(2, f.U, 90))
		if got := f.issueFor(2); got.Workflow != "resolved" || len(got.LateHistory) != 1 {
			t.Fatalf("unknown ancestry before the boundary: %+v", got)
		}
		f.apply(f.ev(2, f.U, 110))
		got := f.issueFor(2)
		if got.Workflow != "open" {
			t.Fatal("unknown ancestry after the explicit boundary did not follow it")
		}
		explained := f.explain(resolved)
		last := explained[len(explained)-1]
		if last.Decision.AncestryKnown || !last.Reopened || !bytes.Contains([]byte(last.Decision.Reason), []byte("ancestry unknown")) {
			t.Fatalf("unknown ancestry not recorded: %+v", last)
		}
	})
	t.Run("ignored keeps counts and is not recovered", func(t *testing.T) {
		f := newFx(t)
		f.apply(f.ev(3, f.A, 50))
		ignored, e := f.act("ignore", f.issueFor(3), nil)
		if e != nil || ignored.Workflow != "ignored" {
			t.Fatalf("ignore: %v %+v", e, ignored)
		}
		f.apply(f.ev(3, f.C, 200))
		got := f.issueFor(3)
		if got.Workflow != "ignored" || issues.Summarize(got).Count != 2 || f.store.regressEffects() != 0 {
			t.Fatalf("ignored issue changed state or notified: %+v", got)
		}
		open, e := f.act("unignore", got, nil)
		if e != nil || open.Workflow != "open" || issues.Summarize(open).Count != 2 {
			t.Fatalf("unignore: %v %+v", e, open)
		}
	})
}

func TestIssueActions(t *testing.T) {
	f := newFx(t)
	f.apply(f.ev(1, f.A, 50))
	current := f.issueFor(1)
	// Stale expected revision.
	if _, e := f.act("resolve", current, func(a *issues.IssueAction) { a.ExpectedVersion-- }); code(e) != model.Conflict {
		t.Fatalf("stale version: %v", e)
	}
	// Frontier needs a reason and known releases; nothing is committed on rejection.
	commits := len(f.store.commits)
	if _, e := f.act("resolve", current, func(a *issues.IssueAction) { a.Reason = ""; a.FixedDescendantFrontier = []model.ID{f.B} }); code(e) != model.Invalid {
		t.Fatalf("unreasoned frontier: %v", e)
	}
	if _, e := f.act("resolve", current, func(a *issues.IssueAction) { a.FixedDescendantFrontier = []model.ID{model.NewID()} }); code(e) != model.Invalid {
		t.Fatalf("unknown frontier release: %v", e)
	}
	if _, e := f.act("resolve", current, func(a *issues.IssueAction) { a.ResolutionBoundary = 5000 }); code(e) != model.Invalid {
		t.Fatalf("future boundary: %v", e)
	}
	if _, e := f.act("explode", current, nil); code(e) != model.Invalid {
		t.Fatalf("unknown kind: %v", e)
	}
	if len(f.store.commits) != commits {
		t.Fatal("rejected actions committed")
	}
	// Audited, reasoned frontier and command-ID retry.
	command := model.NewID()
	resolve := func(m func(*issues.IssueAction)) (issues.Issue, error) {
		return f.act("resolve", current, func(a *issues.IssueAction) {
			a.CommandID = command
			a.Reason = "fixed in B"
			a.FixedDescendantFrontier = []model.ID{f.B}
			if m != nil {
				m(a)
			}
		})
	}
	first, e := resolve(nil)
	if e != nil || first.Workflow != "resolved" {
		t.Fatalf("resolve: %v", e)
	}
	if len(f.store.audits) != 1 || f.store.audits[0].Reason != "fixed in B" || f.store.audits[0].ID != command || f.store.audits[0].Principal != f.writer.PrincipalID() || f.store.audits[0].Org != f.org.String() || f.store.audits[0].Action != "issues.resolve" || !reflect.DeepEqual(f.store.audits[0].Targets, []model.ID{current.ID, f.B}) {
		t.Fatalf("frontier not audited: %+v", f.store.audits)
	}
	commits = len(f.store.commits)
	again, e := resolve(nil)
	if e != nil || again.Revision != first.Revision || len(f.store.commits) != commits || len(f.store.audits) != 1 {
		t.Fatalf("command retry re-applied: %v", e)
	}
	if _, e = resolve(func(a *issues.IssueAction) { a.Reason = "something else" }); code(e) != model.Conflict {
		t.Fatalf("command ID reused for a different action: %v", e)
	}
	// Transitions are explicit.
	if _, e = f.act("resolve", first, nil); code(e) != model.Conflict {
		t.Fatalf("double resolve: %v", e)
	}
	if _, e = f.act("unignore", first, nil); code(e) != model.Conflict {
		t.Fatalf("unignore of a resolved issue: %v", e)
	}
	reopened, e := f.act("reopen", first, nil)
	if e != nil || reopened.Workflow != "open" || reopened.ResolutionTime != nil {
		t.Fatalf("reopen: %v %+v", e, reopened)
	}
	if _, e = f.act("reopen", reopened, nil); code(e) != model.Conflict {
		t.Fatalf("reopen of an open issue: %v", e)
	}
	// Missing issues.write is the service's decision, not the caller's.
	commits = len(f.store.commits)
	if _, e = f.svc.Act(context.Background(), f.reader, issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: reopened.Revision, IssueID: reopened.ID, Kind: "ignore", Reason: "r"}); code(e) != model.Forbidden {
		t.Fatalf("read-only scope acted: %v", e)
	}
	if e = f.svc.ApplyThrough(context.Background(), f.reader, model.Cursor{Group: f.group, Index: 9}, []issues.Evidence{f.evAt(9, 1, f.A, 60)}); code(e) != model.Forbidden {
		t.Fatalf("read-only scope applied evidence: %v", e)
	}
	if len(f.store.commits) != commits {
		t.Fatal("forbidden call committed")
	}
	// Another organization learns nothing: a real foreign issue and a missing one answer identically.
	foreign, e1 := f.svc.Act(context.Background(), f.otherWriter, issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: reopened.Revision, IssueID: reopened.ID, Kind: "ignore", Reason: "r"})
	_, e2 := f.svc.Act(context.Background(), f.otherWriter, issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: reopened.Revision, IssueID: model.NewID(), Kind: "ignore", Reason: "r"})
	var f1, f2 *model.Fault
	if !errors.As(e1, &f1) || !errors.As(e2, &f2) || f1.Code != model.NotFound || f1.Code != f2.Code || f1.SafeDetail != f2.SafeDetail || foreign.ID != (model.ID{}) {
		t.Fatalf("cross-org metadata leaked: %v / %v / %+v", e1, e2, foreign)
	}
	if _, e = f.svc.Get(context.Background(), f.otherWriter, f.project, reopened.ID); e == nil {
		t.Fatal("cross-org read of a project the scope does not hold")
	}
}

func TestIssueGroupingMigrationNeedsPolicyWrite(t *testing.T) {
	f := newFx(t)
	f.apply(f.ev(1, f.A, 50))
	current := f.issueFor(1)
	migration := model.GroupingMigration{ID: model.NewID(), Org: f.org, Project: f.project, From: current.ID, To: model.NewID(), FromRevision: current.Revision, GroupingVersion: 2, Fingerprint: model.Hash{9}, Reason: "approved grouping upgrade", At: 100}
	do := func(m *model.GroupingMigration) error {
		_, e := f.act("grouping_migration", current, func(a *issues.IssueAction) { a.Migration = m })
		return e
	}
	f.policy.err = model.Fail(model.Forbidden)
	if e := do(&migration); code(e) != model.Forbidden || len(f.migrator.calls) != 0 {
		t.Fatalf("migration without project policy.write: %v", e)
	}
	f.policy.err = nil
	stale := migration
	stale.FromRevision--
	if e := do(&stale); code(e) != model.Conflict || len(f.migrator.calls) != 0 {
		t.Fatalf("migration from a stale revision: %v", e)
	}
	foreign := migration
	foreign.Org = f.org2
	if e := do(&foreign); code(e) != model.Invalid || len(f.migrator.calls) != 0 {
		t.Fatalf("migration naming another org: %v", e)
	}
	if e := do(nil); code(e) != model.Invalid {
		t.Fatalf("migration without payload: %v", e)
	}
	if e := do(&migration); e != nil || len(f.migrator.calls) != 1 || !reflect.DeepEqual(f.migrator.calls[0], migration) {
		t.Fatalf("migration not delegated: %v", e)
	}
	if _, e := f.act("resolve", current, func(a *issues.IssueAction) { a.Migration = &migration }); code(e) != model.Invalid {
		t.Fatalf("non-migration action carried a migration: %v", e)
	}
}

func TestIssueTotalOrderBetweenHumanAndEvidence(t *testing.T) {
	t.Run("evidence lands first: stale human is rejected, never overwritten", func(t *testing.T) {
		f := newFx(t)
		f.apply(f.ev(1, f.A, 50))
		current := f.issueFor(1)
		late := f.ev(1, f.A, 60)
		f.store.beforeCommit = func() { f.apply(late) }
		if _, e := f.act("resolve", current, nil); code(e) != model.Conflict {
			t.Fatalf("human resolved a revision it had not seen: %v", e)
		}
		if got := f.issueFor(1); got.Workflow != "open" || issues.Summarize(got).Count != 2 {
			t.Fatalf("racing evidence lost: %+v", got)
		}
	})
	t.Run("human lands first: evidence is rereduced as late history", func(t *testing.T) {
		f := newFx(t)
		f.apply(f.ev(1, f.A, 50))
		current := f.issueFor(1)
		f.clock.at = 100
		pending := f.ev(1, f.A, 90)
		f.store.beforeCommit = func() {
			if _, e := f.act("resolve", current, nil); e != nil {
				t.Error(e)
			}
		}
		f.apply(pending)
		got := f.issueFor(1)
		if got.Workflow != "resolved" || len(got.LateHistory) != 1 || f.store.regressEffects() != 0 {
			t.Fatalf("evidence overwrote or reopened after the human resolution: %+v", got)
		}
	})
}

func TestCheckpointCrashPoints(t *testing.T) {
	regressingBatch := func(f *fx) (issues.Evidence, model.Cursor) {
		f.apply(f.ev(1, f.A, 50))
		f.resolve(1, f.B)
		e := f.ev(1, f.C, 120)
		return e, e.Origin
	}
	t.Run("crash before commit leaves nothing and replay applies once", func(t *testing.T) {
		f := newFx(t)
		e, cursor := regressingBatch(f)
		f.store.failBefore = errors.New("crash")
		if err := f.svc.ApplyThrough(context.Background(), f.writer, cursor, []issues.Evidence{e}); err == nil {
			t.Fatal("crash was not reported")
		}
		if st := f.projectState(); st.Checkpoints[f.group] != 1 || len(st.Occurrences) != 1 || f.issueFor(1).Workflow != "resolved" {
			t.Fatalf("partial effects survived: %+v", st.Checkpoints)
		}
		f.store.failBefore = nil
		f.apply(e)
		if st := f.projectState(); st.Checkpoints[f.group] != model.Uint64(cursor.Index) || len(st.Occurrences) != 2 || f.store.regressEffects() != 1 {
			t.Fatal("replay did not apply exactly once")
		}
	})
	t.Run("lost acknowledgement replays as a no-op", func(t *testing.T) {
		f := newFx(t)
		e, cursor := regressingBatch(f)
		f.store.failAfter = errors.New("ack lost")
		if err := f.svc.ApplyThrough(context.Background(), f.writer, cursor, []issues.Evidence{e}); err == nil {
			t.Fatal("lost ack was not reported")
		}
		f.store.failAfter = nil
		commits := len(f.store.commits)
		f.apply(e)
		if len(f.store.commits) != commits || f.store.regressEffects() != 1 || issues.Summarize(f.issueFor(1)).Count != 2 {
			t.Fatal("replay after a committed batch changed state")
		}
	})
	t.Run("crash between evidence apply and checkpoint cannot double count, regress or notify", func(t *testing.T) {
		f := newFx(t)
		e, cursor := regressingBatch(f)
		f.store.tear = true
		if err := f.svc.ApplyThrough(context.Background(), f.writer, cursor, []issues.Evidence{e}); err == nil {
			t.Fatal("torn commit was not reported")
		}
		f.store.tear = false
		if f.projectState().Checkpoints[f.group] != 1 {
			t.Fatal("torn fixture advanced the checkpoint")
		}
		f.apply(e)
		st := f.projectState()
		if issues.Summarize(f.issueFor(1)).Count != 2 || f.store.regressEffects() != 1 || st.Checkpoints[f.group] != model.Uint64(cursor.Index) {
			t.Fatalf("replay after torn apply double applied: count %d effects %d", issues.Summarize(f.issueFor(1)).Count, f.store.regressEffects())
		}
	})
	t.Run("one atomic commit carries evidence, effects and checkpoint", func(t *testing.T) {
		f := newFx(t)
		e, cursor := regressingBatch(f)
		before := len(f.store.commits)
		f.apply(e)
		if len(f.store.commits) != before+1 {
			t.Fatalf("batch used %d commits", len(f.store.commits)-before)
		}
		c := f.store.commits[len(f.store.commits)-1]
		if c.Checkpoint == nil || c.Checkpoint.Group != f.group || c.Checkpoint.Index != model.Uint64(cursor.Index) || len(c.Records) != 1 || len(c.Effects) != 1 || c.Occurrences[e.OccurrenceID] != c.Records[0].Issue.ID {
			t.Fatalf("commit incomplete: %+v", c)
		}
	})
	t.Run("cursor rules", func(t *testing.T) {
		f := newFx(t)
		f.apply(f.ev(1, f.A, 50), f.ev(1, f.A, 51), f.ev(1, f.A, 52))
		commits := len(f.store.commits)
		if f.projectState().Checkpoints[f.group] != 3 {
			t.Fatal("checkpoint not at the batch cursor")
		}
		other := f.ev(1, f.A, 60)
		other.Origin.Group = model.NewID()
		beyond := f.ev(1, f.A, 61)
		for name, c := range map[string]struct {
			cursor model.Cursor
			e      issues.Evidence
		}{
			"group mismatch":      {model.Cursor{Group: f.group, Index: 10}, other},
			"origin beyond":       {model.Cursor{Group: f.group, Index: beyond.Origin.Index - 1}, beyond},
			"zero group":          {model.Cursor{Index: 10}, beyond},
			"zero index":          {model.Cursor{Group: f.group}, beyond},
			"zero occurrence":     {model.Cursor{Group: f.group, Index: 10}, func() issues.Evidence { e := beyond; e.OccurrenceID = model.ID{}; return e }()},
			"known without build": {model.Cursor{Group: f.group, Index: 10}, func() issues.Evidence { e := beyond; e.ReleaseID = nil; return e }()},
		} {
			if err := f.svc.ApplyThrough(context.Background(), f.writer, c.cursor, []issues.Evidence{c.e}); code(err) != model.Invalid {
				t.Fatalf("%s accepted: %v", name, err)
			}
		}
		// A cursor behind the checkpoint is a replay; the checkpoint never moves back.
		if err := f.svc.ApplyThrough(context.Background(), f.writer, model.Cursor{Group: f.group, Index: 2}, nil); err != nil {
			t.Fatal(err)
		}
		if f.projectState().Checkpoints[f.group] != 3 || len(f.store.commits) != commits {
			t.Fatal("stale cursor moved state")
		}
		// Evidence at or below the checkpoint that the ledger never saw was suppressed or gapped; it is not resurrected.
		ghost := f.evAt(2, 4, f.A, 70)
		ghost.OccurrenceID = model.NewID()
		if err := f.svc.ApplyThrough(context.Background(), f.writer, model.Cursor{Group: f.group, Index: 4}, []issues.Evidence{ghost}); err != nil {
			t.Fatal(err)
		}
		for _, r := range f.projectState().Issues {
			if r.Issue.Fingerprint == (model.Hash{4}) {
				t.Fatal("evidence below the checkpoint was resurrected")
			}
		}
	})
}

func TestIssueEvidenceGap(t *testing.T) {
	f := newFx(t)
	f.apply(f.ev(1, f.A, 50), f.ev(1, f.A, 51))
	gap := model.EvidenceGap{ID: model.NewID(), Org: f.org, Project: f.project, Group: f.group, After: 2, Through: 9, Count: 7, Start: 60, End: 90, Reason: "journal expired before processing", RecordedAt: 100}
	if h, e := f.svc.Health(context.Background(), f.writer, f.project); e != nil || !h.Complete {
		t.Fatalf("fresh project not complete: %v", e)
	}
	// A denied gap commit cannot advance the checkpoint or mark the journal evictable.
	f.store.denyGap = true
	if e := f.svc.RecordGap(context.Background(), f.writer, gap); e == nil {
		t.Fatal("denied gap commit reported success")
	}
	if f.projectState().Checkpoints[f.group] != 2 {
		t.Fatal("checkpoint advanced past an uncommitted gap")
	}
	f.store.denyGap = false
	skipped := gap
	skipped.After = 4
	if e := f.svc.RecordGap(context.Background(), f.writer, skipped); code(e) != model.Conflict {
		t.Fatalf("gap that skips unprocessed evidence silently: %v", e)
	}
	for name, bad := range map[string]model.EvidenceGap{
		"foreign org":     func() model.EvidenceGap { g := gap; g.Org = f.org2; return g }(),
		"foreign project": func() model.EvidenceGap { g := gap; g.Project = f.project2; return g }(),
		"empty interval":  func() model.EvidenceGap { g := gap; g.Through = g.After; return g }(),
		"no reason":       func() model.EvidenceGap { g := gap; g.Reason = ""; return g }(),
	} {
		if e := f.svc.RecordGap(context.Background(), f.writer, bad); code(e) != model.Invalid {
			t.Fatalf("%s accepted: %v", name, e)
		}
	}
	if e := f.svc.RecordGap(context.Background(), f.writer, gap); e != nil {
		t.Fatal(e)
	}
	if e := f.svc.RecordGap(context.Background(), f.writer, gap); e != nil {
		t.Fatalf("gap retry: %v", e)
	}
	st := f.projectState()
	if st.Checkpoints[f.group] != 9 || len(st.Gaps) != 1 {
		t.Fatalf("gap not committed once with its checkpoint: %+v", st)
	}
	h, e := f.svc.Health(context.Background(), f.writer, f.project)
	if e != nil || h.Complete || len(h.Gaps) != 1 || h.Gaps[0].ID != gap.ID {
		t.Fatalf("gap not surfaced as unknown health: %v %+v", e, h)
	}
	// Processing resumes after the gap; the gapped interval is not resurrected.
	f.next = 9
	f.apply(f.ev(1, f.A, 120))
	if issues.Summarize(f.issueFor(1)).Count != 3 {
		t.Fatal("processing did not resume after the gap")
	}
}

func TestIssueFencePrecedesReadAndWork(t *testing.T) {
	f := newFx(t)
	f.apply(f.ev(1, f.A, 50))
	current := f.issueFor(1)
	loads, graphs, commits := f.store.loads, f.graphs.calls, len(f.store.commits)
	f.fence.err = model.Fail(model.NotFound)
	ctx := context.Background()
	_, eAct := f.svc.Act(ctx, f.writer, issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: current.Revision, IssueID: current.ID, Kind: "ignore", Reason: "r"})
	eApply := f.svc.ApplyThrough(ctx, f.writer, model.Cursor{Group: f.group, Index: 9}, []issues.Evidence{f.evAt(9, 1, f.C, 60)})
	_, eGet := f.svc.Get(ctx, f.writer, f.project, current.ID)
	_, eExplain := f.svc.Explain(ctx, f.writer, f.project, current.ID)
	_, eHealth := f.svc.Health(ctx, f.writer, f.project)
	eGap := f.svc.RecordGap(ctx, f.writer, model.EvidenceGap{ID: model.NewID(), Org: f.org, Project: f.project, Group: f.group, After: 1, Through: 3, Count: 2, Reason: "x", RecordedAt: 1})
	for i, e := range []error{eAct, eApply, eGet, eExplain, eHealth, eGap} {
		if code(e) != model.NotFound {
			t.Fatalf("operation %d ran behind a deletion fence: %v", i, e)
		}
	}
	if f.store.loads != loads || f.graphs.calls != graphs || len(f.store.commits) != commits {
		t.Fatal("state was read or written before the fence")
	}
}

func TestRegressionThresholdAndWindow(t *testing.T) {
	run := func(policy issues.RegressionPolicy, events ...model.UnixNano) (issues.Issue, []issues.Explanation) {
		f := newFx(t)
		f.svc = f.service(policy)
		f.apply(f.ev(1, f.A, 50))
		resolved := f.resolve(1, f.B)
		for _, at := range events {
			f.apply(f.ev(1, f.C, at))
		}
		return f.issueFor(1), f.explain(resolved)
	}
	got, explained := run(issues.RegressionPolicy{MinOccurrences: 2, Window: 10}, 120)
	if got.Workflow != "resolved" || len(explained) != 1 || !explained[0].Decision.Eligible || explained[0].Reopened || explained[0].Qualifying != 1 || explained[0].Threshold != 2 || explained[0].Window != 10 {
		t.Fatalf("one qualifying occurrence reopened under a threshold of two: %+v", explained)
	}
	if got, _ = run(issues.RegressionPolicy{MinOccurrences: 2, Window: 10}, 120, 131); got.Workflow != "resolved" {
		t.Fatal("qualifying occurrences outside the window were combined")
	}
	got, explained = run(issues.RegressionPolicy{MinOccurrences: 2, Window: 10}, 120, 129)
	if got.Workflow != "open" || explained[len(explained)-1].Qualifying != 2 || !explained[len(explained)-1].Reopened {
		t.Fatalf("threshold within window did not reopen: %+v", explained)
	}
}

func TestIssueDurableEvidenceReplay(t *testing.T) {
	f := newFx(t)
	a, b, c := f.ev(1, f.A, 50), f.ev(1, f.A, 60), f.ev(1, f.A, 40)
	f.apply(a, b, c)
	// Restart: a fresh service over the same durable store; the worker replays an overlapping range with retried copies.
	f.svc = f.service(issues.RegressionPolicy{MinOccurrences: 1})
	d, e := f.ev(1, f.A, 70), f.ev(1, f.C, 80)
	retriedB := b
	retriedB.ArrivalTime = 999999
	if err := f.svc.ApplyThrough(context.Background(), f.writer, e.Origin, []issues.Evidence{retriedB, c, d, e, d}); err != nil {
		t.Fatal(err)
	}
	got := f.issueFor(1)
	s := issues.Summarize(got)
	unique := map[model.ID]bool{a.OccurrenceID: true, b.OccurrenceID: true, c.OccurrenceID: true, d.OccurrenceID: true, e.OccurrenceID: true}
	if s.Count != len(unique) || s.FirstSeen != 40 || s.LastSeen != 80 {
		t.Fatalf("count %d want %d summary %+v", s.Count, len(unique), s)
	}
	for _, o := range got.Occurrences {
		if o.OccurrenceID == b.OccurrenceID && o.ArrivalTime != b.ArrivalTime {
			t.Fatal("replay rewrote a receipt time")
		}
	}
	// Late older-release history stays visible after resolution and a descendant regresses with an auditable explanation.
	f.resolve(1, f.B)
	f.apply(f.evAt(6, 1, f.A, 75))
	f.next = 6
	f.apply(f.ev(1, f.C, 130))
	reopened := f.issueFor(1)
	if len(reopened.LateHistory) != 1 || reopened.Workflow != "open" {
		t.Fatalf("late history or regression missing: %+v", reopened)
	}
	explained := f.explain(reopened)
	if len(explained) == 0 || !explained[len(explained)-1].Reopened || fmt.Sprint(explained[len(explained)-1].Decision.Frontier) != fmt.Sprint([]model.ID{f.B}) {
		t.Fatalf("regression explanation missing: %+v", explained)
	}
}
