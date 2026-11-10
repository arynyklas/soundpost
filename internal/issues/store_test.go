// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package issues_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/issues"
	"soundpost/internal/model"
)

// realFx is the service fixture over the real control store: the same
// organization, scopes, release graph and clock as fx, with the fake ledger
// replaced by the durable adapter.
type realFx struct {
	*fx
	real *issues.ControlStore
}

func newRealFx(t *testing.T) *realFx {
	t.Helper()
	r := &realFx{fx: newFx(t)}
	r.bind()
	return r
}

func (r *realFx) bind() {
	real, e := issues.NewControlStore(r.app.Control)
	if e != nil {
		r.t.Fatal(e)
	}
	r.real = real
	svc, e := issues.New(issues.Deps{Store: real, Authorizer: r.app.Auth, Graphs: r.graphs, Fence: r.fence, Policy: r.policy, Migrator: r.migrator, Clock: r.clock, Regression: issues.RegressionPolicy{MinOccurrences: 1}})
	if e != nil {
		r.t.Fatal(e)
	}
	r.svc = svc
}

// restart closes the whole application and opens it again over the same
// directory, as a process restart would; every scope is minted again.
func (r *realFx) restart() {
	r.t.Helper()
	if e := r.app.Close(); e != nil {
		r.t.Fatal(e)
	}
	app, e := appcore.Open(r.dir)
	if e != nil {
		r.t.Fatal(e)
	}
	r.app = app
	pw := "issues fixture password 2026"
	r.writer = r.scopeFor("writer@example.test", pw, r.org, []model.ID{r.project}, auth.Permission("issues.write"))
	r.reader = r.scopeFor("reader@example.test", pw, r.org, []model.ID{r.project}, auth.Read)
	r.otherWriter = r.scopeFor("other@example.test", pw, r.org2, []model.ID{r.project2}, auth.Permission("issues.write"))
	r.bind()
}

func (r *realFx) load() issues.State {
	r.t.Helper()
	st, e := r.real.Load(context.Background(), r.writer, r.project)
	if e != nil {
		r.t.Fatal(e)
	}
	return st
}
func (r *realFx) issueByFp(fp byte) issues.Issue {
	r.t.Helper()
	for _, rec := range r.load().Issues {
		if rec.Issue.Fingerprint == (model.Hash{fp}) {
			return rec.Issue
		}
	}
	r.t.Fatalf("no issue for fingerprint %d", fp)
	return issues.Issue{}
}
func (r *realFx) book() map[string]any {
	r.t.Helper()
	s, e := r.app.Control.IssueBook(context.Background(), r.writer, r.project)
	if e != nil {
		r.t.Fatal(e)
	}
	raw, _ := json.Marshal(s)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

// shape is the comparable outcome of a lifecycle script, free of per-run IDs.
type shape struct {
	Issues      []string
	Checkpoint  model.Uint64
	Commands    int
	Gaps        int
	Occurrences int
}

func shapeOf(st issues.State, group model.ID) shape {
	var s shape
	for _, rec := range st.Issues {
		i := rec.Issue
		reopened := 0
		for _, x := range rec.Explanations {
			if x.Reopened {
				reopened++
			}
		}
		s.Issues = append(s.Issues, fmt.Sprintf("fp=%x wf=%s rev=%d occ=%d late=%d expl=%d reopened=%d observed=%d frontier=%d fixed=%d res=%v", i.Fingerprint[0], i.Workflow, i.Revision, len(i.Occurrences), len(i.LateHistory), len(rec.Explanations), reopened, len(i.ObservedReleases), len(i.ResolutionFrontier), len(i.FixedDescendants), i.ResolutionTime != nil))
	}
	sort.Strings(s.Issues)
	s.Checkpoint, s.Commands, s.Gaps, s.Occurrences = st.Checkpoints[group], len(st.Commands), len(st.Gaps), len(st.Occurrences)
	return s
}

// script drives one lifecycle through the service: evidence, a fix frontier
// resolution, late history, a regression, ignore/unignore, an unfixed
// resolution, a gap and replays. It returns nothing: both stores must end alike.
func script(f *fx, issueFor func(byte) issues.Issue) {
	f.t.Helper()
	ctx := context.Background()
	f.apply(f.ev(1, f.A, 50), f.ev(2, f.A, 55))
	f.clock.at = 100
	first := issueFor(1)
	resolved, e := f.svc.Act(ctx, f.writer, issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: first.Revision, IssueID: first.ID, Kind: "resolve", Reason: "fixed in B", FixedDescendantFrontier: []model.ID{f.B}})
	if e != nil || resolved.Workflow != "resolved" {
		f.t.Fatalf("resolve: %v", e)
	}
	late := f.evAt(3, 1, f.A, 90)
	f.next = 3
	f.apply(late)
	f.apply(f.ev(1, f.A, 110), f.ev(1, f.D, 115))
	f.apply(f.ev(1, f.C, 120)) // a descendant of the fix: reopens
	second := issueFor(2)
	ignore := issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: second.Revision, IssueID: second.ID, Kind: "ignore", Reason: "noise"}
	ignored, e := f.svc.Act(ctx, f.writer, ignore)
	if e != nil || ignored.Workflow != "ignored" {
		f.t.Fatalf("ignore: %v", e)
	}
	if again, e := f.svc.Act(ctx, f.writer, ignore); e != nil || again.Revision != ignored.Revision {
		f.t.Fatalf("ignore retry: %v", e)
	}
	if _, e = f.svc.Act(ctx, f.writer, issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: second.Revision, IssueID: second.ID, Kind: "unignore", Reason: "stale"}); code(e) != model.Conflict {
		f.t.Fatalf("stale unignore: %v", e)
	}
	un, e := f.svc.Act(ctx, f.writer, issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: ignored.Revision, IssueID: second.ID, Kind: "unignore", Reason: "back"})
	if e != nil {
		f.t.Fatal(e)
	}
	if _, e = f.svc.Act(ctx, f.writer, issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: un.Revision, IssueID: second.ID, Kind: "resolve", Reason: "fixed without a frontier"}); e != nil {
		f.t.Fatal(e)
	}
	f.apply(f.ev(2, f.C, 130)) // descendant of the observed release: reopens
	gap := model.EvidenceGap{ID: model.NewID(), Org: f.org, Project: f.project, Group: f.group, After: model.Uint64(f.next), Through: model.Uint64(f.next + 9), Count: 9, Start: 200, End: 300, Reason: "journal expired before processing", RecordedAt: 100}
	if e = f.svc.RecordGap(ctx, f.writer, gap); e != nil {
		f.t.Fatal(e)
	}
	if e = f.svc.RecordGap(ctx, f.writer, gap); e != nil {
		f.t.Fatalf("gap retry: %v", e)
	}
	f.apply(late) // a replayed batch below the checkpoint changes nothing
}

// The durable adapter must give the service the same lifecycle the committed
// reference ledger does.
func TestControlStoreMatchesReferenceLedger(t *testing.T) {
	ref := newFx(t)
	script(ref, ref.issueFor)
	want := shapeOf(ref.projectState(), ref.group)
	real := newRealFx(t)
	script(real.fx, real.issueByFp)
	got := shapeOf(real.load(), real.group)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("durable ledger differs from the reference:\n got %+v\nwant %+v", got, want)
	}
	if got.Commands != 4 || got.Gaps != 1 || len(got.Issues) != 2 || got.Checkpoint < 9 {
		t.Fatalf("script did not reach the interesting states: %+v", got)
	}
	// And a restart changes nothing.
	before := real.load()
	real.restart()
	if after := real.load(); !reflect.DeepEqual(shapeOf(after, real.group), got) || !reflect.DeepEqual(before.Gaps, after.Gaps) || !reflect.DeepEqual(before.Checkpoints, after.Checkpoints) {
		t.Fatalf("restart changed the ledger")
	}
}

// The end-to-end lifecycle over the real store: dedup, late history, a
// regression decided against a release graph with a reconstructible
// explanation and one effect, a human action, a restart, replays.
func TestIssueServiceOverDurableControl(t *testing.T) {
	f := newRealFx(t)
	ctx := context.Background()
	first := f.ev(1, f.A, 50)
	f.apply(first)
	f.apply(first) // a retry of the same durable occurrence never counts twice
	issue := f.issueByFp(1)
	if s := issues.Summarize(issue); s.Count != 1 || issue.Revision != 1 || issue.Workflow != "open" {
		t.Fatalf("first occurrence: %+v %+v", issue, s)
	}
	f.clock.at = 100
	resolved, e := f.svc.Act(ctx, f.writer, issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: issue.Revision, IssueID: issue.ID, Kind: "resolve", Reason: "fixed in B", FixedDescendantFrontier: []model.ID{f.B}})
	if e != nil || resolved.Workflow != "resolved" || resolved.ResolutionTime == nil || *resolved.ResolutionTime != 100 || !reflect.DeepEqual(resolved.FixedDescendants, []model.ID{f.B}) || !reflect.DeepEqual(resolved.ResolutionFrontier, []model.ID{f.A}) {
		t.Fatalf("resolve: %v %+v", e, resolved)
	}
	// Late history: appended once, never reopens, receipt time kept.
	late := f.evAt(3, 1, f.A, 90)
	f.next = 3
	f.apply(late)
	f.apply(late)
	got := f.issueByFp(1)
	if s := issues.Summarize(got); got.Workflow != "resolved" || len(got.LateHistory) != 1 || len(got.Occurrences) != 1 || s.Count != 2 || s.Late != 1 || got.LateHistory[0].ArrivalTime != late.ArrivalTime {
		t.Fatalf("late history: %+v %+v", got, s)
	}
	// A post-boundary occurrence in a release without the fix: evaluated, not eligible.
	f.apply(f.ev(1, f.D, 115))
	if f.issueByFp(1).Workflow != "resolved" {
		t.Fatal("a release without the fix reopened the issue")
	}
	// A descendant of the fix reopens; the explanation is stored and reconstructible.
	descendant := f.ev(1, f.C, 120)
	f.apply(descendant)
	reopened := f.issueByFp(1)
	if reopened.Workflow != "open" || reopened.ResolutionTime != nil || len(reopened.FixedDescendants) != 0 {
		t.Fatalf("descendant did not reopen: %+v", reopened)
	}
	explained := f.explain(reopened)
	last := explained[len(explained)-1]
	if len(explained) != 2 || explained[0].Decision.Eligible || explained[0].EvidenceRelease != f.D || !last.Reopened || !last.Decision.Eligible || !last.Decision.AncestryKnown || last.OccurrenceID != descendant.OccurrenceID || last.ResolutionTime != 100 || last.Threshold != 1 || last.Qualifying != 1 || last.EvidenceRelease != f.C || !reflect.DeepEqual(last.Decision.Frontier, []model.ID{f.B}) || last.Decision.Reason == "" {
		t.Fatalf("explanations %+v", explained)
	}
	effects := f.book()["Effects"].([]any)
	if len(effects) != 1 || effects[0].(map[string]any)["kind"] != "issue_regressed" {
		t.Fatalf("regression effects %+v", effects)
	}
	// An unversioned occurrence: ancestry unknown, explained with no evidence release.
	f.clock.at = 200
	again, e := f.svc.Act(ctx, f.writer, issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: reopened.Revision, IssueID: reopened.ID, Kind: "resolve", Reason: "fixed again", ResolutionBoundary: 150})
	if e != nil {
		t.Fatal(e)
	}
	unversioned := f.ev(1, f.A, 160)
	unversioned.ReleaseID, unversioned.Ancestry = nil, "unknown"
	f.apply(unversioned)
	unknown := f.explain(f.issueByFp(1))
	lastUnknown := unknown[len(unknown)-1]
	if lastUnknown.Decision.AncestryKnown || !strings.Contains(lastUnknown.Decision.Reason, "ancestry unknown") || !lastUnknown.Reopened {
		t.Fatalf("unknown ancestry decision: %+v (resolved at %v)", lastUnknown, again.ResolutionTime)
	}
	// Restart: the whole ledger, explanations and command records are durable.
	before := f.load()
	f.restart()
	after := f.load()
	if !reflect.DeepEqual(shapeOf(before, f.group), shapeOf(after, f.group)) || before.Revision != after.Revision {
		t.Fatalf("restart changed the ledger:\n%+v\n%+v", shapeOf(before, f.group), shapeOf(after, f.group))
	}
	rec := after.Issues[f.issueByFp(1).ID]
	if len(rec.Explanations) != len(unknown) || rec.Explanations[len(rec.Explanations)-1].EvidenceRelease != (model.ID{}) {
		t.Fatalf("explanations after restart: %+v", rec.Explanations)
	}
	// A replay of everything already processed neither regresses nor notifies again.
	revision := f.load().Revision
	f.apply(first, late, descendant)
	if f.load().Revision != revision || len(f.book()["Effects"].([]any)) != 2 {
		t.Fatal("a replay after restart changed the ledger or minted an effect")
	}
	// A human action after the restart, with a stale version and a retried command.
	current := f.issueByFp(1)
	if _, e = f.svc.Act(ctx, f.writer, issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: current.Revision - 1, IssueID: current.ID, Kind: "ignore", Reason: "stale"}); code(e) != model.Conflict {
		t.Fatalf("stale version: %v", e)
	}
	ignore := issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: current.Revision, IssueID: current.ID, Kind: "ignore", Reason: "accepted risk"}
	ignored, e := f.svc.Act(ctx, f.writer, ignore)
	if e != nil || ignored.Workflow != "ignored" {
		t.Fatalf("ignore: %v", e)
	}
	f.restart()
	retry, e := f.svc.Act(ctx, f.writer, ignore)
	if e != nil || retry.Revision != ignored.Revision || retry.Workflow != "ignored" {
		t.Fatalf("command retry after a restart: %v %+v", e, retry)
	}
	reused := ignore
	reused.Reason = "something else"
	if _, e = f.svc.Act(ctx, f.writer, reused); code(e) != model.Conflict {
		t.Fatalf("command ID reused for another action: %v", e)
	}
}

func TestControlStoreRevisionConflictCarriesCurrentRevision(t *testing.T) {
	f := newRealFx(t)
	f.apply(f.ev(1, f.A, 50))
	f.apply(f.ev(1, f.A, 51))
	st := f.load()
	if st.Revision != 2 {
		t.Fatalf("revision %d", st.Revision)
	}
	e := f.real.Commit(context.Background(), f.writer, f.project, issues.Commit{ExpectedRevision: 1, Checkpoint: &issues.Checkpoint{Group: f.group, Index: 9}})
	cur, ok := issues.ConflictRevision(e)
	if code(e) != model.Conflict || !ok || cur != 2 {
		t.Fatalf("stale commit: %v (current %d %v)", e, cur, ok)
	}
	if _, ok = issues.ConflictRevision(model.Fail(model.Conflict)); ok {
		t.Fatal("a plain conflict carried a revision")
	}
	if f.load().Checkpoints[f.group] != 2 {
		t.Fatal("a conflicting commit moved the checkpoint")
	}
}

func TestControlStoreCommitIsExactlyOnceUnderReorderedRetries(t *testing.T) {
	f := newRealFx(t)
	ctx := context.Background()
	f.apply(f.ev(1, f.A, 50))
	issue := f.issueByFp(1)
	command := model.NewID()
	audit := model.ControlAudit{ID: command, Principal: f.writer.PrincipalID(), Action: "issues.ignore", Reason: "noise", Time: 100, Org: f.org.String(), PolicyEpoch: f.writer.PolicyEpoch(), Targets: []model.ID{issue.ID}, RequestID: command, Outcome: model.AuditAllowed}
	next := issue
	next.Workflow, next.Revision = "ignored", issue.Revision+1
	fingerprint := [32]byte{4}
	act := issues.Commit{CommandID: command, ExpectedRevision: f.load().Revision, Records: []issues.Record{{Issue: next}}, Audits: []model.ControlAudit{audit}, Command: &issues.CommandRecord{Fingerprint: fingerprint, IssueID: issue.ID}}
	if e := f.real.Commit(ctx, f.writer, f.project, act); e != nil {
		t.Fatal(e)
	}
	f.apply(f.ev(1, f.A, 60))
	f.apply(f.ev(1, f.A, 61))
	before := f.load()
	audits := countAudits(t, f, "issues.ignore")
	for range 3 {
		// The original commit arrives again, late: it is the same command.
		if e := f.real.Commit(ctx, f.writer, f.project, act); e != nil {
			t.Fatalf("retry of a committed command: %v", e)
		}
	}
	if after := f.load(); !reflect.DeepEqual(shapeOf(before, f.group), shapeOf(after, f.group)) || after.Revision != before.Revision || countAudits(t, f, "issues.ignore") != audits {
		t.Fatal("a retried command changed the ledger or audited twice")
	}
	if rec := before.Commands[command]; rec.IssueID != issue.ID || rec.Fingerprint != fingerprint {
		t.Fatalf("command record %+v", rec)
	}
	// The same ID with other content is a conflict, not the first result.
	other := act
	other.Records = []issues.Record{{Issue: func() issues.Issue { i := next; i.Workflow = "open"; return i }()}}
	if e := f.real.Commit(ctx, f.writer, f.project, other); code(e) != model.Conflict {
		t.Fatalf("command ID reused with other content: %v", e)
	}
	// An evidence commit (no command ID) retried after the state moved is not applied twice.
	ev := f.evAt(9, 1, f.A, 70)
	rec := before.Issues[issue.ID]
	grown := rec
	grown.Issue.Occurrences = append(append([]issues.Evidence(nil), rec.Issue.Occurrences...), ev)
	grown.Issue.Revision = rec.Issue.Revision + 1
	evidence := issues.Commit{ExpectedRevision: f.load().Revision, Records: []issues.Record{grown}, Occurrences: map[model.ID]model.ID{ev.OccurrenceID: issue.ID}, Checkpoint: &issues.Checkpoint{Group: f.group, Index: 9}}
	if e := f.real.Commit(ctx, f.writer, f.project, evidence); e != nil {
		t.Fatal(e)
	}
	f.apply(f.evAt(10, 1, f.A, 71))
	mid := f.load()
	if e := f.real.Commit(ctx, f.writer, f.project, evidence); e != nil {
		t.Fatalf("retried evidence commit: %v", e)
	}
	if f.load().Revision != mid.Revision {
		t.Fatal("a retried evidence commit changed the ledger")
	}
}

func countAudits(t *testing.T, f *realFx, action string) int {
	t.Helper()
	n := 0
	if e := f.app.Control.View(context.Background(), func(st model.ControlState) error {
		for _, a := range st.Audits {
			if a.Action == action {
				n++
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	return n
}

// A commit is atomic: evidence whose checkpoint cannot advance is not stored.
func TestControlStoreCommitIsAtomic(t *testing.T) {
	f := newRealFx(t)
	f.apply(f.ev(1, f.A, 50), f.ev(1, f.A, 51))
	st := f.load()
	issue := st.Issues[f.issueByFp(1).ID]
	ev := f.evAt(7, 1, f.A, 80)
	grown := issue
	grown.Issue.Occurrences = append(append([]issues.Evidence(nil), issue.Issue.Occurrences...), ev)
	grown.Issue.Revision++
	// The checkpoint (2) cannot go back to 1: the whole commit is refused.
	e := f.real.Commit(context.Background(), f.writer, f.project, issues.Commit{ExpectedRevision: st.Revision, Records: []issues.Record{grown}, Occurrences: map[model.ID]model.ID{ev.OccurrenceID: issue.Issue.ID}, Checkpoint: &issues.Checkpoint{Group: f.group, Index: 1}})
	if code(e) != model.Conflict {
		t.Fatalf("regressing checkpoint: %v", e)
	}
	after := f.load()
	if after.Revision != st.Revision || len(after.Issues[issue.Issue.ID].Issue.Occurrences) != 2 || len(after.Occurrences) != 2 {
		t.Fatalf("a refused commit left partial state: %+v", after)
	}
	// Malformed commits: an occurrence index entry its issue does not hold.
	bad := issues.Commit{ExpectedRevision: st.Revision, Records: []issues.Record{issue}, Occurrences: map[model.ID]model.ID{model.NewID(): issue.Issue.ID}}
	if e = f.real.Commit(context.Background(), f.writer, f.project, bad); code(e) != model.Invalid {
		t.Fatalf("an occurrence the issue does not hold: %v", e)
	}
	if e = f.real.Commit(context.Background(), f.writer, f.project, issues.Commit{ExpectedRevision: st.Revision}); code(e) != model.Invalid {
		t.Fatalf("an empty commit: %v", e)
	}
	if f.load().Revision != st.Revision {
		t.Fatal("a rejected commit moved the revision")
	}
}

// 24 workers, one data group each, apply evidence for three shared issues at the
// same time; every occurrence lands exactly once, whichever commit wins.
func TestControlStoreConcurrentWorkers(t *testing.T) {
	f := newRealFx(t)
	const workers, batches = 24, 3
	var wg sync.WaitGroup
	groups := make([]model.ID, workers)
	for i := range groups {
		groups[i] = model.ID{0xe5, byte(i + 1)}
	}
	var mu sync.Mutex
	occ := map[model.ID]bool{}
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for b := 1; b <= batches; b++ {
				rel := f.A
				e := issues.Evidence{OccurrenceID: model.ID{0xd9, byte(w), byte(b)}, RecordID: model.ID{0xda, byte(w), byte(b)}, Origin: model.Cursor{Group: groups[w], Index: model.Uint64(b)}, GroupingVersion: 1,
					Fingerprint: model.Hash{byte(w%3 + 1)}, EventTime: model.UnixNano(1000 + w*10 + b), ArrivalTime: model.UnixNano(2000 + w*10 + b), ReleaseID: &rel, Ancestry: "known", Freshness: "fresh", Ordinal: model.Uint64(b)}
				mu.Lock()
				occ[e.OccurrenceID] = true
				mu.Unlock()
				done := false
				for range 400 {
					switch err := f.svc.ApplyThrough(context.Background(), f.writer, e.Origin, []issues.Evidence{e}); {
					case err == nil:
						done = true
					case code(err) == model.Conflict:
					default:
						t.Error(err)
						return
					}
					if done {
						break
					}
				}
				if !done {
					t.Errorf("worker %d never applied batch %d", w, b)
					return
				}
			}
		}()
	}
	wg.Wait()
	st := f.load()
	total := 0
	for _, rec := range st.Issues {
		total += len(rec.Issue.Occurrences)
	}
	if len(st.Issues) != 3 || total != workers*batches || len(st.Occurrences) != len(occ) {
		t.Fatalf("%d issues, %d occurrences stored, %d indexed, %d expected", len(st.Issues), total, len(st.Occurrences), len(occ))
	}
	for _, g := range groups {
		if st.Checkpoints[g] != batches {
			t.Fatalf("checkpoint of %s is %d", g, st.Checkpoints[g])
		}
	}
	// Each occurrence is one commit that bumped its issue's revision exactly once.
	for _, rec := range st.Issues {
		if int(rec.Issue.Revision) != len(rec.Issue.Occurrences) {
			t.Fatalf("issue revision %d for %d occurrences", rec.Issue.Revision, len(rec.Issue.Occurrences))
		}
	}
}

func TestControlStoreGapsAndHealthSurviveRestart(t *testing.T) {
	f := newRealFx(t)
	ctx := context.Background()
	f.apply(f.ev(1, f.A, 50), f.ev(1, f.A, 51))
	gap := model.EvidenceGap{ID: model.NewID(), Org: f.org, Project: f.project, Group: f.group, After: 2, Through: 9, Count: 7, Start: 60, End: 90, Reason: "journal expired before processing", RecordedAt: 100}
	skipped := gap
	skipped.After = 4
	if e := f.svc.RecordGap(ctx, f.writer, skipped); code(e) != model.Conflict {
		t.Fatalf("gap that skips unprocessed evidence: %v", e)
	}
	if h, e := f.svc.Health(ctx, f.writer, f.project); e != nil || !h.Complete || f.load().Checkpoints[f.group] != 2 {
		t.Fatalf("a refused gap changed health or the checkpoint: %v %+v", e, h)
	}
	if e := f.svc.RecordGap(ctx, f.writer, gap); e != nil {
		t.Fatal(e)
	}
	f.restart()
	h, e := f.svc.Health(ctx, f.writer, f.project)
	if e != nil || h.Complete || len(h.Gaps) != 1 || !reflect.DeepEqual(h.Gaps[0], gap) || f.load().Checkpoints[f.group] != 9 {
		t.Fatalf("gap after restart: %v %+v", e, h)
	}
	if e = f.svc.RecordGap(ctx, f.writer, gap); e != nil {
		t.Fatalf("gap retry after restart: %v", e)
	}
	// Processing resumes after the gap; the gapped interval is not resurrected.
	f.next = 9
	f.apply(f.ev(1, f.A, 120))
	if issues.Summarize(f.issueByFp(1)).Count != 3 {
		t.Fatal("processing did not resume after the gap")
	}
}

func TestControlStoreScopes(t *testing.T) {
	f := newRealFx(t)
	ctx := context.Background()
	f.apply(f.ev(1, f.A, 50))
	issue := f.issueByFp(1)
	// A read-only scope reads through the service but cannot write.
	if got, e := f.svc.Get(ctx, f.reader, f.project, issue.ID); e != nil || got.ID != issue.ID {
		t.Fatalf("read scope get: %v", e)
	}
	if e := f.real.Commit(ctx, f.reader, f.project, issues.Commit{ExpectedRevision: 1, Checkpoint: &issues.Checkpoint{Group: f.group, Index: 5}}); code(e) != model.Forbidden {
		t.Fatalf("read scope committed: %v", e)
	}
	// Another organization's scope neither reads nor writes this project, and the
	// answer for a foreign project equals the answer for a missing one.
	_, errForeign := f.real.Load(ctx, f.otherWriter, f.project)
	_, errMissing := f.real.Load(ctx, f.otherWriter, model.NewID())
	if code(errForeign) != model.NotFound || code(errMissing) != model.NotFound || errForeign.Error() != errMissing.Error() {
		t.Fatalf("foreign %v vs missing %v", errForeign, errMissing)
	}
	if e := f.real.Commit(ctx, f.otherWriter, f.project, issues.Commit{ExpectedRevision: 1, Checkpoint: &issues.Checkpoint{Group: f.group, Index: 5}}); code(e) != model.NotFound {
		t.Fatalf("foreign scope committed: %v", e)
	}
	if f.load().Checkpoints[f.group] != 1 {
		t.Fatal("a refused commit moved the checkpoint")
	}
	if _, e := issues.NewControlStore(nil); code(e) != model.Invalid {
		t.Fatalf("nil control: %v", e)
	}
}

// What the store keeps for an issue is IDs, hashes, counts, cursors and
// versions: no occurrence body, message or stack text exists to store.
func TestControlStoreKeepsNoTelemetryText(t *testing.T) {
	f := newRealFx(t)
	e := f.ev(1, f.A, 50)
	e.Denominator = &model.GroupingDenominator{Name: "http_requests_total", Start: 1, End: 2, Count: 100, Complete: true, Cursors: []model.Cursor{{Group: f.group, Index: 1}}}
	f.apply(e)
	var raw []byte
	if err := f.app.Control.View(context.Background(), func(st model.ControlState) error {
		raw, _ = json.Marshal(struct {
			Books  map[string]json.RawMessage
			Issues map[string]model.GroupingIssue
		}{st.IssueBooks, st.GroupingIssues})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"message", "stack", "body", "title", "attributes", "text"} {
		if strings.Contains(strings.ToLower(string(raw)), `"`+forbidden+`"`) {
			t.Fatalf("stored state has a %q field", forbidden)
		}
	}
	if !strings.Contains(string(raw), "http_requests_total") {
		t.Fatal("the named denominator was not kept")
	}
}

// Two issues holding one occurrence is corruption, never silently indexed.
func TestControlStoreLoadRefusesDuplicateOccurrence(t *testing.T) {
	f := newRealFx(t)
	f.apply(f.ev(1, f.A, 50), f.ev(2, f.A, 51))
	st := f.load()
	var one, two issues.Issue
	for _, r := range st.Issues {
		if r.Issue.Fingerprint == (model.Hash{1}) {
			one = r.Issue
		} else {
			two = r.Issue
		}
	}
	two.Occurrences = append(two.Occurrences, one.Occurrences[0])
	if err := f.app.Control.Update(context.Background(), func(cs *model.ControlState) error {
		cs.GroupingIssues[model.ReleaseScopeKey(f.org, f.project, two.ID)] = two
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, e := f.real.Load(context.Background(), f.writer, f.project); code(e) != model.Corrupt {
		t.Fatalf("duplicate occurrence across issues: %v", e)
	}
}

func TestControlStoreCommandRecordNeedsItsID(t *testing.T) {
	f := newRealFx(t)
	f.apply(f.ev(1, f.A, 50))
	issue := f.issueByFp(1)
	next := issue
	next.Workflow, next.Revision = "ignored", issue.Revision+1
	e := f.real.Commit(context.Background(), f.writer, f.project, issues.Commit{ExpectedRevision: f.load().Revision, Records: []issues.Record{{Issue: next}}, Command: &issues.CommandRecord{IssueID: issue.ID}})
	if code(e) != model.Invalid {
		t.Fatalf("a command record without a command ID: %v", e)
	}
}

// Explanations are stored as closed facts: a reason that is long or holds control
// characters is refused whole, never truncated into the ledger.
func TestControlStoreRefusesUnsafeExplanations(t *testing.T) {
	f := newRealFx(t)
	f.apply(f.ev(1, f.A, 50))
	issue := f.issueByFp(1)
	next := issue
	next.Revision++
	for name, reason := range map[string]string{"long": strings.Repeat("r", 257), "control": "bad\x00reason", "not utf8": "bad\xffreason"} {
		x := issues.Explanation{OccurrenceID: issue.Occurrences[0].OccurrenceID, EventTime: 50, Decision: issues.RegressionDecision{Reason: reason}}
		e := f.real.Commit(context.Background(), f.writer, f.project, issues.Commit{ExpectedRevision: f.load().Revision, Records: []issues.Record{{Issue: next, Explanations: []issues.Explanation{x}}}})
		if code(e) != model.Invalid {
			t.Errorf("%s reason: %v", name, e)
		}
	}
	x := issues.Explanation{OccurrenceID: issue.Occurrences[0].OccurrenceID, EventTime: 50, Decision: issues.RegressionDecision{Reason: strings.Repeat("r", 256)}}
	if e := f.real.Commit(context.Background(), f.writer, f.project, issues.Commit{ExpectedRevision: f.load().Revision, Records: []issues.Record{{Issue: next, Explanations: []issues.Explanation{x}}}}); e != nil {
		t.Fatalf("a reason at the bound: %v", e)
	}
}
