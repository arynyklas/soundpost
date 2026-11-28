// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package issues_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// Occurrence-ledger compaction (06.02-W3): a hot fingerprint keeps committing
// past the per-issue window; its count, bounds and observed releases stay exact.

// hot builds n evidence of one fingerprint at consecutive durable cursors with
// scattered (non-monotone) event and arrival times, so bounds are not an accident
// of ordering.
func (f *fx) hot(fp byte, release model.ID, n int) []issues.Evidence {
	out := make([]issues.Evidence, n)
	for i := range out {
		e := f.ev(fp, release, model.UnixNano(10_000+int64(i*7919%5003)))
		e.ArrivalTime = model.UnixNano(500_000 + int64(i*104729%7001))
		out[i] = e
	}
	return out
}

func (f *fx) applyBatches(es []issues.Evidence, size int) {
	f.t.Helper()
	for i := 0; i < len(es); i += size {
		f.apply(es[i:min(i+size, len(es))]...)
	}
}

// exact is the brute-force summary of every evidence ever applied.
func exact(es []issues.Evidence) issues.Summary {
	s := issues.Summary{Count: len(es), FirstSeen: es[0].EventTime, LastSeen: es[0].EventTime, FirstArrival: es[0].ArrivalTime, LastArrival: es[0].ArrivalTime}
	for _, e := range es {
		s.FirstSeen, s.LastSeen = min(s.FirstSeen, e.EventTime), max(s.LastSeen, e.EventTime)
		s.FirstArrival, s.LastArrival = min(s.FirstArrival, e.ArrivalTime), max(s.LastArrival, e.ArrivalTime)
	}
	return s
}

func (f *fx) withLedger(w issues.LedgerWindow) {
	f.t.Helper()
	svc, e := issues.New(issues.Deps{Store: f.store, Authorizer: f.app.Auth, Graphs: f.graphs, Fence: f.fence, Policy: f.policy, Migrator: f.migrator, Clock: f.clock, Regression: issues.RegressionPolicy{MinOccurrences: 1}, Ledger: w})
	if e != nil {
		f.t.Fatal(e)
	}
	f.svc = svc
}

// A: 5000 occurrences of one fingerprint over many batches against the REAL
// control store: nothing is refused, the checkpoint advances with every batch,
// the summary is exact, and the stored issue stays small (F).
func TestHotFingerprintKeepsCommittingAcrossCompaction(t *testing.T) {
	// The control journal is cut by its own cadence (decision D4: 4096 commands or 64 MiB). Each of this
	// test's folding commits carries the whole issue, so the default cadence leaves tens of MiB of journal
	// that the restart below replays inside appcore's fixed 20 s startup budget; under -race that replay
	// alone takes about 23 s and Open fails with replica.ErrStale. A tighter byte cadence, the same
	// mechanism, makes the restart load a snapshot plus a short tail, which is what a long-lived node does.
	prev := control.DefaultJournalCadence
	control.DefaultJournalCadence = replica.Cadence{Commands: prev.Commands, Bytes: 4 << 20}
	t.Cleanup(func() { control.DefaultJournalCadence = prev })
	f := newRealFx(t)
	const total = 5000
	all := f.hot(1, f.A, total)
	f.applyBatches(all, 100)

	st := f.load()
	issue := f.issueByFp(1)
	if got, want := issues.Summarize(issue), exact(all); got != want {
		t.Fatalf("summary after compaction:\n got %+v\nwant %+v", got, want)
	}
	if st.Checkpoints[f.group] != total {
		t.Fatalf("checkpoint %d, want %d: a hot fingerprint stalled the data group", st.Checkpoints[f.group], total)
	}
	window := len(issue.Occurrences) + len(issue.LateHistory)
	if issue.Compacted == nil || window < model.GroupingWindowKeep || window > model.GroupingWindowMax || int(issue.Compacted.Count)+window != total {
		t.Fatalf("window %d, aggregate %+v", window, issue.Compacted)
	}
	if len(issue.Compacted.Recent) != model.GroupingDedupTail || len(issue.Compacted.Releases) != 1 || issue.LateCompacted != nil {
		t.Fatalf("aggregate shape: %d tail, %d releases, late %v", len(issue.Compacted.Recent), len(issue.Compacted.Releases), issue.LateCompacted)
	}
	if !reflect.DeepEqual(issue.ObservedReleases, []model.ID{f.A}) {
		t.Fatalf("observed releases %v", issue.ObservedReleases)
	}
	// The project index covers the window and the dedup tail, nothing else.
	if len(st.Occurrences) != window+model.GroupingDedupTail {
		t.Fatalf("index holds %d IDs, want %d", len(st.Occurrences), window+model.GroupingDedupTail)
	}
	// F: the stored issue is bounded by the window, not by the history. Measured
	// against the real JSON the control state holds.
	raw, e := json.Marshal(issue)
	if e != nil {
		t.Fatal(e)
	}
	const bound = 512 << 10 // at most 1024 evidence of about 400 B and a 512-ID tail, with room
	if len(raw) > bound {
		t.Fatalf("stored issue is %d bytes after %d occurrences, bound %d", len(raw), total, bound)
	}
	t.Logf("issue JSON after %d occurrences: %d bytes (window %d, aggregate count %d)", total, len(raw), window, issue.Compacted.Count)

	f.restart()
	if got := issues.Summarize(f.issueByFp(1)); got != exact(all) {
		t.Fatalf("restart changed the summary: %+v", got)
	}
}

// One batch may need more room than a commit can free. It is applied in several
// commits; each moves the checkpoint to just below the first evidence it did not
// apply and the last one to the batch cursor. A crash after the second commit
// (its acknowledgement lost, or its checkpoint never written) replays the batch:
// evidence already folded or still in the window is not counted again, and what
// the checkpoint already covers is skipped.
func TestOversizedBatchIsAppliedInCommitsAndSurvivesAReplay(t *testing.T) {
	boom := errors.New("acknowledgement lost")
	for name, c := range map[string]struct {
		crash      func(*fakeStore)
		checkpoint model.Uint64
	}{
		"acknowledgement lost":   {func(s *fakeStore) { s.failAfter = boom }, 2048},
		"checkpoint not written": {func(s *fakeStore) { s.tear = true }, 1024},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFx(t)
			all := f.hot(1, f.A, 3000)
			last := all[len(all)-1].Origin
			f.store.beforeCommit = func() { f.store.beforeCommit = func() { c.crash(f.store) } }
			if e := f.svc.ApplyThrough(context.Background(), f.writer, last, all); e == nil {
				t.Fatal("the injected crash did not surface")
			}
			f.store.failAfter, f.store.tear = nil, false
			part := f.issueFor(1)
			if s := issues.Summarize(part); s.Count != 2048 || part.Compacted == nil || f.projectState().Checkpoints[f.group] != c.checkpoint {
				t.Fatalf("after the crash: %d counted, aggregate %v, checkpoint %d (want %d)", s.Count, part.Compacted, f.projectState().Checkpoints[f.group], c.checkpoint)
			}
			f.store.commits = nil
			if e := f.svc.ApplyThrough(context.Background(), f.writer, last, all); e != nil {
				t.Fatal(e)
			}
			if got, want := issues.Summarize(f.issueFor(1)), exact(all); got != want {
				t.Fatalf("replay after the crash:\n got %+v\nwant %+v", got, want)
			}
			if f.projectState().Checkpoints[f.group] != last.Index {
				t.Fatal("checkpoint did not reach the batch cursor")
			}
			if len(f.store.commits) < 1 {
				t.Fatalf("%d commits after the crash", len(f.store.commits))
			}
			through := c.checkpoint
			for i, commit := range f.store.commits {
				if commit.Checkpoint == nil || commit.Checkpoint.Index <= through || (commit.Checkpoint.Index == last.Index) != (i == len(f.store.commits)-1) {
					t.Fatalf("commit %d of %d: checkpoint %v after %d", i+1, len(f.store.commits), commit.Checkpoint, through)
				}
				through = commit.Checkpoint.Index
			}
		})
	}
}

// The same oversized batch over the real store, where control verifies every
// fold: the commits are accepted and the issue is exact.
func TestOversizedBatchOverDurableControl(t *testing.T) {
	f := newRealFx(t)
	all := f.hot(1, f.A, 2600)
	f.apply(all...)
	issue := f.issueByFp(1)
	if got, want := issues.Summarize(issue), exact(all); got != want || f.load().Checkpoints[f.group] != 2600 {
		t.Fatalf("summary %+v, want %+v", got, want)
	}
	if issue.Revision < 3 || issue.Compacted == nil {
		t.Fatalf("revision %d, aggregate %+v: expected several folding commits", issue.Revision, issue.Compacted)
	}
}

// B: an occurrence ID the issue already counts is not counted again. In the
// window it must be the same durable occurrence (a different origin is a
// Conflict, as before compaction); in the dedup tail there is no identity left to
// compare, so a hit is a duplicate. Either way the checkpoint does not stall.
func TestRedeliveryAfterCompactionIsNotDoubleCounted(t *testing.T) {
	f := newRealFx(t)
	all := f.hot(1, f.A, 3000)
	f.applyBatches(all, 150)
	issue := f.issueByFp(1)
	inWindow := issue.Occurrences[len(issue.Occurrences)-1]
	var tail issues.Evidence
	for _, e := range all {
		if e.OccurrenceID == issue.Compacted.Recent[len(issue.Compacted.Recent)-1] {
			tail = e
		}
	}
	if tail.OccurrenceID == (model.ID{}) {
		t.Fatal("fixture: tail evidence not found")
	}
	redeliver := func(e issues.Evidence, mutate func(*issues.Evidence)) error {
		f.next++
		e.Origin.Index = model.Uint64(f.next)
		if mutate != nil {
			mutate(&e)
		}
		return f.svc.ApplyThrough(context.Background(), f.writer, e.Origin, []issues.Evidence{e})
	}
	if err := redeliver(tail, nil); err != nil {
		t.Fatalf("tail redelivery: %v", err)
	}
	if got := issues.Summarize(f.issueByFp(1)).Count; got != 3000 {
		t.Fatalf("a tail redelivery changed the count to %d", got)
	}
	if cp := f.load().Checkpoints[f.group]; cp != model.Uint64(f.next) {
		t.Fatalf("checkpoint %d, want %d: a duplicate must still move it", cp, f.next)
	}
	// The same occurrence ID with another identity inside the window is corruption.
	cp := f.load().Checkpoints[f.group]
	if err := redeliver(inWindow, nil); code(err) != model.Conflict {
		t.Fatalf("identity conflict in the window: %v", err)
	}
	if f.load().Checkpoints[f.group] != cp {
		t.Fatal("a refused batch moved the checkpoint")
	}
	// A folded occurrence has no identity left to compare: a tail hit is a duplicate.
	if err := redeliver(tail, func(e *issues.Evidence) { e.RecordID = model.NewID() }); err != nil {
		t.Fatalf("tail hit with another identity: %v", err)
	}
	if got := issues.Summarize(f.issueByFp(1)).Count; got != 3000 {
		t.Fatalf("count %d", got)
	}
}

// The residual of compaction, pinned: an occurrence redelivered after its ID has
// left both the window and the dedup tail is counted again. The horizon is the
// window plus the tail, the same order as the 1024 evidence an issue held before.
func TestRedeliveryBeyondTheDedupHorizonIsCountedAgain(t *testing.T) {
	f := newRealFx(t)
	all := f.hot(1, f.A, 3000)
	f.applyBatches(all, 150)
	old := all[0]
	f.next++
	old.Origin.Index = model.Uint64(f.next)
	f.apply(old)
	if got := issues.Summarize(f.issueByFp(1)).Count; got != 3001 {
		t.Fatalf("count %d: the dedup horizon is the window plus the tail", got)
	}
}

// twinOut is the outcome of one lifecycle: early evidence in a release that only
// the folded part names, a fix-frontier resolution, late history, post-boundary
// evidence that does not and then does regress, and a second resolution.
type twinOut struct {
	Summary              issues.Summary
	Frontier1, Frontier2 []model.ID
	Observed             []model.ID
	Workflow             string
	Explanations         []issues.Explanation
	Effects, Checkpoint  int
}

func twinScript(f *fx) (twinOut, issues.Issue) {
	f.t.Helper()
	f.next = 0
	f.clock.at = 100
	var batch []issues.Evidence
	for i := range 5 {
		batch = append(batch, f.ev(1, f.D, model.UnixNano(10+i)))
	}
	f.apply(batch...)
	for i := range 5 {
		var more []issues.Evidence
		for j := range 5 {
			more = append(more, f.ev(1, f.A, model.UnixNano(20+5*i+j)))
		}
		f.apply(more...)
	}
	resolved := f.resolve(1, f.B)
	out := twinOut{Frontier1: resolved.ResolutionFrontier}
	var late []issues.Evidence
	for i := range 5 {
		late = append(late, f.evAt(uint64(f.next)+1+uint64(i), 1, f.C, model.UnixNano(50+i)))
	}
	f.next += 5
	f.apply(late...)
	for i := range 3 {
		f.apply(f.ev(1, f.A, model.UnixNano(200+2*i)), f.ev(1, f.A, model.UnixNano(201+2*i))) // releases without the fix: no regression
	}
	f.apply(f.ev(1, f.C, 300)) // a descendant of the fix: reopens
	f.clock.at = 400
	again, e := f.act("resolve", f.issueFor(1), nil)
	if e != nil {
		f.t.Fatal(e)
	}
	out.Frontier2 = again.ResolutionFrontier
	final := f.issueFor(1)
	out.Summary, out.Observed, out.Workflow = issues.Summarize(final), final.ObservedReleases, final.Workflow
	out.Explanations = f.explain(final)
	out.Effects, out.Checkpoint = f.store.regressEffects(), int(f.projectState().Checkpoints[f.group])
	return out, final
}

// C: the regression, resolution frontier and counts after compaction are those of
// a twin that never compacted (a window too large to fill).
func TestCompactionDoesNotChangeResolutionOrRegression(t *testing.T) {
	f := newFx(t)
	twin, twinIssue := twinScript(f)
	f.store = newFakeStore()
	f.withLedger(issues.LedgerWindow{Trigger: 16, Keep: 8})
	compacted, compactedIssue := twinScript(f)

	if twinIssue.Compacted != nil || twinIssue.LateCompacted != nil || compactedIssue.Compacted == nil {
		t.Fatalf("fixture: twin %+v, small window %+v", twinIssue.Compacted, compactedIssue.Compacted)
	}
	if got, was := len(compactedIssue.Occurrences)+len(compactedIssue.LateHistory), len(twinIssue.Occurrences)+len(twinIssue.LateHistory); got >= was {
		t.Fatalf("window did not shrink: %d against %d", got, was)
	}
	if !reflect.DeepEqual(twin.Frontier1, []model.ID{f.D, f.A}) || twin.Workflow != "resolved" || twin.Effects != 1 || len(twin.Explanations) != 7 {
		t.Fatalf("fixture: twin %+v", twin)
	}
	if !reflect.DeepEqual(compacted, twin) {
		t.Fatalf("compaction changed the lifecycle:\n twin %+v\n got  %+v", twin, compacted)
	}
	// The release only the folded evidence named is still in the second frontier.
	if !reflect.DeepEqual(compacted.Frontier2, []model.ID{f.D, f.A, f.C}) {
		t.Fatalf("second frontier %v", compacted.Frontier2)
	}
}

// Post-boundary evidence of a resolved issue folds like any other when the window
// is full, oldest first (the pre-boundary evidence first, because it is the oldest);
// the summary and the releases observed at or before the boundary stay exact, and
// the hot issue keeps committing (R01-3).
func TestResolvedIssueFoldsPostBoundaryEvidenceToMakeRoom(t *testing.T) {
	f := newFx(t)
	f.withLedger(issues.LedgerWindow{Trigger: 8, Keep: 4})
	f.apply(f.ev(1, f.A, 10), f.ev(1, f.A, 11), f.ev(1, f.A, 12))
	f.resolve(1, f.B) // boundary 100; the fix is B, which releases A and D do not contain
	for i := range 5 {
		f.apply(f.ev(1, f.A, model.UnixNano(200+i)))
	}
	if got := f.issueFor(1); len(got.Occurrences) != 8 || got.Compacted != nil || got.Workflow != "resolved" {
		t.Fatalf("fixture: %+v", got)
	}
	// Room is made by folding the four oldest: the three pre-boundary evidence and the first after it.
	f.apply(f.ev(1, f.A, 205))
	got := f.issueFor(1)
	if got.Compacted == nil || got.Compacted.Count != 4 || got.Compacted.LastEvent != 200 || len(got.Occurrences) != 5 {
		t.Fatalf("the oldest four were not the part folded: %+v", got)
	}
	for i := 206; i < 240; i++ {
		f.apply(f.ev(1, f.A, model.UnixNano(i)))
	}
	cp := f.projectState().Checkpoints[f.group]
	after := f.issueFor(1)
	if cp != model.Uint64(f.next) || len(after.Occurrences) > 8 || after.Workflow != "resolved" {
		t.Fatalf("checkpoint %d (want %d), %d in the window, workflow %s", cp, f.next, len(after.Occurrences), after.Workflow)
	}
	if s := issues.Summarize(after); s.Count != 43 || s.FirstSeen != 10 || s.LastSeen != 239 {
		t.Fatalf("summary %+v", s)
	}
	// A resolution after a later reopen still sees the release the folded evidence named.
	if observed := after.ObservedReleases; len(observed) != 1 || observed[0] != f.A {
		t.Fatalf("observed releases %v", observed)
	}
}

// C over the real store with the real window: 1500 pre-boundary occurrences, a
// release that only the first three name, a fix-frontier resolution and a regression.
func TestResolutionAndRegressionAfterRealCompaction(t *testing.T) {
	f := newRealFx(t)
	f.clock.at = 100_000
	var all []issues.Evidence
	for i := range 1500 {
		release := f.A
		if i < 3 {
			release = f.D
		}
		all = append(all, f.ev(1, release, model.UnixNano(10+i)))
	}
	f.applyBatches(all, 100)
	issue := f.issueByFp(1)
	if issue.Compacted == nil || issue.Compacted.Count < 400 {
		t.Fatalf("fixture: no compaction: %+v", issue.Compacted)
	}
	resolved, e := f.svc.Act(context.Background(), f.writer, issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: issue.Revision, IssueID: issue.ID, Kind: "resolve", Reason: "fixed in B", FixedDescendantFrontier: []model.ID{f.B}})
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(resolved.ResolutionFrontier, []model.ID{f.D, f.A}) || resolved.ResolutionTime == nil || *resolved.ResolutionTime != 100_000 {
		t.Fatalf("resolution frontier %v: the folded evidence's release was lost", resolved.ResolutionFrontier)
	}
	f.apply(f.ev(1, f.A, 200_000)) // after the boundary, a release without the fix
	if got := f.issueByFp(1); got.Workflow != "resolved" {
		t.Fatalf("reopened by a release without the fix: %s", got.Workflow)
	}
	f.apply(f.ev(1, f.C, 300_000)) // a descendant of the fix
	reopened := f.issueByFp(1)
	if reopened.Workflow != "open" || issues.Summarize(reopened).Count != 1502 {
		t.Fatalf("workflow %s, count %d", reopened.Workflow, issues.Summarize(reopened).Count)
	}
	explained := f.explain(reopened)
	if len(explained) != 2 || explained[0].Decision.Eligible || !explained[1].Reopened || explained[1].EvidenceRelease != f.C || !reflect.DeepEqual(explained[1].Decision.Frontier, []model.ID{f.B}) {
		t.Fatalf("explanations %+v", explained)
	}
	snap, e := f.app.Control.IssueBook(context.Background(), f.writer, f.project)
	if e != nil || len(snap.Effects) != 1 || snap.Effects[0].Kind != "issue_regressed" {
		t.Fatalf("effects %+v %v", snap.Effects, e)
	}
}

// A resolved issue whose window is full of post-boundary evidence does not stall
// its batch: the oldest evidence folds, the whole batch commits and the checkpoint
// reaches its end (R01-3; it used to rest just below the stalled evidence, and with
// nothing applicable the answer was Quota, wedging the data group).
func TestAResolvedIssueFullOfPostBoundaryEvidenceDoesNotStallItsBatch(t *testing.T) {
	f := newFx(t)
	f.withLedger(issues.LedgerWindow{Trigger: 8, Keep: 4})
	f.apply(f.ev(1, f.A, 10))
	f.resolve(1, f.B) // boundary 100: later evidence in A does not contain the fix
	for i := range 11 {
		f.apply(f.ev(1, f.A, model.UnixNano(200+i)))
	}
	if got := f.issueFor(1); len(got.Occurrences) != 8 || got.Compacted == nil || got.Compacted.Count != 4 || got.Workflow != "resolved" {
		t.Fatalf("fixture: %d in the window, aggregate %+v", len(got.Occurrences), got.Compacted)
	}
	other, overflow, after := f.ev(2, f.A, 300), f.ev(1, f.A, 211), f.ev(2, f.A, 301)
	if e := f.svc.ApplyThrough(context.Background(), f.writer, after.Origin, []issues.Evidence{other, overflow, after}); e != nil {
		t.Fatalf("a resolved issue with a full post-boundary window stalled its batch: %v", e)
	}
	if cp := f.projectState().Checkpoints[f.group]; cp != after.Origin.Index {
		t.Fatalf("checkpoint %d, want the end of the batch %d", cp, after.Origin.Index)
	}
	got := f.issueFor(1)
	if s := issues.Summarize(got); s.Count != 13 || s.FirstSeen != 10 || s.LastSeen != 211 || got.Workflow != "resolved" {
		t.Fatalf("summary %+v workflow %s", s, got.Workflow)
	}
	if s := issues.Summarize(f.issueFor(2)); s.Count != 2 || s.LastSeen != 301 {
		t.Fatalf("the other issue: %+v", s)
	}
}

func TestLedgerWindowIsValidated(t *testing.T) {
	f := newFx(t)
	for name, w := range map[string]issues.LedgerWindow{
		"keep not below the trigger": {Trigger: 4, Keep: 4},
		"no keep":                    {Trigger: 5},
		"above the control cap":      {Trigger: model.GroupingWindowMax + 1, Keep: 8},
	} {
		_, e := issues.New(issues.Deps{Store: f.store, Authorizer: f.app.Auth, Graphs: f.graphs, Fence: f.fence, Policy: f.policy, Clock: f.clock, Ledger: w})
		if code(e) != model.Invalid {
			t.Errorf("%s: %v", name, e)
		}
	}
	f.withLedger(issues.LedgerWindow{Trigger: model.GroupingWindowMax, Keep: 1})
}

// R01-3: a resolved issue whose post-boundary evidence keeps arriving (a hot
// fingerprint in a release that does not contain the fix) must not wedge the data
// group's checkpoint. Over the real control store, 3000 such occurrences commit,
// the count stays exact, the issue stays resolved and its stored explanations stay
// inside control's size bound.
func TestHotResolvedFingerprintDoesNotWedgeTheCheckpoint(t *testing.T) {
	f := newRealFx(t)
	f.clock.at = 100_000
	first := f.ev(1, f.A, 10)
	f.apply(first)
	issue := f.issueByFp(1)
	if _, e := f.svc.Act(context.Background(), f.writer, issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: issue.Revision, IssueID: issue.ID, Kind: "resolve", Reason: "fixed in B", FixedDescendantFrontier: []model.ID{f.B}}); e != nil {
		t.Fatal(e)
	}
	const total = 3000
	all := []issues.Evidence{first}
	for i := 0; i < total; i += 100 {
		batch := make([]issues.Evidence, 0, 100)
		for j := range 100 {
			batch = append(batch, f.ev(1, f.A, model.UnixNano(200_000+i+j))) // after the boundary, without the fix
		}
		all = append(all, batch...)
		last := batch[len(batch)-1].Origin
		if e := f.svc.ApplyThrough(context.Background(), f.writer, last, batch); e != nil {
			t.Fatalf("batch at %d: %v (a hot resolved fingerprint wedged the checkpoint)", i, e)
		}
	}
	st := f.load()
	if st.Checkpoints[f.group] != model.Uint64(f.next) {
		t.Fatalf("checkpoint %d, want %d", st.Checkpoints[f.group], f.next)
	}
	got := f.issueByFp(1)
	if got.Workflow != "resolved" || issues.Summarize(got).Count != total+1 {
		t.Fatalf("workflow %s, count %d", got.Workflow, issues.Summarize(got).Count)
	}
	if window := len(got.Occurrences) + len(got.LateHistory); window > model.GroupingWindowMax || got.Compacted == nil {
		t.Fatalf("window %d, aggregate %+v", window, got.Compacted)
	}
	if want := exact(all); issues.Summarize(got) != want {
		t.Fatalf("summary\n got %+v\nwant %+v", issues.Summarize(got), want)
	}
	explained := f.explain(got)
	if len(explained) == 0 || len(explained) >= total {
		t.Fatalf("%d explanations kept of %d evaluated", len(explained), total)
	}
	if newest := all[len(all)-1]; explained[len(explained)-1].OccurrenceID != newest.OccurrenceID {
		t.Fatalf("the newest evaluation was not kept")
	}
}

// Pruning explanations never loses one the lifecycle still needs: an eligible
// evaluation of the current resolution counts toward the reopen threshold however
// many ineligible ones came after it.
func TestExplanationPruningKeepsWhatTheThresholdCounts(t *testing.T) {
	f := newFx(t)
	f.svc = f.service(issues.RegressionPolicy{MinOccurrences: 3})
	f.apply(f.ev(1, f.A, 10))
	f.resolve(1, f.B)
	f.apply(f.ev(1, f.C, 200), f.ev(1, f.C, 201)) // descendants of the fix: eligible, below the threshold
	var noise []issues.Evidence
	for i := range 2500 {
		noise = append(noise, f.ev(1, f.A, model.UnixNano(300+i))) // a release without the fix: never eligible
	}
	f.applyBatches(noise, 100)
	explained := f.explain(f.issueFor(1))
	if len(explained) >= 2502 {
		t.Fatalf("%d explanations are all kept", len(explained))
	}
	eligible := 0
	for _, x := range explained {
		if x.Decision.Eligible {
			eligible++
		}
	}
	if eligible != 2 {
		t.Fatalf("%d eligible evaluations kept, want the 2 the threshold counts", eligible)
	}
	f.apply(f.ev(1, f.C, 9000))
	if got := f.issueFor(1); got.Workflow != "open" {
		t.Fatalf("the third eligible occurrence must reopen: %s", got.Workflow)
	}
}
