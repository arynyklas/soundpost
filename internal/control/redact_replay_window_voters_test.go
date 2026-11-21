// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// The window the patch base does not check (state_patch_redact.go, redact_journal.go): an erasure
// pass rewrites the retained commands of the control group, and once one was rewritten every later
// retained patch loses its base, because the voter that applies the rewritten log holds records the
// pass erased. A voter that was behind replays that log. It has to reach, at the pass head, the
// bytes of the voters that applied the originals; the group then has to take patches whose base
// it checks again.
//
// The log is rewritten without the snapshot and compaction the whole pass ends with
// (RedactRetainedLogOnlyForTest): the pass compacts onto a snapshot, which a lagging voter installs,
// and the point here is the replay of the rewritten retained commands.

// A voter that applied the first half (it holds the records the pass erases) and then missed the
// rest replays the rewritten log.
func TestALaggingVoterReplayingARewrittenLogReachesThePassHead(t *testing.T) {
	rewrittenLogReplay(t, false, false, false)
}

// A voter that missed everything after the fixture is behind by the commands before the first
// rewritten one (they keep their base) and by those after it (they lose it).
func TestAVoterBehindTheFirstRewrittenCommandReplaysTheRewrittenLogToThePassHead(t *testing.T) {
	rewrittenLogReplay(t, true, false, false)
}

// The first record of a book is the one the deletion drops whole: its command wrote the whole book
// (the state it came from held none), the rewrite of it leaves an empty book, which the state
// encoding does not keep (omitempty), and the next record of the book was proposed against a state
// that held the book. A voter that replays the rewritten log answers corrupt to that patch and stops.
func TestAVoterReplayingARewrittenLogThatEmptiesAWholeBookReachesThePassHead(t *testing.T) {
	rewrittenLogReplay(t, true, true, false)
}

// The book holds only the erased project's views: the last records of it are key-level sets that the
// rewrite turns into deletes, which empty the book (an omitted-when-empty member).
func TestAVoterReplayingARewrittenLogWhoseLastBookRecordsAreErasedReachesThePassHead(t *testing.T) {
	rewrittenLogReplay(t, false, false, true)
}

func rewrittenLogReplay(t *testing.T, behindFromTheStart, firstRecordOfTheBookIsErased, onlyErasedViews bool) {
	d := newPatchVoters(t, replica.Cadence{}, true) // the gate is open on every voter: SOUNDPOST_FORCE_STATE_PATCH is not needed
	const (
		first  = "CANARYWINDOWFIRST0d2b86a7c41e"
		second = "CANARYWINDOWSECOND51f0aa93c7d"
		kept   = "CANARYWINDOWKEPT7c41e90d2b86a"
	)
	leader := d.fx[1]
	ctx := context.Background()
	patchesAtStart := d.patches()
	cut := func() {
		d.await(2, d.mustRevision(1))
		d.mesh.cut(stormVoter, true)
	}
	if behindFromTheStart {
		d.await(stormVoter, d.mustRevision(1))
		d.mesh.cut(stormVoter, true)
	}
	keptSeed := leader.newSeed(leader.otherProject, kept)
	leader.seedAll(keptSeed, 40) // before any command that is rewritten: a retained patch with its base
	erasedFirst := leader.newSeed(leader.project, first)
	leader.seedAll(erasedFirst, 50)
	if !behindFromTheStart {
		d.await(stormVoter, d.mustRevision(1)) // the voter holds the records the pass erases
		cut()
	}
	lagApplied := d.stores[stormVoter].ReplicaGroup().Status().Applied
	// Records written several times: the erased project's and the kept one's rule.
	evaluated := map[model.ID]model.Revision{erasedFirst.rule: 1, keptSeed.rule: 1} // seedAll applied one evaluation to each
	reevaluate := func(s eraseSeed, at uint64) {
		reEvaluateRule(leader, s, at, evaluated[s.rule])
		evaluated[s.rule]++
	}
	for at := uint64(51); at <= 54; at++ {
		reevaluate(erasedFirst, at)
		reevaluate(keptSeed, at)
	}
	if !firstRecordOfTheBookIsErased && !onlyErasedViews {
		writeSavedView(d, leader.org, leader.otherProject, "kept", kept+"-seed") // the book exists before any record of it is erased
	}
	for n := range 3 { // a record the deletion drops whole, written three times; and one of the kept project
		writeSavedView(d, leader.org, leader.project, "erased", fmt.Sprintf("%s-%d", first, n))
		if !onlyErasedViews {
			writeSavedView(d, leader.org, leader.otherProject, "kept", fmt.Sprintf("%s-%d", kept, n))
		}
	}
	erasedSecond := leader.newSeed(leader.project, second)
	leader.seedAll(erasedSecond, 60)
	d.write(1, 3)
	reevaluate(keptSeed, 70)
	leader.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{leader.project}})
	reevaluate(keptSeed, 71) // and a last write of a kept record after the erasure
	d.write(2, 2)
	d.await(2, d.mustRevision(1))
	if n := d.patches() - patchesAtStart; n < 25 {
		t.Fatalf("only %d commands were patches: the scenario did not run on patches", n)
	}
	if got := d.stores[stormVoter].ReplicaGroup().Status().Applied; got != lagApplied {
		t.Fatalf("fixture invalid: the cut voter applied through index %d to %d", lagApplied, got)
	}
	d.mesh.mu.Lock()
	snapshotsBefore := d.mesh.snaps[stormVoter]
	d.mesh.mu.Unlock()
	head := d.mustRevision(1)

	// The leader's retained commands before the rewrite: every patch carries its base.
	shape, err := d.stores[1].RetainedCommandShapeForTest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if shape.PatchesWithBase == 0 || shape.PatchesWithoutBase != 0 {
		t.Fatalf("fixture invalid: before the rewrite the leader retains %+v", shape)
	}
	if err = leader.write(func() error { return d.stores[1].RedactRetainedLogOnlyForTest(ctx) }); err != nil {
		t.Fatal(err)
	}
	rewritten, err := d.stores[1].RetainedCommandShapeForTest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rewritten.PatchesWithoutBase == 0 {
		t.Fatalf("the pass rewrote no patch without its base: %+v", rewritten)
	}
	if rewritten.PatchesWithBase == 0 {
		t.Fatalf("no retained patch kept its base although some precede the first rewritten command: %+v", rewritten)
	}
	if got := d.mustRevision(1); got != head {
		t.Fatalf("the rewrite moved the leader from revision %d to %d", head, got)
	}
	for _, canary := range []string{first, second} {
		if hits := leader.raftHits(canary); len(hits) != 0 {
			t.Fatalf("the leader's rewritten log still holds %s: %v", canary, hits)
		}
	}

	// The lagging voter is caught up from the rewritten retained log, not from a snapshot.
	d.mesh.cut(stormVoter, false)
	d.await(stormVoter, head)
	d.mesh.mu.Lock()
	snapshotsAfter := d.mesh.snaps[stormVoter]
	d.mesh.mu.Unlock()
	if snapshotsAfter != snapshotsBefore {
		t.Fatalf("voter %d installed a snapshot: it did not replay the rewritten log", stormVoter)
	}
	status := d.stores[stormVoter].ReplicaGroup().Status()
	leaderStatus := d.stores[1].ReplicaGroup().Status()
	if status.Failed || status.Applied <= lagApplied || status.Applied < leaderStatus.Applied {
		t.Fatalf("voter %d did not apply through the rewritten patches: applied %d (was %d, leader %d) failed=%v", stormVoter, status.Applied, lagApplied, leaderStatus.Applied, status.Failed)
	}
	if got := d.mustRevision(stormVoter); got != head {
		t.Fatalf("voter %d is at revision %d, the pass head is %d", stormVoter, got, head)
	}

	// At the pass head: byte-identical state, no erased payload on any voter, the kept records are there.
	assertWindowState := func(what string) {
		t.Helper()
		d.converge()
		want := d.fx[1].canonicalState()
		for id := uint64(1); id <= 3; id++ {
			if got := d.fx[id].canonicalState(); got != want {
				t.Fatalf("%s: voter %d holds other state bytes than voter 1", what, id)
			}
			if !d.fx[id].stateHoldsNone(first, second) {
				t.Fatalf("%s: voter %d holds an erased payload", what, id)
			}
			if !d.fx[id].stateHolds(kept) {
				t.Fatalf("%s: voter %d lost a payload no deletion covers", what, id)
			}
		}
		d.agree()
	}
	assertWindowState("at the pass head")

	// The group takes patches that carry a base again, on the voter that replayed the window too.
	d.settle()
	patches := d.patches()
	d.write(stormVoter, 3)
	assertWindowState("after the replayed voter proposed")
	d.write(1, 2)
	d.write(2, 2)
	assertWindowState("after every voter proposed")
	if n := d.patches() - patches; n < 7 {
		t.Fatalf("only %d of 7 later commands were patches", n)
	}
	later, err := d.stores[stormVoter].RetainedCommandShapeForTest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if later.PatchesWithBase <= rewritten.PatchesWithBase {
		t.Fatalf("no later patch carried a base on voter %d: %+v then %+v", stormVoter, rewritten, later)
	}
	if d.stores[stormVoter].ReplicaGroup().Status().Failed {
		t.Fatalf("voter %d failed", stormVoter)
	}
}

// reEvaluateRule commits another evaluation of a rule seedAll already evaluated: the command that
// rewrites the rule's book (the record keeps its identity, its last write changes). expected is the
// number of evaluations already applied to it.
func reEvaluateRule(f *eraseFx, s eraseSeed, at uint64, expected model.Revision) {
	f.t.Helper()
	payload := fmt.Sprintf(`{"series":%q}`, s.canary)
	out := control.RuleOutputIntent{ID: model.NewID(), Kind: control.RuleOutputRecording, Signal: model.Metric,
		Payload: json.RawMessage(fmt.Sprintf(`{"batch":{"records":[{"metric":%q}]}}`, s.canary)), Inputs: []model.Cursor{{Group: model.ID{9}, Index: 1}}}
	e := &control.RuleEvaluationApply{Project: s.project, Rule: s.rule, Version: 1, At: model.UnixNano(at), Mode: control.RuleModeLive, Health: control.RuleHealthOK,
		Digest: digestOf(payload), Payload: json.RawMessage(payload), ExpectedStateRevision: expected,
		Cursors: []model.Cursor{{Group: model.ID{9}, Index: model.Uint64(at)}}, Outputs: []control.RuleOutputIntent{out}}
	id := model.NewID()
	if err := f.write(func() error {
		lease, err := f.leaseNow()
		if err != nil {
			return err
		}
		_, err = f.transactNow(control.KindApplyRuleEvaluation, id, control.RuleCommand{Operation: control.RuleOpEvaluation, Lease: &lease, Evaluation: e})
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
}

// writeSavedView commits one write of the saved view record "org:project:name" through voter 1: a
// patch of that record, which the retirement of its project drops whole (eraseSavedViews).
func writeSavedView(d *patchVoters, org, project model.ID, name, text string) {
	d.t.Helper()
	key := org.String() + ":" + project.String() + ":" + name
	err := d.fx[1].write(func() error {
		return d.stores[1].Update(context.Background(), func(st *control.State) error {
			if st.SavedViewBooks == nil {
				st.SavedViewBooks = map[string]json.RawMessage{}
			}
			st.SavedViewBooks[key] = json.RawMessage(fmt.Sprintf(`{"name":%q,"expression":%q}`, name, text))
			return nil
		})
	})
	if err != nil {
		d.t.Fatal(err)
	}
}
