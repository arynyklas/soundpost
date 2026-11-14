// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// A commit that adds an erasing audit frees the pages that held what it erased, on every voter
// that applies it: the leader that proposed it, a follower that replays it. The replicated log
// then also carries the scrubbed audit the leader appended after zeroing ITS file. These tests
// use the one voter's own Apply for the commit a follower replays (the command carries the whole
// next state, so Apply cannot tell a replay from a live commit) and pin that the file owes a
// scrub of its own whatever the log says another node did.

// erasedByTheLeader drops the payload and appends what the leader's log carries after its own
// erasure and scrub: the erasing audit and, when scrubbed is set, the scrubbed audit.
func (f *installFx) erasedByTheLeader(scrubbed bool) {
	f.t.Helper()
	if err := f.s.Update(f.ctx, func(st *State) error {
		f.dropPayload(st)
		st.Deletions = f.finishedDeletion()
		st.Audits = append(st.Audits, f.audit(controlErasedAction, 10))
		if scrubbed {
			st.Audits = append(st.Audits, f.audit(controlScrubbedAction, 12))
		}
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
}

func TestAnAppliedErasureOwesThisFilesScrubWhateverTheLogSays(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(true)
	if len(owedScrubs(f.state().Audits)) != 0 {
		t.Fatal("fixture invalid: the log owes nothing by itself, the local debt proves nothing")
	}
	if !f.dbHolds() {
		t.Fatal("fixture invalid: the commit left no copy of the replaced state in control.db")
	}
	if !f.owesState() {
		t.Errorf("FALSE CLEAN: this file applied the erasure, its control.db still holds the payload, and the replicated scrubbed audit settled the receipt: %v", f.s.ResidualStores())
	}

	// The debt is a fact about the file: restarts keep it, a local scrub ends it, and the scrub
	// commits nothing replicated (the log owes nothing itself).
	for range 2 {
		f.reopen()
		if !f.owesState() {
			t.Fatalf("a restart forgot the scrub an applied erasure owes: %v", f.s.ResidualStores())
		}
		if !f.dbHolds() {
			t.Fatal("fixture invalid: the restart changed the payload bytes")
		}
	}
	before := f.canonical(f.state())
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.dbHolds() {
		t.Fatal("control.db still holds the erased payload after the local scrub")
	}
	if f.owesState() || f.canonical(f.state()) != before {
		t.Fatalf("the local scrub left the debt or changed replicated state: %v", f.s.ResidualStores())
	}
	for range 2 {
		f.reopen()
		if f.owesState() || f.dbHolds() {
			t.Fatalf("a restart after the local scrub brought the debt or the payload back: %v", f.s.ResidualStores())
		}
	}
}

// Once this file has scrubbed, a commit that adds no erasing audit does not owe a scrub again,
// although the log still names the erasure.
func TestACommitAfterTheLocalScrubOwesNothingAgain(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(true)
	if !f.owesState() {
		t.Fatal("fixture invalid: applying an erasure left no debt")
	}
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.owesState() {
		t.Fatalf("the local scrub left the debt: %v", f.s.ResidualStores())
	}
	if err := f.s.Update(f.ctx, func(st *State) error {
		st.Quotas = map[string]model.QuotaState{"after:scrub": {MaxBytes: 1}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if f.owesState() {
		t.Fatalf("a commit without an erasure owes a scrub again: %v %+v", f.s.ResidualStores(), f.local())
	}
}

// A scrubbed audit that a replicated commit appends later, from any node, settles nothing here.
func TestAReplicatedScrubbedAuditNeverSettlesTheLocalDebt(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(false)
	owed := f.local()
	if !owed.owed || !f.owesState() {
		t.Fatal("fixture invalid: applying an erasure left no debt")
	}
	if err := f.s.Update(f.ctx, func(st *State) error {
		st.Audits = append(st.Audits, f.audit(controlScrubbedAction, 12))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(owedScrubs(f.state().Audits)) != 0 {
		t.Fatal("fixture invalid: the scrubbed audit did not settle the log's own debt")
	}
	if !f.owesState() || f.local() != owed || !f.dbHolds() {
		t.Fatalf("a replicated scrubbed audit settled this file's debt: %v %+v", f.s.ResidualStores(), f.local())
	}
}

// A node that applied no erasure owes nothing, whatever else the log carries.
func TestACommitWithoutAnErasureOwesNoScrub(t *testing.T) {
	f := newInstallFx(t)
	for _, change := range []func(*State){
		func(st *State) { st.Quotas = map[string]model.QuotaState{"no:erasure": {MaxBytes: 1}} },
		func(st *State) { st.Audits = append(st.Audits, f.audit(controlScrubbedAction, 12)) },
	} {
		if err := f.s.Update(f.ctx, func(st *State) error { change(st); return nil }); err != nil {
			t.Fatal(err)
		}
		if f.owesState() || f.local() != (localScrub{}) {
			t.Fatalf("a commit that adds no erasing audit owes a scrub: %v %+v", f.s.ResidualStores(), f.local())
		}
	}
	// A scrub with nothing owed does not touch the file.
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	if !f.dbHolds() {
		t.Fatal("a scrub with nothing owed zeroed the file")
	}
}

// A scrub clears the debt it started with: an erasure committed while it ran freed pages it may
// have passed.
func TestAnErasureAppliedDuringAScrubKeepsTheDebtItDidNotCover(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(false)
	started := f.local()
	if err := f.s.Update(f.ctx, func(st *State) error { // lands after the scrub read its state
		st.Audits = append(st.Audits, f.audit(controlErasedAction, 20))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	landed := f.local()
	if landed.generation == started.generation || !landed.owed {
		t.Fatalf("a second erasure did not bump the debt: %+v then %+v", started, landed)
	}
	if err := f.s.settleLocalScrub(started.generation); err != nil {
		t.Fatal(err)
	}
	if f.local() != landed {
		t.Fatalf("a scrub cleared a debt it did not cover: %+v", f.local())
	}
	if err := f.s.settleLocalScrub(landed.generation); err != nil {
		t.Fatal(err)
	}
	if f.local().owed {
		t.Fatalf("the scrub that covered the debt did not clear it: %+v", f.local())
	}
}

// The marker is invisible to replicated apply: two files that differ only in it compute the same
// state from the same commit, and nothing a node hands out carries it.
func TestTheScrubMarkerDoesNotChangeWhatAVoterComputes(t *testing.T) {
	owing, plain := newInstallFx(t), newInstallFx(t)
	raw := owing.snapshot(owing.leader(0, true, true))
	for _, f := range []*installFx{owing, plain} {
		if err := f.s.repl.Restore(raw, f.s.repl.Applied()); err != nil {
			t.Fatal(err)
		}
	}
	if err := plain.s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("control")).Delete(localScrubKey) }); err != nil {
		t.Fatal(err)
	}
	if !owing.local().owed || plain.local() != (localScrub{}) || owing.canonical(owing.state()) != plain.canonical(plain.state()) {
		t.Fatal("fixture invalid: the two files must differ only in the marker")
	}
	// The same commit, erasing audit included, on both.
	for _, f := range []*installFx{owing, plain} {
		if err := f.s.Update(f.ctx, func(st *State) error {
			st.Quotas = map[string]model.QuotaState{"same:change": {MaxBytes: 7}}
			st.Audits = append(st.Audits, model.ControlAudit{ID: model.ID{0xee}, Principal: model.ID{0xbb}, Action: controlErasedAction, Time: 100, Targets: []model.ID{{0xef}}, Outcome: model.AuditAllowed})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if owing.canonical(owing.state()) != plain.canonical(plain.state()) || owing.s.repl.Applied() != plain.s.repl.Applied() {
		t.Fatal("the marker changed what a replicated commit computed")
	}
	if !owing.local().owed || !plain.local().owed {
		t.Fatalf("applying an erasure must owe on both files: %+v %+v", owing.local(), plain.local())
	}
	snap, err := owing.s.repl.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var parsed controlSnapshot
	if err = json.Unmarshal(snap, &parsed); err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.Metadata[string(localScrubKey)]; ok || bytes.Contains(snap, localScrubKey) {
		t.Fatal("a node's snapshot carries its scrub marker")
	}
}
