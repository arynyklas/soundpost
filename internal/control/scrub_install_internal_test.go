// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The control.db scrub debt has two halves. The replicated one is derived from the audit log
// (an erasing audit owes a scrub, a scrubbed audit settles it) and says what SOME node's file
// went through. A voter that installs the leader's snapshot inherits the leader's log, scrubbed
// audit included, while Restore rewrites its own tree through copy-on-write pages and zeroes
// nothing: the payload its replaced state held stays in its own free pages. The local half is
// a marker in this file, written by the install in the same transaction and cleared only by a
// ScrubErased that ran on this file afterwards. These tests pin that the transplanted record
// settles nothing, that the debt is a durable fact about the file, and that nothing replicated
// reads or writes it.

const (
	installCanary  = "CANARYSCRUB72010d2b86a7c41e"
	installPayload = 30 // incident books carrying the canary: the replaced state spans many pages
)

// installFx is a real one-voter control store that holds installPayload incident books, every
// one carrying the canary.
type installFx struct {
	t                       *testing.T
	ctx                     context.Context
	dir                     string
	s                       *Store
	org, project, operation model.ID
	keys                    []string
}

func newInstallFx(t *testing.T) *installFx {
	t.Helper()
	f := &installFx{t: t, ctx: context.Background(), dir: t.TempDir(),
		org: model.ID{0x10}, project: model.ID{0x11}, operation: model.ID{0xdd}}
	s, err := Open(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	f.s = s
	t.Cleanup(func() { f.s.Close() })
	if err = s.EnableSingle(f.ctx, filepath.Join(f.dir, "raft-control")); err != nil {
		t.Fatal(err)
	}
	books := map[string]json.RawMessage{}
	for i := range installPayload {
		incident := model.ID{0xa1, byte(i)}
		rec, err := json.Marshal(IncidentRecord{Org: f.org, Project: f.project, ID: incident, Version: 1, Digest: model.Hash{7},
			State: json.RawMessage(`{"incident_id":"` + incident.String() + `","org_id":"` + f.org.String() + `","project_id":"` + f.project.String() + `","version":"1","evidence":"` + installCanary + `","at":"5"}`)})
		if err != nil {
			t.Fatal(err)
		}
		key := f.org.String() + ":" + f.project.String() + ":" + incident.String()
		books[key] = rec
		f.keys = append(f.keys, key)
	}
	if err = s.Update(f.ctx, func(st *State) error {
		st.IncidentBooks = books
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains([]byte(f.canonical(f.state())), []byte(installCanary)) || !f.dbHolds() {
		t.Fatal("fixture invalid: the local state or control.db does not hold the payload")
	}
	return f
}

func (f *installFx) state() State {
	f.t.Helper()
	st, err := f.s.localState()
	if err != nil {
		f.t.Fatal(err)
	}
	return st
}

func (f *installFx) canonical(st State) string {
	f.t.Helper()
	raw, err := model.CanonicalJSON(st)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(raw)
}

// dbHolds reports whether the bytes of control.db hold the payload (it is stored as JSON text).
func (f *installFx) dbHolds() bool {
	f.t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.dir, "control.db"))
	if err != nil {
		f.t.Fatal(err)
	}
	return bytes.Contains(raw, []byte(installCanary))
}

func (f *installFx) audit(action string, at int64) model.ControlAudit {
	return model.ControlAudit{ID: model.NewID(), Principal: model.ID{0xbb}, Action: action, Time: at, Org: f.org.String(), Targets: []model.ID{f.operation}, Outcome: model.AuditAllowed}
}

func (f *installFx) finishedDeletion() map[string]model.DeletionOperation {
	return map[string]model.DeletionOperation{f.operation.String(): {
		Predicate: model.DeletePredicate{Operation: f.operation, Org: f.org, Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}, Generation: 1},
		Phase:     model.DeletePhaseComplete, Principal: model.ID{0xbb}, CompletedAt: 10}}
}

func (f *installFx) dropPayload(st *State) {
	for _, key := range f.keys {
		delete(st.IncidentBooks, key)
	}
}

// leader is the leader's state `ahead` revisions after this voter's, without the payload; erased
// and scrubbed add its erasing audit and the scrubbed audit its own worker pass appended.
func (f *installFx) leader(ahead model.Revision, erased, scrubbed bool) State {
	st := f.state()
	st.Revision += ahead
	f.dropPayload(&st)
	if erased {
		st.Audits = append(st.Audits, f.audit(controlErasedAction, 10))
		st.Deletions = f.finishedDeletion()
	}
	if scrubbed {
		st.Audits = append(st.Audits, f.audit(controlScrubbedAction, 12))
	}
	return st
}

func (f *installFx) snapshot(st State) []byte {
	f.t.Helper()
	raw, err := json.Marshal(controlSnapshot{State: st, Keys: map[string][]byte{}, Metadata: map[string][]byte{}})
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

// install is what the replication layer does with a snapshot from the leader (restoreSnapshot):
// verify it, then restore it at the next index. The group's own cursors do not move, so nothing
// may be committed to the group afterwards; installInSync is for the tests that commit.
func (f *installFx) install(st State) {
	f.t.Helper()
	raw, m := f.snapshot(st), f.s.repl
	if err := m.VerifySnapshot(raw); err != nil {
		f.t.Fatalf("the voter refused the leader's snapshot: %v", err)
	}
	if err := m.Restore(raw, m.Applied()+1); err != nil {
		f.t.Fatalf("Restore: %v", err)
	}
}

// installInSync installs st at the group's own revision and index, so the group keeps taking
// commands afterwards.
func (f *installFx) installInSync(st State) {
	f.t.Helper()
	st.Revision = f.state().Revision
	m := f.s.repl
	if err := m.Restore(f.snapshot(st), m.Applied()); err != nil {
		f.t.Fatalf("Restore: %v", err)
	}
}

func (f *installFx) owesState() bool {
	f.t.Helper()
	return slices.Contains(f.s.ResidualStores(), ResidualControlState)
}

func (f *installFx) local() localScrub {
	f.t.Helper()
	_, local, err := f.s.scrubState()
	if err != nil {
		f.t.Fatal(err)
	}
	return local
}

// reopen closes the store and opens the same control.db again, as a restart does. The control
// group is not started: these tests install on the machine alone, so the group's cursors stay
// where they were and its journal could not replay (the live install through a group is in
// scrub_install_voters_test.go).
func (f *installFx) reopen() {
	f.t.Helper()
	if err := f.s.Close(); err != nil {
		f.t.Fatal(err)
	}
	s, err := Open(f.dir)
	if err != nil {
		f.t.Fatal(err)
	}
	f.s = s
}

// The leader's snapshot carries the leader's settled scrub debt. Installing it must not settle
// this voter's: its own control.db still holds, in free pages, the payload the leader erased.
func TestAnInstalledSnapshotDoesNotSettleThisFilesScrubDebt(t *testing.T) {
	f := newInstallFx(t)
	f.install(f.leader(5, true, true))
	holds := f.dbHolds()
	got := f.s.ResidualStores()
	t.Logf("after installing the leader's snapshot: the payload is on disk in control.db=%v; the receipt names %v", holds, got)
	if !holds {
		t.Fatal("fixture invalid: the install left no copy of the replaced state in control.db")
	}
	if !slices.Contains(got, ResidualControlState) {
		t.Errorf("FALSE CLEAN: the voter's own control.db still holds the erased payload while ResidualStores does not name control_state (the installed audit log settled the debt the leader paid, not this file's): %v", got)
	}
	if bytes.Contains([]byte(f.canonical(f.state())), []byte(installCanary)) {
		t.Fatal("the install did not replace the live state: the bytes should survive only in the file's free pages")
	}
	if len(owedScrubs(f.state().Audits)) != 0 {
		t.Fatal("fixture invalid: the installed log still owes a scrub by itself, the local debt proves nothing")
	}
}

// The debt is a fact about this file: a restart keeps it, and it ends only when a ScrubErased
// ran on this file after the install.
func TestTheInstalledScrubDebtSurvivesARestartUntilALocalScrubRan(t *testing.T) {
	f := newInstallFx(t)
	f.install(f.leader(5, true, true))
	for range 2 {
		f.reopen()
		if !f.owesState() {
			t.Fatalf("a restart forgot the scrub an install owes: %v", f.s.ResidualStores())
		}
		if !f.dbHolds() {
			t.Fatal("fixture invalid: the restart changed the payload bytes")
		}
	}
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.dbHolds() {
		t.Fatal("control.db still holds the erased payload after the local scrub")
	}
	for range 2 {
		f.reopen()
		if f.owesState() {
			t.Fatalf("a restart after the local scrub names control_state again: %v", f.s.ResidualStores())
		}
		if f.dbHolds() {
			t.Fatal("a restart brought the erased payload back")
		}
	}
}

// The local scrub zeroes the installed file's free pages and settles a debt that is this file's
// alone: it appends no audit and commits no revision, so what every voter computes is untouched.
func TestALocalScrubAfterAnInstallZeroesTheFreePagesAndCommitsNothingReplicated(t *testing.T) {
	f := newInstallFx(t)
	f.install(f.leader(5, true, true))
	before, applied := f.canonical(f.state()), f.s.repl.Applied()
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.dbHolds() {
		t.Fatal("control.db still holds the erased payload after the scrub of the installed file")
	}
	if f.owesState() {
		t.Fatalf("a scrub that zeroed the installed file leaves the debt: %v", f.s.ResidualStores())
	}
	if after := f.canonical(f.state()); after != before || f.s.repl.Applied() != applied {
		t.Fatal("the local scrub changed replicated state: it must commit nothing")
	}
	// A second scrub has nothing owed and touches nothing.
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.s.repl.Applied() != applied {
		t.Fatal("a scrub with nothing owed committed a command")
	}
}

// Nothing but a local scrub clears the debt: not a replicated commit, not another scrubbed
// audit, not a scrub that failed.
func TestOnlyALocalScrubClearsTheInstalledScrubDebt(t *testing.T) {
	f := newInstallFx(t)
	f.installInSync(f.leader(0, true, true))
	owed := f.local()
	if !owed.owed {
		t.Fatal("fixture invalid: the install owes nothing")
	}
	// Any replicated commit, including one that appends scrubbed audits.
	if err := f.s.Update(f.ctx, func(st *State) error {
		st.Quotas = map[string]model.QuotaState{"after:install": {MaxBytes: 1}}
		st.Audits = append(st.Audits, f.audit(controlScrubbedAction, 20), f.audit(controlScrubbedAction, 21))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !f.owesState() || f.local() != owed {
		t.Fatalf("a replicated commit cleared the install debt: %v %+v", f.s.ResidualStores(), f.local())
	}
	// A scrub that did not finish.
	cancelled, cancel := context.WithCancel(f.ctx)
	cancel()
	if err := f.s.ScrubErased(cancelled); err == nil {
		t.Fatal("a cancelled scrub reported success")
	}
	if !f.owesState() || f.local() != owed {
		t.Fatalf("a scrub that did not complete cleared the install debt: %v %+v", f.s.ResidualStores(), f.local())
	}
	if !f.dbHolds() {
		t.Fatal("fixture invalid: the cancelled scrub zeroed the file")
	}
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.owesState() || f.dbHolds() {
		t.Fatalf("the completed scrub left the debt or the bytes: %v", f.s.ResidualStores())
	}
}

// A scrub clears the debt it started with. An install that lands while it runs frees pages it
// may have passed, so the debt must stay.
func TestAnInstallThatLandsDuringAScrubKeepsTheDebtItDidNotCover(t *testing.T) {
	f := newInstallFx(t)
	f.install(f.leader(5, true, true))
	started := f.local()
	f.install(f.leader(9, true, true)) // lands after the scrub read its state
	landed := f.local()
	if landed.generation == started.generation || !landed.owed {
		t.Fatalf("a second install did not bump the debt: %+v then %+v", started, landed)
	}
	if err := f.s.settleLocalScrub(started.generation); err != nil {
		t.Fatal(err)
	}
	if f.local() != landed || !f.owesState() {
		t.Fatalf("a scrub cleared a debt it did not cover: %+v", f.local())
	}
	if err := f.s.settleLocalScrub(landed.generation); err != nil {
		t.Fatal(err)
	}
	if f.local().owed || f.owesState() {
		t.Fatalf("the scrub that covered the debt did not clear it: %+v", f.local())
	}
}

// An install owes only when something is owed: a log that names no erasure, installed over a
// file that owes nothing, leaves no marker.
func TestAnInstallThatNamesNoErasureOwesNoScrub(t *testing.T) {
	f := newInstallFx(t)
	f.install(f.leader(5, false, false))
	if f.owesState() || f.local() != (localScrub{}) {
		t.Fatalf("an install of a log with no erasure owes a scrub: %v %+v", f.s.ResidualStores(), f.local())
	}
	// A scrub with nothing owed does not touch the file.
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	if !f.dbHolds() {
		t.Fatal("a scrub with nothing owed zeroed the file")
	}
}

// A scrub that was already owed is not forgotten by an install whose log does not name it. The
// debt is in the file's own marker (set when it applied its erasure, or by an earlier install),
// and for a file that predates the marker the log the install replaces is the only thing that
// knows: it can hold an erasing audit nothing settled.
func TestAnInstallKeepsAScrubTheInstalledLogDoesNotName(t *testing.T) {
	erase := func(f *installFx) {
		t.Helper()
		if err := f.s.Update(f.ctx, func(st *State) error {
			f.dropPayload(st)
			st.Deletions = f.finishedDeletion()
			st.Audits = append(st.Audits, f.audit(controlErasedAction, 10))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	lineageOf := func(f *installFx) State {
		st := f.leader(0, false, false) // another lineage: no erasing audit
		st.Audits, st.Deletions = nil, nil
		st.Revision = f.state().Revision + 5
		return st
	}

	// This file applied an erasure itself and has not scrubbed yet.
	f := newInstallFx(t)
	erase(f)
	if !f.local().owed {
		t.Fatal("fixture invalid: applying an erasure left no marker")
	}
	f.install(lineageOf(f))
	if !f.local().owed || !f.owesState() {
		t.Fatalf("an install without an erasure settled the debt of an applied one: %v %+v", f.s.ResidualStores(), f.local())
	}

	// A file that predates the marker: only its log owes.
	old := newInstallFx(t)
	erase(old)
	if err := old.s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("control")).Delete(localScrubKey) }); err != nil {
		t.Fatal(err)
	}
	if old.local() != (localScrub{}) || !old.owesState() {
		t.Fatalf("fixture invalid: the replicated debt alone must be what is owed: %v %+v", old.s.ResidualStores(), old.local())
	}
	old.install(lineageOf(old))
	if !old.local().owed || !old.owesState() {
		t.Fatalf("an install dropped the audit that owed a scrub and the debt with it: %v %+v", old.s.ResidualStores(), old.local())
	}

	// A marker that an install set stays set across a later install that names no erasure.
	g := newInstallFx(t)
	g.install(g.leader(5, true, true))
	first := g.local()
	next := g.state()
	next.Audits, next.Deletions = nil, nil
	next.Revision += 4
	g.install(next)
	if !g.local().owed || !g.owesState() {
		t.Fatalf("a later install without an erasure settled the debt of the first: %v %+v", g.s.ResidualStores(), g.local())
	}
	// The install freed pages a scrub that started before it may have passed.
	if g.local().generation == first.generation {
		t.Fatalf("an install over an owed file did not bump the debt: %+v then %+v", first, g.local())
	}
}

// A control.db that OpenSeed has just created never held anything but the seed's own state,
// which is already erased: it owes no scrub, and the marker of the node that cut the seed is
// not part of the seed.
func TestASeededReplicaOwesNoInstalledScrub(t *testing.T) {
	f := newInstallFx(t)
	f.install(f.leader(5, true, true))
	if !f.local().owed {
		t.Fatal("fixture invalid: the cutting node owes nothing")
	}
	seed, _, err := f.s.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(seed, localScrubKey) {
		t.Fatal("the scrub marker is part of the seed a node hands out")
	}
	var parsed controlSnapshot
	if err = json.Unmarshal(seed, &parsed); err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.Metadata[string(localScrubKey)]; ok {
		t.Fatal("the scrub marker is part of the snapshot metadata")
	}
	seeded, err := OpenSeed(t.TempDir(), seed)
	if err != nil {
		t.Fatal(err)
	}
	defer seeded.Close()
	if slices.Contains(seeded.ResidualStores(), ResidualControlState) {
		t.Fatalf("a freshly seeded file owes a scrub of payloads it never held: %v", seeded.ResidualStores())
	}
	if _, local, err := seeded.scrubState(); err != nil || local != (localScrub{}) {
		t.Fatalf("a freshly seeded file carries a scrub marker: %+v %v", local, err)
	}
}
