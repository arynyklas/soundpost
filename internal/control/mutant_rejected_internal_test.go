// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

// These tests drive the control state machine (replicatedControl.Apply) directly with committed
// commands, the way the replica group hands them over, and pin the rejected branch: a command whose
// expected revision is not the committed one answers replica.ErrConflict, replaces nothing, owes no
// scrub, records the replica index of the rejection (staleAppliedKey: attest.go reads it as the
// floor of every journal proof) and a "rejected:<id>" marker that makes a replay answer the same
// conflict. The machine is handed commands the group has not committed, so no test commits anything
// through the group afterwards.

// mutantEntry is a committed control command for the machine of f at the next replica index. It
// expects revision expected and carries the current state, changed by build, with revision
// expected+1; cursor is the application slot the group stamped on it.
func (f *installFx) mutantEntry(expected, cursor model.Revision, build func(*State)) replica.CommittedEntry {
	f.t.Helper()
	st := f.state()
	build(&st)
	st.Revision = expected + 1
	keys, err := f.s.replicaKeyFiles()
	if err != nil {
		f.t.Fatal(err)
	}
	payload, err := json.Marshal(controlReplacement{Expected: expected, State: st, Keys: keys})
	if err != nil {
		f.t.Fatal(err)
	}
	physical, err := f.s.appliedIndex()
	if err != nil {
		f.t.Fatal(err)
	}
	g := f.s.ReplicaGroup().Status()
	return replica.CommittedEntry{
		Group: g.Group, Term: g.Term, Index: physical + 1,
		ApplicationCursor: model.Cursor{Group: g.Group, Index: model.Uint64(cursor)},
		Entry:             replica.Entry{ID: model.NewID(), Kind: replica.Control, Payload: payload},
	}
}

// mutantMeta is one value of the replica_control metadata bucket (nil when the key is absent).
func (f *installFx) mutantMeta(key string) []byte {
	f.t.Helper()
	var out []byte
	if err := f.s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket([]byte("replica_control")).Get([]byte(key)); v != nil {
			out = append([]byte{}, v...)
		}
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// mutantMarks is the three watermarks the machine stores after every command it takes.
func (f *installFx) mutantMarks() [3]uint64 {
	f.t.Helper()
	return [3]uint64{readWatermark(f.mutantMeta("physical")), readWatermark(f.mutantMeta("application")), readWatermark(f.mutantMeta("term"))}
}

func mutantCode(err error) model.Code {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fault.Code
	}
	return ""
}

// stale is a command built before the committed revision: it expects one revision behind, and its
// state differs from the committed one in everything a replacement could change (a quota, an erasing
// audit, a dropped payload), so a stale command that was applied, or only compared, would show.
func (f *installFx) mutantStale(cursor model.Revision) replica.CommittedEntry {
	f.t.Helper()
	rev := f.state().Revision
	return f.mutantEntry(rev-1, cursor, func(st *State) {
		f.dropPayload(st)
		st.Quotas = map[string]model.QuotaState{"stale:cmd": {MaxBytes: 9}}
		st.Audits = append(st.Audits, f.audit(controlErasedAction, 10))
		st.Deletions = f.finishedDeletion()
	})
}

// A rejected command changes nothing but the watermarks: the committed state is byte for byte what it
// was, no scrub is owed, and the index of the rejection is stored durably where the attestation floor
// reads it (the journal floor moves to it; the control.db floor is an install's, never a stale
// command's).
func TestMutantAStaleCommandIsRejectedAndRecordsOnlyItsIndex(t *testing.T) {
	f := newInstallFx(t)
	before, owedBefore := f.canonical(f.state()), f.local()
	_, stateFloor := f.s.attestFloors()
	rev := f.state().Revision
	c := f.mutantStale(rev)
	if err := f.s.repl.Apply(c); !errors.Is(err, replica.ErrConflict) {
		t.Fatalf("a command that expects an older revision answered %v, want replica.ErrConflict", err)
	}
	if got := f.canonical(f.state()); got != before {
		t.Fatalf("a rejected command replaced the committed state:\n got  %.300s\n want %.300s", got, before)
	}
	if f.local() != owedBefore || f.owesState() {
		t.Fatalf("a rejected command owes a scrub: %+v %v", f.local(), f.s.ResidualStores())
	}
	if marks := f.mutantMarks(); marks != [3]uint64{c.Index, uint64(rev), c.Term} {
		t.Fatalf("watermarks after the rejection = %v, want physical %d, application %d, term %d", marks, c.Index, rev, c.Term)
	}
	if got := f.mutantMeta("rejected:" + c.Entry.ID.String()); len(got) != 1 || got[0] != 1 {
		t.Fatalf("the rejection left no marker: %v", got)
	}
	if got := f.s.staleCutoff(); got != c.Index {
		t.Fatalf("the stale cutoff is %d, want the index of the rejected command %d", got, c.Index)
	}
	if journal, state := f.s.attestFloors(); journal != c.Index || state != stateFloor {
		t.Fatalf("attest floors after a stale command: journal %d, state %d; want %d and %d (unchanged)", journal, state, c.Index, stateFloor)
	}
}

// The group may hand the machine a command again (a restart replays what the machine had already
// applied); a rejected one must answer the same conflict, however often and whatever the file holds,
// and must not touch anything.
func TestMutantAReplayedStaleCommandIsRejectedAgain(t *testing.T) {
	f := newInstallFx(t)
	c := f.mutantStale(f.state().Revision)
	if err := f.s.repl.Apply(c); !errors.Is(err, replica.ErrConflict) {
		t.Fatalf("fixture invalid: %v", err)
	}
	state, marks, cutoff := f.canonical(f.state()), f.mutantMarks(), f.s.staleCutoff()
	replay := func(label string, m *replicatedControl) {
		t.Helper()
		if err := m.Apply(c); !errors.Is(err, replica.ErrConflict) {
			t.Fatalf("%s: a replayed stale command answered %v, want replica.ErrConflict", label, err)
		}
		if f.canonical(f.state()) != state || f.mutantMarks() != marks || f.s.staleCutoff() != cutoff {
			t.Fatalf("%s: a replayed stale command changed the state or the watermarks", label)
		}
	}
	replay("replay", f.s.repl)
	replay("second replay", f.s.repl)
	f.reopen()
	replay("replay after a restart", &replicatedControl{store: f.s})
}

// A command is rejected when its expected revision is not the committed one, in either direction.
func TestMutantACommandExpectingAFutureRevisionIsRejectedToo(t *testing.T) {
	f := newInstallFx(t)
	before, rev := f.canonical(f.state()), f.state().Revision
	c := f.mutantEntry(rev+1, rev, func(st *State) { st.Quotas = map[string]model.QuotaState{"future:cmd": {MaxBytes: 9}} })
	if err := f.s.repl.Apply(c); !errors.Is(err, replica.ErrConflict) {
		t.Fatalf("a command that expects a later revision answered %v, want replica.ErrConflict", err)
	}
	if f.canonical(f.state()) != before {
		t.Fatal("a command that expects a later revision replaced the committed state")
	}
}

// A rejected command still takes the application slot the group stamped on it: the state's revision
// follows the group's application cursor and nothing else about the state changes.
func TestMutantARejectedCommandMovesTheRevisionToItsApplicationSlot(t *testing.T) {
	f := newInstallFx(t)
	rev := f.state().Revision
	want := f.state()
	want.Revision = rev + 1
	c := f.mutantStale(rev + 1)
	if err := f.s.repl.Apply(c); !errors.Is(err, replica.ErrConflict) {
		t.Fatalf("a stale command in a later application slot answered %v, want replica.ErrConflict", err)
	}
	if got := f.canonical(f.state()); got != f.canonical(want) {
		t.Fatalf("the state after a rejected command in slot %d is not the old state at that revision:\n got  %.300s\n want %.300s", rev+1, got, f.canonical(want))
	}
	if marks := f.mutantMarks(); marks[1] != uint64(rev)+1 {
		t.Fatalf("application watermark = %d, want %d", marks[1], rev+1)
	}
}

// The machine verifies what the group hands it: a replay of the last applied command changes nothing,
// one that carries a different state at the same revision is corrupt (never accepted), and a command
// that skips a replica index is corrupt and applies nothing.
func TestMutantTheMachineVerifiesReplaysAndRefusesIndexGaps(t *testing.T) {
	f := newInstallFx(t)
	rev := f.state().Revision
	good := f.mutantEntry(rev, rev+1, func(st *State) { st.Quotas = map[string]model.QuotaState{"good:cmd": {MaxBytes: 5}} })
	if err := f.s.repl.Apply(good); err != nil {
		t.Fatalf("a command that expects the committed revision was refused: %v", err)
	}
	applied, marks := f.canonical(f.state()), f.mutantMarks()
	if marks[0] != good.Index || f.state().Quotas["good:cmd"].MaxBytes != 5 {
		t.Fatalf("fixture invalid: the good command did not apply: %v", marks)
	}
	if err := f.s.repl.Apply(good); err != nil {
		t.Fatalf("a replay of the last applied command answered %v", err)
	}
	if f.canonical(f.state()) != applied || f.mutantMarks() != marks {
		t.Fatal("a replay of the last applied command changed the state or the watermarks")
	}
	diverged := f.mutantEntry(rev, rev+1, func(st *State) { st.Quotas = map[string]model.QuotaState{"good:cmd": {MaxBytes: 6}} })
	diverged.Index, diverged.Entry.ID = good.Index, good.Entry.ID
	if err := f.s.repl.Apply(diverged); mutantCode(err) != model.Corrupt {
		t.Fatalf("a replay that carries another state at the same revision answered %v, want corrupt", err)
	}
	next := f.mutantEntry(rev+1, rev+2, func(st *State) { st.Quotas = map[string]model.QuotaState{"gap:cmd": {MaxBytes: 7}} })
	next.Index += 3
	if err := f.s.repl.Apply(next); mutantCode(err) != model.Corrupt {
		t.Fatalf("a command that skips replica indexes answered %v, want corrupt", err)
	}
	if f.canonical(f.state()) != applied || f.mutantMarks() != marks {
		t.Fatal("a refused command changed the state or the watermarks")
	}
}

// A command of another installation is never taken, stale or not.
func TestMutantACommandOfAnotherInstallationIsCorruptNotConflicting(t *testing.T) {
	f := newInstallFx(t)
	before, rev := f.canonical(f.state()), f.state().Revision
	c := f.mutantEntry(rev-1, rev, func(st *State) { st.Installation = model.ID{0xee, 0x01} })
	if err := f.s.repl.Apply(c); mutantCode(err) != model.Corrupt {
		t.Fatalf("a stale command of another installation answered %v, want corrupt", err)
	}
	if f.canonical(f.state()) != before || f.mutantMeta("rejected:"+c.Entry.ID.String()) != nil {
		t.Fatal("a command of another installation left a trace")
	}
}
