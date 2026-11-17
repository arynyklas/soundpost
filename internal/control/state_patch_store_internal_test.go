// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"errors"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

// StatePatchStatsForTest is how many commands the store proposed as state patches and the bytes of
// their payloads.
func (s *Store) StatePatchStatsForTest() (commands, payloadBytes uint64) {
	return s.statePatches.Load(), s.statePatchBytes.Load()
}

// patchEntry is a committed state patch for the machine of f at the next replica index, from the
// current state to the state build makes of it, expecting revision expected.
func (f *installFx) patchEntry(expected, cursor model.Revision, build func(*State)) replica.CommittedEntry {
	f.t.Helper()
	oldRaw := mustMarshal(f.t, f.state())
	st := f.state()
	build(&st)
	st.Revision = expected + 1
	keys, err := f.s.replicaKeyFiles()
	if err != nil {
		f.t.Fatal(err)
	}
	payload, err := patchCommand(oldRaw, expected, &st, keys)
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

// A command committed as a patch leaves exactly the state the whole-state command of the same
// transition leaves: same revisions, same AuthorityRevision, same revision clock, same books, over
// random transitions and a clock that moves by random steps. Two stores run the same sequence of
// real transitions through their real groups, one per path.
func TestStatePatchEqualsReplacement(t *testing.T) {
	whole, patch := newInstallFx(t), newInstallFx(t)
	whole.s.SetStatePatchGate(func() bool { return false })
	patch.s.SetStatePatchGate(func() bool { return true })
	now := int64(2_000)
	clock := func() time.Time { return time.Unix(0, now) }
	whole.s.SetClock(clock)
	patch.s.SetClock(clock)
	// Both stores start from the same state: same stamps (the fixtures were built at two moments).
	for _, f := range []*installFx{whole, patch} {
		if err := f.s.Update(f.ctx, func(st *State) error {
			st.RevisionClock = []model.RevisionStamp{{Revision: 1, At: 1_000}}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	const steps = 150
	for i := range steps {
		now += int64(i%4) * int64(time.Minute) * 30
		transition := func(st *State) error {
			r := rand.New(rand.NewPCG(uint64(i), 7))
			for range 1 + r.IntN(4) {
				mutateState(r, st)
			}
			return nil
		}
		if err := whole.s.Update(whole.ctx, transition); err != nil {
			t.Fatalf("whole-state command %d: %v", i, err)
		}
		if err := patch.s.Update(patch.ctx, transition); err != nil {
			t.Fatalf("patch command %d: %v", i, err)
		}
		a, b := whole.state(), patch.state()
		a.Installation, b.Installation = model.ID{0x50}, model.ID{0x50} // what differs between the two fixtures:
		b.BootstrapHash = a.BootstrapHash                               // random per store
		if whole.canonical(a) != patch.canonical(b) {
			var ma, mb map[string]json.RawMessage
			_ = json.Unmarshal([]byte(whole.canonical(a)), &ma)
			_ = json.Unmarshal([]byte(patch.canonical(b)), &mb)
			var differing []string
			for k := range ma {
				if string(ma[k]) != string(mb[k]) {
					differing = append(differing, k+": "+string(ma[k])[:min(len(ma[k]), 160)]+" | "+string(mb[k])[:min(len(mb[k]), 160)])
				}
			}
			t.Fatalf("command %d: the patch left a state that differs from the whole-state command's in %v", i, differing)
		}
		if a.AuthorityRevision != b.AuthorityRevision || a.Revision != b.Revision {
			t.Fatalf("command %d: revision %d/%d authority %d/%d", i, a.Revision, b.Revision, a.AuthorityRevision, b.AuthorityRevision)
		}
	}
	if n, _ := patch.s.StatePatchStatsForTest(); n != steps+1 { // the steps and the stamp reset before them
		t.Fatalf("the patch store proposed %d patches, want %d", n, steps+1)
	}
	if n, _ := whole.s.StatePatchStatsForTest(); n != 0 {
		t.Fatalf("the store with the gate closed proposed %d patches", n)
	}
}

// The gate decides at every update, and a store without one proposes none.
func TestStatePatchGateDecidesAtEveryUpdate(t *testing.T) {
	f := newInstallFx(t)
	touch := func(st *State) error { st.BootstrapHash += "x"; return nil }
	if f.s.StatePatch() {
		t.Fatal("a store without a gate proposes patches: an older peer cannot decode them")
	}
	if err := f.s.Update(f.ctx, touch); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.s.StatePatchStatsForTest(); n != 0 {
		t.Fatalf("no gate: %d patches", n)
	}
	var open bool
	f.s.SetStatePatchGate(func() bool { return open })
	if err := f.s.Update(f.ctx, touch); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.s.StatePatchStatsForTest(); n != 0 {
		t.Fatalf("gate closed: %d patches", n)
	}
	open = true
	if err := f.s.Update(f.ctx, touch); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.s.StatePatchStatsForTest(); n != 1 {
		t.Fatalf("gate open: %d patches, want 1", n)
	}
	open = false
	if err := f.s.Update(f.ctx, touch); err != nil {
		t.Fatal(err)
	}
	f.s.SetStatePatchGate(func() bool { return true })
	f.s.SetStatePatchGate(nil)
	if f.s.StatePatch() {
		t.Fatal("removing the gate must close it")
	}
	if n, _ := f.s.StatePatchStatsForTest(); n != 1 {
		t.Fatalf("gate closed again: %d patches in total, want the 1 of the open gate", n)
	}
}

// A patch that expects an older (or a newer) revision is rejected exactly like a stale replacement:
// nothing is replaced, the rejection is recorded and a replay answers it again.
func TestStatePatchWithAStaleExpectedRevisionIsRejected(t *testing.T) {
	f := newInstallFx(t)
	before := f.canonical(f.state())
	rev := f.state().Revision
	for _, expected := range []model.Revision{rev - 1, rev + 1} {
		c := f.patchEntry(expected, rev, func(st *State) { f.dropPayload(st); st.BootstrapHash = "stale" })
		if err := f.s.repl.Apply(c); !errors.Is(err, replica.ErrConflict) {
			t.Fatalf("a patch expecting %d at revision %d answered %v, want replica.ErrConflict", expected, rev, err)
		}
		if got := f.canonical(f.state()); got != before {
			t.Fatalf("a stale patch (expected %d) changed the state", expected)
		}
		if err := f.s.repl.Apply(c); !errors.Is(err, replica.ErrConflict) {
			t.Fatalf("a replay of the rejected patch answered %v, want replica.ErrConflict", err)
		}
	}
}

// A replay of a patch the machine already applied is verified against the committed state: it
// passes while the state still holds what the patch wrote, and a state that does not is corrupt, as
// a replacement's replay compares the state it carries.
func TestStatePatchReplayIsVerifiedAgainstTheCommittedState(t *testing.T) {
	f := newInstallFx(t)
	rev := f.state().Revision
	c := f.patchEntry(rev, rev+1, func(st *State) { st.BootstrapHash = "applied-once"; f.dropPayload(st) })
	if err := f.s.repl.Apply(c); err != nil {
		t.Fatal(err)
	}
	if got := f.state(); got.Revision != rev+1 || got.BootstrapHash != "applied-once" {
		t.Fatalf("the patch left %d %q", got.Revision, got.BootstrapHash)
	}
	if err := f.s.repl.Apply(c); err != nil {
		t.Fatalf("the replay of an applied patch: %v", err)
	}
	// The same revision with other contents: the committed state is not the patch's.
	f.mutantWrite(func(b *bolt.Bucket) error {
		st := f.state()
		st.BootstrapHash = "tampered"
		return putState(b, mustMarshal(f.t, st))
	})
	if err := f.s.repl.Apply(c); mutantCode(err) != model.Corrupt {
		t.Fatalf("the replay against a state that is not the patch's answered %v, want corrupt", err)
	}
	// A state ahead of the patch is not compared: later commands changed what the patch wrote.
	f.mutantWrite(func(b *bolt.Bucket) error {
		st := f.state()
		st.Revision += 3
		st.BootstrapHash = "later"
		return putState(b, mustMarshal(f.t, st))
	})
	if err := f.s.repl.Apply(c); err != nil {
		t.Fatalf("the replay against a state ahead of the patch: %v", err)
	}
}

// A patch names the bytes it was computed against, not only their revision. After a stale-reject
// revision bump (Apply, replicated.go) two voters can hold different bytes at one revision; a patch
// that only checks the revision commits on both, writes only the members it names and so keeps the
// difference for good, where a replacement would have rewritten it. The voter that holds other bytes
// than the proposer read refuses the patch (corrupt: it has to be resynchronised by a snapshot), and
// the voter that holds the bytes commits it.
func TestStatePatchOfOneLineageIsRefusedByAVoterHoldingAnother(t *testing.T) {
	f := newInstallFx(t)
	lineageA := f.state()
	rev := lineageA.Revision
	c := f.patchEntry(rev, rev+1, func(st *State) { st.BootstrapHash = "patched"; f.dropPayload(st) })

	// Voter B: the same revision and installation, a member the patch does not name differs.
	f.mutantWrite(func(b *bolt.Bucket) error {
		st := f.state()
		st.BearerHashKey = "lineage-b"
		return putState(b, mustMarshal(f.t, st))
	})
	before, marks := f.canonical(f.state()), f.mutantMarks()
	if err := f.s.repl.Apply(c); mutantCode(err) != model.Corrupt {
		t.Fatalf("a patch computed against other bytes of the same revision answered %v on the voter holding the other bytes, want corrupt; it left BootstrapHash %q BearerHashKey %q at revision %d",
			err, f.state().BootstrapHash, f.state().BearerHashKey, f.state().Revision)
	}
	if got := f.canonical(f.state()); got != before {
		t.Fatal("the refused patch changed the voter's state")
	}
	if f.mutantMarks() != marks {
		t.Fatal("the refused patch moved the voter's watermarks")
	}

	// Voter A: the bytes the patch was computed against.
	f.mutantWrite(func(b *bolt.Bucket) error { return putState(b, mustMarshal(f.t, lineageA)) })
	if err := f.s.repl.Apply(c); err != nil {
		t.Fatalf("the voter holding the bytes the patch was computed against: %v", err)
	}
	if got := f.state(); got.Revision != rev+1 || got.BootstrapHash != "patched" || got.BearerHashKey != lineageA.BearerHashKey {
		t.Fatalf("the patch left %d %q %q", got.Revision, got.BootstrapHash, got.BearerHashKey)
	}
}

// The leader refuses a proposal before it is committed: one without a base digest is invalid, one
// computed against other bytes than the leader holds is stale (the proposer reads again), the one
// computed against the leader's bytes passes.
func TestStatePatchProposalNamesTheLeadersBytes(t *testing.T) {
	f := newInstallFx(t)
	rev := f.state().Revision
	c := f.patchEntry(rev, rev+1, func(st *State) { st.BootstrapHash = "patched"; f.dropPayload(st) })
	entry := c.Entry
	entry.ApplicationIndex = uint64(rev + 1)
	if err := f.s.repl.Validate(f.ctx, entry); err != nil {
		t.Fatalf("a proposal computed against the leader's bytes: %v", err)
	}
	decoded, err := decodeControlCommand(entry.Payload)
	if err != nil || decoded.patch == nil || len(decoded.patch.Base) != 64 {
		t.Fatalf("the proposal carries no base digest: %v %+v", err, decoded.patch)
	}
	bare := *decoded.patch
	bare.Base = ""
	noBase := entry
	noBase.Payload = mustMarshal(t, statePatchCommand{StatePatch: bare})
	if err := f.s.repl.Validate(f.ctx, noBase); mutantCode(err) != model.Invalid {
		t.Fatalf("a proposal without a base digest answered %v, want invalid", err)
	}
	f.mutantWrite(func(b *bolt.Bucket) error {
		st := f.state()
		st.BearerHashKey = "lineage-b"
		return putState(b, mustMarshal(f.t, st))
	})
	if err := f.s.repl.Validate(f.ctx, entry); mutantCode(err) != model.Stale {
		t.Fatalf("a proposal computed against other bytes answered %v, want stale", err)
	}
}

// The base digest covers the maps of records too: a voter whose record map differs at the same
// revision (a record the proposer's bytes do not hold) refuses a patch that does not name that
// record, so the difference is detected at the first patch instead of being built on for good.
func TestStatePatchOfOneLineageIsRefusedByAVoterWhoseRecordMapDiffers(t *testing.T) {
	f := newInstallFx(t)
	rev := f.state().Revision
	c := f.patchEntry(rev, rev+1, func(st *State) { st.BootstrapHash = "patched" })
	f.mutantWrite(func(b *bolt.Bucket) error {
		st := f.state()
		if st.IncidentBooks == nil {
			st.IncidentBooks = map[string]json.RawMessage{}
		}
		st.IncidentBooks["lineage:b:record"] = json.RawMessage(`{"n":1}`)
		return putState(b, mustMarshal(f.t, st))
	})
	before := f.canonical(f.state())
	if err := f.s.repl.Apply(c); mutantCode(err) != model.Corrupt {
		t.Fatalf("a patch computed against other record maps of the same revision answered %v, want corrupt; the voter left %q at revision %d", err, f.state().BootstrapHash, f.state().Revision)
	}
	if f.canonical(f.state()) != before {
		t.Fatal("the refused patch changed the voter's state")
	}
}

// After an erasure pass rewrote a retained command, the voter that applies the rewritten log holds
// maps that differ, by design, from the ones the proposer read: every later patch of the pass loses
// its base (clearPatchBase), a replacement and a patch with no base are not touched.
func TestClearPatchBaseDropsOnlyTheBase(t *testing.T) {
	f := newInstallFx(t)
	rev := f.state().Revision
	c := f.patchEntry(rev, rev+1, func(st *State) { st.BootstrapHash = "patched" })
	out, changed, err := clearPatchBase(c.Entry.Payload)
	if err != nil || !changed {
		t.Fatalf("a patch with a base: changed=%v err=%v", changed, err)
	}
	was, _ := decodeControlCommand(c.Entry.Payload)
	now, err := decodeControlCommand(out)
	if err != nil || now.patch == nil || now.patch.Base != "" || now.patch.Expected != was.patch.Expected || len(now.patch.Ops) != len(was.patch.Ops) {
		t.Fatalf("the rewritten patch: %v %+v", err, now.patch)
	}
	if again, changed, err := clearPatchBase(out); err != nil || changed || string(again) != string(out) {
		t.Fatalf("not idempotent: changed=%v err=%v", changed, err)
	}
	delta := f.deltaPayload(rev, 1, f.audit("export.chunk", 1))
	if same, changed, err := clearPatchBase(delta); err != nil || changed || string(same) != string(delta) {
		t.Fatalf("a delta was touched: changed=%v err=%v", changed, err)
	}
}
