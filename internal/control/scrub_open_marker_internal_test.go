// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/model"
)

// The control bucket's local_scrub key says that a build with the marker has seen this file.
// Open writes it once into every file it opens or creates, so a control.db written before the
// marker existed is marked owed whatever its log names (its own free pages may hold a payload
// and the replicated log is not a complete memory of the erasures it applied); a file that
// already has the key is never rewritten. These tests pin that rule, and that the group's first
// open of a seeded replica installs the seed over itself without marking the file.

// zeroMarker is the stored value of a settled key with generation 0.
var zeroMarker = make([]byte, 9)

// dropMarker deletes the marker key, as a build before the marker would have left the file. The
// rule acts only at Open, so tests restart the store after it.
func (f *installFx) dropMarker() {
	f.t.Helper()
	if err := f.s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("control")).Delete(localScrubKey) }); err != nil {
		f.t.Fatal(err)
	}
	if f.rawMarker() != nil || f.local() != (localScrub{}) {
		f.t.Fatal("fixture invalid: the marker key is still there")
	}
}

// A control.db written by a build before the marker, which applied an erasure whose replicated
// log already carries the leader's scrubbed audit, holds the erased payload in its own free pages
// and nothing says it was ever scrubbed. Opening it under this build marks it owed; one scrub
// clears the debt and the bytes; a restart keeps it cleared and a second Open does not owe it
// again (the key is there).
func TestAPreMarkerFileWhoseLogNamesAnErasureIsMarkedOwedAtOpen(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(true) // erasing audit + scrubbed audit: the log owes nothing by itself
	f.dropMarker()
	if len(owedScrubs(f.state().Audits)) != 0 {
		t.Fatal("fixture invalid: the log owes a scrub by itself")
	}
	hits := f.canaryHits()
	if hits == 0 {
		t.Fatal("fixture invalid: control.db holds no payload")
	}
	f.reopen() // the first start under the new build
	got := f.s.ResidualStores()
	if hits != 0 && !slices.Contains(got, ResidualControlState) {
		t.Errorf("FALSE CLEAN (upgrade gap): a pre-marker file that applied an erasure, never scrubbed, with %d payload copies in its own control.db, reports %v", hits, got)
	}
	owed := f.local()
	if !owed.owed || owed.generation == 0 {
		t.Fatalf("Open did not mark the pre-marker file owed under a generation: %+v", owed)
	}
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.owesState() || f.local().owed || f.canaryHits() != 0 {
		t.Fatalf("one scrub did not clear the debt and the bytes: %v %+v hits=%d", f.s.ResidualStores(), f.local(), f.canaryHits())
	}
	settled := f.rawMarker()
	for range 2 {
		f.reopen()
		if f.owesState() || f.local().owed {
			t.Fatalf("a restart after the scrub owes it again: %v %+v", f.s.ResidualStores(), f.local())
		}
		if !bytes.Equal(f.rawMarker(), settled) {
			t.Fatalf("Open rewrote a settled marker: %x then %x", settled, f.rawMarker())
		}
		if f.canaryHits() != 0 {
			t.Fatal("a restart brought the erased payload back")
		}
	}
}

// A pre-marker file whose log names no erasure is owed too: the log is not a complete memory of
// the erasures the file applied (see the next test), so nothing but a scrub can show that its
// free pages hold no payload. One scrub clears it, it holds nothing to clear in this fixture,
// and no later Open owes it again (the key stays).
func TestAPreMarkerFileWhoseLogNamesNoErasureIsOwedOneScrubToo(t *testing.T) {
	f := newInstallFx(t)
	if namesErasure(f.state().Audits) {
		t.Fatal("fixture invalid: the log names an erasure")
	}
	f.dropMarker()
	f.reopen()
	owed := f.local()
	if !owed.owed || owed.generation == 0 || !f.owesState() {
		t.Fatalf("Open did not mark a keyless file owed: %+v %v", owed, f.s.ResidualStores())
	}
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	settled := f.rawMarker()
	if f.owesState() || f.local().owed {
		t.Fatalf("one scrub did not clear the debt: %v %+v", f.s.ResidualStores(), f.local())
	}
	for range 2 {
		f.reopen()
		if f.owesState() || f.local().owed || !bytes.Equal(f.rawMarker(), settled) {
			t.Fatalf("a later Open owes or rewrote the settled key: %x then %x %v", settled, f.rawMarker(), f.s.ResidualStores())
		}
	}
}

// A control.db that applied an erasure (the payload moves to its free pages) and then took an
// install whose log names no erasure, from a build before the marker (restore with owe=false,
// the branch OpenSeed itself uses), holds the payload under a log that says nothing. A review
// reproduced a CLEAN receipt for it after Open (24 payload copies, settled key). Open now owes
// every keyless file, so the receipt names control_state and one scrub zeroes the bytes.
func TestAPreMarkerFileWhoseInstallDroppedTheErasingAuditIsStillOwedAtOpen(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(false) // the erasing audit is in the log, unsettled
	f.dropMarker()
	lineage := f.leader(3, false, false)
	lineage.Audits, lineage.Deletions = nil, nil
	if namesErasure(lineage.Audits) || len(owedScrubs(lineage.Audits)) != 0 {
		t.Fatal("fixture invalid: the lineage log names an erasure")
	}
	if err := f.s.repl.restore(f.snapshot(lineage), f.s.repl.Applied(), false); err != nil {
		t.Fatalf("the unmarked install failed: %v", err)
	}
	if f.rawMarker() != nil {
		t.Fatal("fixture invalid: the install wrote the marker key, so this is not a pre-marker file")
	}
	hits := f.canaryHits()
	if hits == 0 {
		t.Fatal("fixture invalid: the erasure left no copy of the payload in the file")
	}
	f.reopen() // the first start under this build
	if got := f.s.ResidualStores(); !slices.Contains(got, ResidualControlState) {
		t.Fatalf("FALSE CLEAN: a pre-marker file whose install dropped the erasing audit holds %d payload copies and reports %v", f.canaryHits(), got)
	}
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.owesState() || f.local().owed || f.canaryHits() != 0 {
		t.Fatalf("one scrub did not clear the debt and the bytes: %v %+v hits=%d", f.s.ResidualStores(), f.local(), f.canaryHits())
	}
}

// An existing key is never rewritten by Open: a marker that is owed stays owed under its own
// generation (and the bytes in the free pages stay covered by it), a settled one stays settled
// even though the log names an erasure.
func TestOpenNeverRewritesAnExistingMarker(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(true)
	owedRaw, owed := f.rawMarker(), f.local()
	if !owed.owed || owed.generation == 0 {
		t.Fatalf("fixture invalid: %+v", owed)
	}
	for range 2 {
		f.reopen()
		if !bytes.Equal(f.rawMarker(), owedRaw) || f.local() != owed {
			t.Fatalf("Open rewrote an owed marker: %x %+v then %x %+v", owedRaw, owed, f.rawMarker(), f.local())
		}
	}
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	settledRaw, settled := f.rawMarker(), f.local()
	if settled.owed || settled.generation != owed.generation || bytes.Equal(settledRaw, zeroMarker) {
		t.Fatalf("fixture invalid: the scrub did not settle the marker under its generation: %+v", settled)
	}
	for range 2 {
		f.reopen()
		if !bytes.Equal(f.rawMarker(), settledRaw) || f.local() != settled || f.owesState() {
			t.Fatalf("Open rewrote a settled marker: %x %+v then %x %+v %v", settledRaw, settled, f.rawMarker(), f.local(), f.s.ResidualStores())
		}
	}
}

// A file that Open creates carries the settled key from the start, and so does one that
// OpenSeed creates, even when the seed's log names an erasure: a later Open must not mark them.
func TestAFileCreatedByOpenOrOpenSeedCarriesTheSettledKey(t *testing.T) {
	fresh := t.TempDir()
	s, err := Open(fresh)
	if err != nil {
		t.Fatal(err)
	}
	rawOf := func(s *Store) []byte {
		t.Helper()
		var out []byte
		if err := s.db.View(func(tx *bolt.Tx) error {
			out = slices.Clone(tx.Bucket([]byte("control")).Get(localScrubKey))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := rawOf(s); !bytes.Equal(got, zeroMarker) {
		t.Fatalf("a created control.db has no settled key: %x", got)
	}
	s.Close()

	f := newInstallFx(t)
	f.erasedByTheLeader(true) // the seed's log names an erasure
	seed, _, err := f.s.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	seeded, err := OpenSeed(dir, seed)
	if err != nil {
		t.Fatal(err)
	}
	if got := rawOf(seeded); !bytes.Equal(got, zeroMarker) {
		t.Fatalf("a seeded control.db has no settled key: %x", got)
	}
	seeded.Close()
	// Without the key the next Open would find a log naming an erasure and mark the file.
	for range 2 {
		again, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		_, local, err := again.scrubState()
		raw, owes := rawOf(again), slices.Contains(again.ResidualStores(), ResidualControlState)
		again.Close()
		if err != nil || local != (localScrub{}) || owes || !bytes.Equal(raw, zeroMarker) {
			t.Fatalf("a later Open marked a seeded file that never held a payload: %+v %x %v %v", local, raw, owes, err)
		}
	}
}

// seededReplica seeds a new control.db from a node whose log names an erasure and starts the
// control group on it, as every production bootstrap does (appcore and backup.installControl call
// OpenSeed and then EnableSingle or EnableReplication). The group's open installs the seed's own
// snapshot through Restore, because the file's watermark is behind the seed's index.
func seededReplica(t *testing.T) (*Store, controlSnapshot) {
	t.Helper()
	f := newInstallFx(t)
	f.erasedByTheLeader(true) // the log names the erasure and owes nothing itself
	seed, _, err := f.s.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	seeded, err := OpenSeed(dir, seed)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { seeded.Close() })
	if _, local, err := seeded.scrubState(); err != nil || local != (localScrub{}) {
		t.Fatalf("fixture invalid: OpenSeed marked the file: %+v %v", local, err)
	}
	if err = seeded.EnableSingle(context.Background(), filepath.Join(dir, "raft-control")); err != nil {
		t.Fatalf("EnableSingle: %v", err)
	}
	var parsed controlSnapshot
	if err = json.Unmarshal(seed, &parsed); err != nil {
		t.Fatal(err)
	}
	return seeded, parsed
}

// A freshly SEEDED replica never held anything but the seed's already erased state. When its
// group opens, replica.Open installs the seed's own snapshot through Restore (the file's watermark
// is below the seed's index); that install replaces the state with the same decoded one, frees
// only pages that hold that same state, and must leave the file unmarked.
func TestASeededReplicaStaysCleanWhenItsGroupInstallsTheSeed(t *testing.T) {
	seeded, parsed := seededReplica(t)
	_, local, err := seeded.scrubState()
	if err != nil {
		t.Fatal(err)
	}
	got := seeded.ResidualStores()
	// Pin WHY the install happened and that it replaced nothing: the state the group installed
	// is the state the file already held.
	seedCanon, err := model.CanonicalJSON(parsed.State)
	if err != nil {
		t.Fatal(err)
	}
	st, err := seeded.localState()
	if err != nil {
		t.Fatal(err)
	}
	nowCanon, err := model.CanonicalJSON(st)
	if err != nil {
		t.Fatal(err)
	}
	if string(seedCanon) != string(nowCanon) {
		t.Fatalf("the group-open install changed the seeded state: %s -> %s", seedCanon, nowCanon)
	}
	if local.owed {
		t.Errorf("FALSE DIRTY: a control.db that never held anything but the seed's already-erased state owes a scrub once the group installs the seed's snapshot at Open: marker=%+v receipt=%v", local, got)
	}
	if local != (localScrub{}) || slices.Contains(got, ResidualControlState) {
		t.Errorf("the seeded file is marked after its group opened: %+v %v", local, got)
	}
}

// The exemption is identity only. A second install over the seeded replica that differs from the
// state the file holds in a single field, in any part of the state, still owes a scrub (the
// installed log names an erasure and the file cannot tell what the replaced pages held), while an
// install of the identical state, however often, does not.
func TestAnInstallOverASeededReplicaOfADifferentStateStillOwes(t *testing.T) {
	change := map[string]func(*State){
		"revision": func(st *State) { st.Revision++ },
		"audit": func(st *State) {
			st.Audits = append(st.Audits, model.ControlAudit{ID: model.NewID(), Principal: model.ID{0xbb}, Action: "noop.audit", Outcome: model.AuditAllowed})
		},
		"quota": func(st *State) { st.Quotas = map[string]model.QuotaState{"one:byte": {MaxBytes: 1}} },
		"last":  func(st *State) { st.DeliveryBooks = map[string]json.RawMessage{"x": json.RawMessage(`1`)} },
	}
	for name, mutate := range change {
		t.Run(name, func(t *testing.T) {
			seeded, _ := seededReplica(t)
			install := func(st State) {
				t.Helper()
				raw, err := json.Marshal(controlSnapshot{State: st, Keys: map[string][]byte{}, Metadata: map[string][]byte{}})
				if err != nil {
					t.Fatal(err)
				}
				if err = seeded.repl.Restore(raw, seeded.repl.Applied()); err != nil {
					t.Fatalf("Restore: %v", err)
				}
			}
			current, err := seeded.localState()
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				install(current) // identical, again and again: nothing replaced, nothing owed
				if _, local, err := seeded.scrubState(); err != nil || local != (localScrub{}) {
					t.Fatalf("an install of the identical state marked the file: %+v %v", local, err)
				}
			}
			different := current
			mutate(&different)
			if sameState(current, different) {
				t.Fatal("fixture invalid: the changed state is the same state")
			}
			install(different)
			if _, local, err := seeded.scrubState(); err != nil || !local.owed || local.generation == 0 {
				t.Fatalf("an install of a different state over a clean file whose log names an erasure owes nothing: %+v %v", local, err)
			}
			if !slices.Contains(seeded.ResidualStores(), ResidualControlState) {
				t.Fatalf("FALSE CLEAN: the receipt does not name the debt: %v", seeded.ResidualStores())
			}
		})
	}
}

// The identical-state exemption needs the CURRENT log to owe nothing by itself: a file whose
// marker is settled but whose own log still holds an erasing audit nothing settled owes the
// scrub that audit names, and an install that replaces nothing does not change that.
func TestAnIdenticalInstallOverAFileWhoseLogStillOwesAScrubStillOwes(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(false) // the erasing audit has no scrubbed audit after it
	if err := f.s.db.Update(func(tx *bolt.Tx) error {
		return writeLocalScrub(tx.Bucket([]byte("control")), localScrub{generation: 7}) // settled by hand
	}); err != nil {
		t.Fatal(err)
	}
	if got := f.local(); got.owed || got.generation != 7 || f.rawMarker() == nil || len(owedScrubs(f.state().Audits)) == 0 {
		t.Fatalf("fixture invalid: marker=%+v log_owed=%d", got, len(owedScrubs(f.state().Audits)))
	}
	f.installInSync(f.state()) // the very state the file holds
	if got := f.local(); !got.owed || got.generation == 7 {
		t.Fatalf("an identical install over a file whose log owes a scrub left its marker settled: %+v", got)
	}
}

// An install of the identical state over a file whose marker is owed leaves it owed: the
// exemption needs a settled marker. The install frees pages a scrub that started before it may
// already have passed, so it is covered by a new generation like any other install over an owed
// file, and a scrub that started at the old one clears nothing.
func TestAnIdenticalInstallOverAnOwedFileLeavesItOwed(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(true) // the log owes nothing: only the marker does
	owed := f.local()
	if !owed.owed || len(owedScrubs(f.state().Audits)) != 0 {
		t.Fatalf("fixture invalid: %+v", owed)
	}
	f.installInSync(f.state())
	after := f.local()
	if !after.owed || !f.owesState() {
		t.Fatalf("an identical install settled an owed marker: %+v %v", after, f.s.ResidualStores())
	}
	if after.generation <= owed.generation {
		t.Fatalf("an identical install over an owed file did not take a new generation: %+v then %+v", owed, after)
	}
	if err := f.s.settleLocalScrub(owed.generation); err != nil {
		t.Fatal(err)
	}
	if !f.local().owed {
		t.Fatalf("a scrub that started before the install cleared the debt it did not cover: %+v", f.local())
	}
}

// The exemption trusts the marker, so it needs the marker key: a file without it (Open writes
// it into every file, so this is a file that no build with the marker has opened) is not known
// to owe nothing, and an install of its own state over it, whose log names an erasure, owes.
func TestAnIdenticalInstallOverAFileWithoutTheMarkerKeyOwes(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(true) // the log names an erasure and owes nothing itself
	f.dropMarker()
	f.installInSync(f.state())
	if got := f.local(); !got.owed || !f.owesState() {
		t.Fatalf("an identical install over a file with no marker key left it unmarked: %+v %v", got, f.s.ResidualStores())
	}
}
