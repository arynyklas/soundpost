// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/model"
)

// These tests attack the node-local scrub marker from the outside: they read the raw bytes of
// control.db, not only the receipt, and they run a real ScrubErased where the race is the point.

// rawFile is the whole control.db, free pages included.
func (f *installFx) rawFile() []byte {
	f.t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.dir, "control.db"))
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

// canaryHits is the number of copies of the payload canary anywhere in control.db.
func (f *installFx) canaryHits() int {
	f.t.Helper()
	return bytes.Count(f.rawFile(), []byte(installCanary))
}

// rawMarker is the stored value of the marker key, nil when the key is absent.
func (f *installFx) rawMarker() []byte {
	f.t.Helper()
	var out []byte
	if err := f.s.db.View(func(tx *bolt.Tx) error {
		out = slices.Clone(tx.Bucket([]byte("control")).Get(localScrubKey))
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// stateJSONOf is the state of a snapshot payload, re-encoded.
func stateJSONOf(t *testing.T, snap []byte) []byte {
	t.Helper()
	var parsed controlSnapshot
	if err := json.Unmarshal(snap, &parsed); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(parsed.State)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The marker is set by the applying commit. An immediate restart keeps it, the receipt still
// names control_state and the raw file (free pages included) still holds the payload; one
// local scrub ends all three, and afterwards the receipt is clean AND the raw file holds no
// canary.
func TestARestartBetweenTheMarkerAndTheScrubKeepsTheDebtUntilTheBytesAreZeroed(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(true) // the log owes nothing by itself: only the marker keeps it owed
	if set := f.local(); !set.owed {
		t.Fatalf("the applying commit left no marker: %+v", set)
	}
	f.reopen()
	if !f.local().owed || !f.owesState() {
		t.Fatalf("the restart dropped the marker/debt: %+v %v", f.local(), f.s.ResidualStores())
	}
	if f.canaryHits() == 0 {
		t.Fatal("invalid fixture: control.db holds no canary before the scrub")
	}
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatalf("ScrubErased: %v", err)
	}
	if f.owesState() {
		t.Errorf("FALSE DIRTY: the scrub ran and the receipt still names control_state: %v", f.s.ResidualStores())
	}
	if after := f.canaryHits(); after != 0 {
		t.Errorf("FALSE CLEAN: the receipt is clean while control.db still holds %d copies of the erased payload", after)
	}
	f.reopen()
	if f.owesState() || f.canaryHits() != 0 {
		t.Errorf("after restart post-scrub: receipt=%v hits=%d", f.s.ResidualStores(), f.canaryHits())
	}
}

// holdAReader opens a read transaction that closes on its own timer: it keeps a ScrubErased in
// its reader-deferral loop (40 attempts x 25 ms) while the writer lock stays free for the event
// the test lands mid-run (a bbolt writer's commit waits on an open reader's mmap lock only
// when the file has to grow).
func (f *installFx) holdAReader() {
	f.t.Helper()
	held := make(chan struct{})
	go func() {
		_ = f.s.db.View(func(tx *bolt.Tx) error {
			close(held)
			time.Sleep(400 * time.Millisecond)
			return nil
		})
	}()
	<-held
}

// An install lands WHILE a real ScrubErased runs: the marker advances under the scrub, and the
// scrub, which started at an older generation, must not clear the debt the install created.
func TestARealScrubInFlightDoesNotClearTheDebtAnInstallAddedMidRun(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(true) // the replicated log is settled by the leader's scrubbed audit
	started := f.local()
	if !started.owed || len(owedScrubs(f.state().Audits)) != 0 {
		t.Fatalf("invalid fixture: marker=%+v log_owed=%d", started, len(owedScrubs(f.state().Audits)))
	}
	f.holdAReader()
	done := make(chan error, 1)
	go func() { done <- f.s.ScrubErased(f.ctx) }()
	time.Sleep(150 * time.Millisecond) // the scrub is inside its retry loop
	f.install(f.leader(5, true, true)) // lands mid-run: a marker-only debt again
	mid := f.local()
	var err error
	select {
	case err = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the scrub did not return")
	}
	t.Logf("scrub err=%v started=%+v mid=%+v final=%+v receipt=%v hits=%d", err, started, mid, f.local(), f.s.ResidualStores(), f.canaryHits())
	if mid.generation == started.generation || !mid.owed {
		t.Fatalf("the mid-run install did not bump the marker: %+v then %+v", started, mid)
	}
	if !f.local().owed || !f.owesState() {
		t.Errorf("FALSE CLEAN: a scrub that started at generation %d cleared the debt of generation %d: marker=%+v receipt=%v",
			started.generation, mid.generation, f.local(), f.s.ResidualStores())
	}
	// The debt is not stuck: the scrub that runs after it covers the install.
	if err = f.s.ScrubErased(f.ctx); err != nil {
		t.Fatalf("the second scrub failed: %v", err)
	}
	if f.local().owed || f.owesState() {
		t.Errorf("FALSE DIRTY: the scrub that covered the install debt left it owed: marker=%+v receipt=%v", f.local(), f.s.ResidualStores())
	}
}

// As above, but the mid-run event is an applied erasing commit (a replayed or live erasure).
func TestARealScrubInFlightDoesNotClearTheDebtAnErasingCommitAddedMidRun(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(true)
	started := f.local()
	if !started.owed {
		t.Fatalf("invalid fixture: marker=%+v", started)
	}
	f.holdAReader()
	done := make(chan error, 1)
	go func() { done <- f.s.ScrubErased(f.ctx) }()
	time.Sleep(150 * time.Millisecond)
	if err := f.s.Update(f.ctx, func(st *State) error { // an erasure, replayed mid-run
		st.Audits = append(st.Audits, f.audit(controlErasedAction, 30))
		return nil
	}); err != nil {
		t.Fatalf("the mid-run erasure did not commit: %v", err)
	}
	mid := f.local()
	select {
	case err := <-done:
		if err != nil {
			t.Logf("scrub err=%v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the scrub did not return")
	}
	t.Logf("started=%+v mid=%+v final=%+v receipt=%v", started, mid, f.local(), f.s.ResidualStores())
	if mid.generation == started.generation || !mid.owed {
		t.Fatalf("the mid-run erasure did not bump the marker: %+v then %+v", started, mid)
	}
	if !f.local().owed || !f.owesState() {
		t.Errorf("FALSE CLEAN: the generation guard let a scrub of generation %d clear generation %d: marker=%+v receipt=%v",
			started.generation, mid.generation, f.local(), f.s.ResidualStores())
	}
}

// A dense canary spread across many pages of one large value: after a successful scrub the raw
// file holds no copy of it, whatever pages bbolt reallocated for the smaller state.
func TestAScrubLeavesNoCanaryBytesAnywhereInTheFile(t *testing.T) {
	f := newInstallFx(t)
	block := installCanary + strings.Repeat("-padding-padding-padding-padding-padding-padding-padding-padding-", 120)
	parts := make([]string, 40)
	for i := range parts {
		parts[i] = block
	}
	payload := strings.Join(parts, "")
	if err := f.s.Update(f.ctx, func(st *State) error {
		if st.OIDC == nil {
			st.OIDC = map[string]json.RawMessage{}
		}
		st.OIDC["scrub:big"] = json.RawMessage(`"` + payload + `"`)
		return nil
	}); err != nil {
		t.Fatalf("cannot seed the large value: %v", err)
	}
	before := f.canaryHits()
	if before < 40 {
		t.Fatalf("invalid fixture: control.db holds only %d copies of the dense canary", before)
	}
	if err := f.s.Update(f.ctx, func(st *State) error {
		delete(st.OIDC, "scrub:big")
		f.dropPayload(st)
		st.Deletions = f.finishedDeletion()
		st.Audits = append(st.Audits, f.audit(controlErasedAction, 10), f.audit(controlScrubbedAction, 12))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatalf("ScrubErased: %v", err)
	}
	if hits := f.canaryHits(); hits != 0 {
		t.Errorf("FALSE CLEAN: %d copies of the erased payload survive a scrub that reported success with receipt %v", hits, f.s.ResidualStores())
	}
}

// The marker must not enter replicated state, a snapshot payload, the seed, or anything a digest
// compares: two files that differ only in local debt agree on state and accept each other's
// snapshots.
func TestTheScrubMarkerIsInvisibleToDigestsSnapshotsAndSeeds(t *testing.T) {
	owing, plain := newInstallFx(t), newInstallFx(t)
	raw := owing.snapshot(owing.leader(0, true, true)) // the leader's snapshot: log settled
	for _, f := range []*installFx{owing, plain} {
		if err := f.s.repl.Restore(raw, f.s.repl.Applied()); err != nil {
			t.Fatal(err)
		}
	}
	if err := plain.s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("control")).Delete(localScrubKey) }); err != nil {
		t.Fatal(err)
	}
	if !owing.local().owed || plain.local() != (localScrub{}) {
		t.Fatalf("invalid fixture: owing=%+v plain=%+v", owing.local(), plain.local())
	}
	digest := func(f *installFx) string {
		canon, err := model.CanonicalJSON(f.state())
		if err != nil {
			t.Fatal(err)
		}
		return model.HashCanonical(canon).String()
	}
	if digest(owing) != digest(plain) {
		t.Errorf("the state digest differs between a file that owes and one that does not")
	}
	owSnap, err := owing.s.repl.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	clSnap, err := plain.s.repl.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(owSnap, localScrubKey) || bytes.Contains(clSnap, localScrubKey) {
		t.Errorf("a snapshot payload carries the marker")
	}
	if !bytes.Equal(stateJSONOf(t, owSnap), stateJSONOf(t, clSnap)) {
		t.Errorf("two files differing only in the marker cut different snapshot state bytes")
	}
	if err = plain.s.repl.VerifySnapshot(owSnap); err != nil {
		t.Errorf("a clean file refuses the snapshot of an owing one: %v", err)
	}
	if err = owing.s.repl.VerifySnapshot(clSnap); err != nil {
		t.Errorf("an owing file refuses the snapshot of a clean one: %v", err)
	}
	seed, _, err := owing.s.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(seed, localScrubKey) {
		t.Errorf("a seed carries the marker")
	}
	// The same replicated commit lands identically on both files.
	for _, f := range []*installFx{owing, plain} {
		if err = f.s.Update(f.ctx, func(st *State) error {
			st.Quotas = map[string]model.QuotaState{"marker:invisible": {MaxBytes: 3}}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if owing.canonical(owing.state()) != plain.canonical(plain.state()) {
		t.Errorf("the marker changed what a replicated commit computed")
	}
	if !owing.local().owed {
		t.Errorf("the owing file lost its debt")
	}
	if owing.s.repl.Applied() != plain.s.repl.Applied() {
		t.Errorf("the marker changed the applied watermark")
	}
}

// Every install of a log that names an erasure re-owes a file that was scrubbed a minute ago,
// because the audit log is append-only and the file cannot tell which erasure the installed state
// replaced pages for. That is an accepted cost, bounded to one scrub per install, and it is never
// a stuck debt: one ScrubErased clears it. An install of a log that names no erasure over a file
// that owes nothing owes nothing.
func TestAnInstallOverACleanFileWhoseLogNamesAnErasureOwesOneBoundedScrub(t *testing.T) {
	f := newInstallFx(t)
	f.erasedByTheLeader(true)
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.owesState() || f.canaryHits() != 0 {
		t.Fatal("invalid fixture: the file did not reach clean")
	}
	// A lineage that names no erasure: no marker.
	g := newInstallFx(t)
	g.install(g.leader(5, false, false))
	if g.owesState() || g.local() != (localScrub{}) {
		t.Errorf("FALSE DIRTY: an install naming no erasure over a file that owes nothing left a debt: %v %+v", g.s.ResidualStores(), g.local())
	}
	// A log that names an erasure, installed over a scrubbed clean file and over a DIFFERENT
	// state: re-owed (the accepted cost), then cleared by one scrub.
	f.installInSync(f.leader(3, true, true))
	reowed := f.local()
	if !reowed.owed || !f.owesState() {
		t.Fatalf("the erasure-naming install did not re-owe: %+v", reowed)
	}
	if err := f.s.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	if f.owesState() || f.local().owed {
		t.Errorf("FALSE DIRTY (stuck debt): the scrub after the re-owing install left the debt owed: %v %+v", f.s.ResidualStores(), f.local())
	}
	if f.canaryHits() != 0 {
		t.Errorf("the scrub after the install left %d copies of the payload", f.canaryHits())
	}
}
