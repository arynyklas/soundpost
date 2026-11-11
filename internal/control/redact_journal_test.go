// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
)

// raftHits lists the files of the control group's Raft directory that hold canary.
func (f *eraseFx) raftHits(canary string) []string {
	f.t.Helper()
	var out []string
	for _, h := range eraseFileHits(f.t, f.dir, canary) {
		if strings.HasPrefix(h, "raft-control/") {
			out = append(out, h)
		}
	}
	return out
}

// cutControl is the periodic snapshot an application cuts of the control group.
func (f *eraseFx) cutControl() {
	f.t.Helper()
	group := f.store.ReplicaGroup()
	cut, err := group.ReadIndex(f.ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err = group.CreateSnapshot(f.ctx, cut); err != nil {
		f.t.Fatal(err)
	}
	if _, err = group.CompactJournal(f.ctx); err != nil {
		f.t.Fatal(err)
	}
}

// Every control command carries the whole control state, so a retire-project deletion that
// erased a payload from the live state left it in the journal, the snapshot envelope and the
// retry table of the control Raft group. After the deletion and the redaction pass no file of the
// group holds it, and the receipt stops naming the journal.
func TestRetireProjectLeavesNoPayloadInTheControlRaftFiles(t *testing.T) {
	f := newEraseFx(t)
	const gone, kept = "CANARYJOURNAL0d2b86a7c41e90", "CANARYJKEPT51f0aa93c7de1b"
	f.seedAll(f.newSeed(f.project, gone), 50)
	f.seedAll(f.newSeed(f.otherProject, kept), 50)
	f.cutControl() // a snapshot cut before the deletion carries the payload in its envelope
	f.seedAll(f.newSeed(f.project, gone), 60)

	f.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})

	if f.stateHolds(gone) || len(controlDBHits(t, f.dir, gone)) != 0 {
		t.Fatalf("fixture invalid: the live state or control.db still holds the payload: %v", controlDBHits(t, f.dir, gone))
	}
	before := f.raftHits(gone)
	t.Logf("raft files holding the erased payload after the deletion saga: %v", before)
	if !contains(before, "raft-control/ready.wal") || !hasEnvelope(before) {
		t.Fatalf("fixture invalid: the journal and a snapshot envelope must carry the payload before the pass: %v", before)
	}
	if got := f.store.ResidualStores(); !contains(got, control.ResidualControlJournal) {
		t.Fatalf("before the pass the receipt must name the journal: %v", got)
	}

	if err := f.store.RedactRetainedControlCommands(context.Background()); err != nil {
		t.Fatal(err)
	}

	if after := f.raftHits(gone); len(after) != 0 {
		t.Fatalf("the control Raft directory still holds the erased payload after the deletion and the pass: %v", after)
	}
	if hits := f.raftHits(kept); !contains(hits, "raft-control/ready.wal") {
		t.Fatalf("the pass took a payload no deletion covers out of the journal: %v", hits)
	}
	if !f.stateHolds(kept) {
		t.Fatal("the pass changed the live state")
	}
	if got := f.store.ResidualStores(); len(got) != 0 {
		t.Fatalf("the pass proved the group clean but the receipt still names %v", got)
	}
}

func hasEnvelope(hits []string) bool {
	for _, h := range hits {
		if filepath.Base(h) == "envelope.json" {
			return true
		}
	}
	return false
}

func (f *eraseFx) rawRaft(name string) []byte {
	f.t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.dir, "raft-control", name))
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *eraseFx) pass() {
	f.t.Helper()
	if err := f.store.RedactRetainedControlCommands(context.Background()); err != nil {
		f.t.Fatal(err)
	}
}

// The pass changes no state a reader or a replay can see: the live state is byte for byte what it
// was, a restart reaches it again, the group keeps taking commands, and what the pass proved
// is a fact about this process: after a restart the receipt names the journal again until the
// next pass, which finds the files already clean and proves it.
func TestRedactedControlJournalLeavesTheStateAndSurvivesARestart(t *testing.T) {
	f := newEraseFx(t)
	const gone, kept = "CANARYRESTART0d2b86a7c41e9", "CANARYRKEPT51f0aa93c7de1b"
	f.seedAll(f.newSeed(f.project, gone), 50)
	f.seedAll(f.newSeed(f.otherProject, kept), 50)
	f.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
	want := f.canonicalState()
	f.pass()
	if got := f.canonicalState(); got != want {
		// The pass commits one empty revision: only the revision may differ.
		var a, b model.ControlState
		if json.Unmarshal([]byte(got), &a) != nil || json.Unmarshal([]byte(want), &b) != nil || a.Revision != b.Revision+1 {
			t.Fatal("the pass changed the live state")
		}
		a.Revision = b.Revision
		raw, _ := model.CanonicalJSON(a)
		if string(raw) != want {
			t.Fatal("the pass changed the live state beyond the revision")
		}
	}
	want = f.canonicalState()
	if got := f.store.ResidualStores(); len(got) != 0 {
		t.Fatalf("after the pass: %v", got)
	}
	// A pass with nothing owed touches no file.
	journal, snapshots := f.rawRaft("ready.wal"), snapshotNames(t, filepath.Join(f.dir, "raft-control", "snapshots"))
	f.pass()
	if !bytes.Equal(journal, f.rawRaft("ready.wal")) || !reflect.DeepEqual(snapshots, snapshotNames(t, filepath.Join(f.dir, "raft-control", "snapshots"))) {
		t.Fatal("a pass with nothing owed rewrote files")
	}

	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := control.Open(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err = auth.NewService(auth.AuthDependencies{Control: reopened}); err != nil {
		t.Fatal(err)
	}
	if err = reopened.EnableSingle(f.ctx, filepath.Join(f.dir, "raft-control")); err != nil {
		t.Fatal(err)
	}
	if err = reopened.View(f.ctx, func(st control.State) error {
		raw, e := model.CanonicalJSON(st)
		if e == nil && string(raw) != want {
			t.Error("a restart on the redacted journal changed the state")
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if got := reopened.ResidualStores(); !reflect.DeepEqual(got, []string{control.ResidualControlJournal}) {
		t.Fatalf("a restart must withdraw the proof (it is a fact about the process): %v", got)
	}
	if err = reopened.RedactRetainedControlCommands(f.ctx); err != nil {
		t.Fatal(err)
	}
	if got := reopened.ResidualStores(); len(got) != 0 {
		t.Fatalf("after the pass on the restarted node: %v", got)
	}
	if hits := eraseFileHits(t, f.dir, gone); len(hits) != 0 {
		t.Fatalf("the restarted node holds the erased payload: %v", hits)
	}
	if err = reopened.Update(f.ctx, func(st *control.State) error {
		if st.Quotas == nil {
			st.Quotas = map[string]model.QuotaState{}
		}
		st.Quotas["after:restart"] = model.QuotaState{MaxBytes: 1}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func snapshotNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// A range deletion and a failed deletion are erasures too; the pass covers each, and an erasure
// committed after a proven pass makes the receipt name the journal again until the next one.
func TestRedactedControlJournalCoversEveryKindOfErasureAndEachNewOne(t *testing.T) {
	f := newEraseFx(t)
	const rangeGone, failedGone, kept = "CANARYRANGEJ0d2b86a7c41e9", "CANARYFAILEDJ0d2b86a7c41e", "CANARYJKEEP51f0aa93c7de1b"
	f.seedAll(f.newSeed(f.otherProject, kept), 50)
	f.seedAll(f.newSeed(f.project, rangeGone), 50)
	f.saga(f.lateRange())
	if hits := f.raftHits(rangeGone); len(hits) == 0 {
		t.Fatal("fixture invalid: the journal holds no copy of the erased range")
	}
	f.pass()
	if got := f.store.ResidualStores(); len(got) != 0 {
		t.Fatalf("after the range deletion's pass: %v", got)
	}
	if hits := f.raftHits(rangeGone); len(hits) != 0 {
		t.Fatalf("the range deletion's payload survives in %v", hits)
	}

	f.seedAll(f.newSeed(f.project, failedGone), 150)
	id := f.begin(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
	// While it is fencing the live state still owes it: it is named, nothing is redacted.
	f.pass()
	if got := f.store.ResidualStores(); !contains(got, control.ResidualControlJournal) {
		t.Fatalf("a fencing erasure must be named: %v", got)
	}
	if hits := f.raftHits(failedGone); len(hits) == 0 {
		t.Fatal("a deletion that is still fencing was redacted from the journal")
	}
	if _, err := f.store.FailDeletion(f.ctx, id, model.UnixNano(f.now.UnixNano()), "operator_failed"); err != nil {
		t.Fatal(err)
	}
	if got := f.store.ResidualStores(); !contains(got, control.ResidualControlJournal) {
		t.Fatalf("an erasure committed after a proven pass must be named again: %v", got)
	}
	if err := f.store.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.pass()
	if got := f.store.ResidualStores(); len(got) != 0 {
		t.Fatalf("after the failed deletion's pass: %v", got)
	}
	for _, canary := range []string{rangeGone, failedGone} {
		if hits := f.raftHits(canary); len(hits) != 0 {
			t.Fatalf("%s survives in %v", canary, hits)
		}
	}
	if hits := f.raftHits(kept); !contains(hits, "raft-control/ready.wal") {
		t.Fatalf("the pass took a payload no deletion covers: %v", hits)
	}
}

// A live backup pin holds copies the node cannot rewrite or vouch for: the pass cleans the files
// it can and the receipt keeps naming the journal until the pin is dropped.
func TestALiveBackupPinKeepsTheControlJournalNamed(t *testing.T) {
	f := newEraseFx(t)
	const gone = "CANARYPINNED0d2b86a7c41e90"
	f.seedAll(f.newSeed(f.project, gone), 50)
	if _, err := f.store.ReplicaGroup().PinJournal(0); err != nil {
		t.Fatal(err)
	}
	f.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
	if hits := f.raftHits(gone); !slices.ContainsFunc(hits, func(h string) bool { return strings.HasSuffix(h, ".pin") }) {
		t.Fatalf("fixture invalid: the pin archive holds no copy: %v", hits)
	}
	f.pass()
	if got := f.store.ResidualStores(); !contains(got, control.ResidualControlJournal) {
		t.Fatalf("a live pin must keep the journal named: %v", got)
	}
	if hits := f.raftHits(gone); len(hits) != 0 {
		t.Fatalf("the pass left the payload in %v", hits)
	}
	pins, err := f.store.ReplicaGroup().Pins()
	if err != nil || len(pins) != 1 {
		t.Fatalf("pins %v %v", pins, err)
	}
	if err = f.store.ReplicaGroup().DropPin(pins[0].ID); err != nil {
		t.Fatal(err)
	}
	if got := f.store.ResidualStores(); len(got) != 0 {
		t.Fatalf("after the pin was dropped: %v", got)
	}
}
