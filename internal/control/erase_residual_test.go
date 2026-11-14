// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

func (f *eraseFx) auditsOf(action string) int {
	f.t.Helper()
	n := 0
	if err := f.store.View(f.ctx, func(st control.State) error {
		for _, a := range st.Audits {
			if a.Action == action {
				n++
			}
		}
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// begin starts a deletion and records its barriers, without completing it.
func (f *eraseFx) begin(req control.DeleteScope) model.ID {
	f.t.Helper()
	id, _, err := f.del(req)
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *eraseFx) complete(id model.ID) {
	f.t.Helper()
	if _, err := f.store.RecordBarriers(f.ctx, id, cursors(model.DeleteSlots)); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.store.CompleteDeletion(f.ctx, id, model.UnixNano(f.now.UnixNano()), nil); err != nil {
		f.t.Fatal(err)
	}
}

func (f *eraseFx) canonicalState() string {
	f.t.Helper()
	var out string
	if err := f.store.View(f.ctx, func(st control.State) error {
		raw, err := model.CanonicalJSON(st)
		out = string(raw)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// Erased control payloads are named as residual until they are really gone:
// control.db until its physical step (which scrubs it) is recorded, the control
// Raft journal for as long as the replication layer cannot redact control
// commands. A deletion that erased nothing owes nothing.
func TestResidualStoresNameErasedControlPayloads(t *testing.T) {
	f := newEraseFx(t)
	if got := f.store.ResidualStores(); len(got) != 0 {
		t.Fatalf("residual stores before any deletion: %v", got)
	}
	// A deletion of a project with no control payloads owes nothing.
	f.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.otherProject}})
	if got := f.store.ResidualStores(); len(got) != 0 {
		t.Fatalf("a deletion that erased nothing is named as residual: %v", got)
	}

	s := f.newSeed(f.project, "CANARYRESIDUAL0d2b86a7c41e")
	f.seedAll(s, 50)
	id := f.begin(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
	f.complete(id)
	if got, want := f.store.ResidualStores(), []string{control.ResidualControlJournal, control.ResidualControlState}; !reflect.DeepEqual(got, want) {
		t.Fatalf("residual stores before the physical step: %v, want %v", got, want)
	}
	if _, err := f.store.RecordPhysicalCleanup(f.ctx, f.org, []model.ID{id}, model.UnixNano(f.now.UnixNano())); err != nil {
		t.Fatal(err)
	}
	if got, want := f.store.ResidualStores(), []string{control.ResidualControlJournal}; !reflect.DeepEqual(got, want) {
		t.Fatalf("residual stores after the physical step: %v, want %v", got, want)
	}
}

// control.db keeps the replaced state in free pages; ScrubErased zeroes them and
// the physical step cannot be recorded without it.
func TestScrubErasedZeroesTheFreePagesOfControlDB(t *testing.T) {
	f := newEraseFx(t)
	const gone = "CANARYSCRUB7c41e90d2b86a"
	// Many payloads, so the replaced state spans freed pages the later writes do
	// not all reuse.
	for range 12 {
		f.seedAll(f.newSeed(f.project, gone), 50)
	}
	id := f.begin(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
	f.complete(id)
	if f.stateHolds(gone) {
		t.Fatal("the canary is still in the committed state")
	}
	before := controlDBHits(t, f.dir, gone)
	if len(before) == 0 {
		t.Fatal("fixture: bbolt kept no copy of the replaced state in control.db: the scrub has nothing to prove")
	}
	if err := f.store.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
	if after := controlDBHits(t, f.dir, gone); len(after) != 0 {
		t.Fatalf("control.db still holds the erased payloads after the scrub: %v", after)
	}
	// A scrub with nothing owed does not touch the file.
	if _, err := f.store.RecordPhysicalCleanup(f.ctx, f.org, []model.ID{id}, model.UnixNano(f.now.UnixNano())); err != nil {
		t.Fatal(err)
	}
	if err := f.store.ScrubErased(f.ctx); err != nil {
		t.Fatal(err)
	}
}

// Whatever the control Raft files still hold is named: an erased payload found
// in a file under raft-control while ResidualStores does not say so would be an
// unreported copy.
func TestControlRaftFilesHoldingErasedPayloadsAreNamed(t *testing.T) {
	f := newEraseFx(t)
	const gone = "CANARYRAFT0d3b86a7c41e9"
	f.seedAll(f.newSeed(f.project, gone), 50)
	f.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
	named := false
	for _, r := range f.store.ResidualStores() {
		named = named || r == control.ResidualControlJournal
	}
	var raft []string
	for _, h := range eraseFileHits(t, f.dir, gone) {
		if strings.HasPrefix(h, "raft-control/") {
			raft = append(raft, h)
		}
	}
	t.Logf("control raft files still holding the erased payloads: %v (named residual: %v)", raft, named)
	if len(raft) != 0 && !named {
		t.Fatalf("raft files %v hold erased payloads and are not named as residual", raft)
	}
}

// The erasure is a function of committed state: a restart, a snapshot-seeded
// replica and a second erasing pass all see the same bytes, and none of them
// brings a payload back.
func TestErasureIsDeterministicAcrossRestartSnapshotAndRepeat(t *testing.T) {
	f := newEraseFx(t)
	const gone = "CANARYDET7c41e90d2b86a5"
	s := f.newSeed(f.project, gone)
	s.note = true
	f.seedAll(s, 50)
	f.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
	// Begin erased; completion found nothing new to drop: one erasing audit.
	if n := f.auditsOf("delete.control_erased"); n != 1 {
		t.Fatalf("erasing audits: %d, want 1 (the completion pass must be a no-op)", n)
	}
	want := f.canonicalState()

	seed, _, err := f.store.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	seeded, err := control.OpenSeed(t.TempDir(), seed)
	if err != nil {
		t.Fatal(err)
	}
	defer seeded.Close()
	var got string
	if err = seeded.View(f.ctx, func(st control.State) error {
		raw, e := model.CanonicalJSON(st)
		got = string(raw)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if got != want || strings.Contains(got, gone) {
		t.Fatal("a snapshot-seeded replica does not hold exactly the erased state")
	}

	if err = f.store.Close(); err != nil {
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
		if e != nil {
			return e
		}
		if string(raw) != want {
			t.Error("a restart changed the erased state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := reopened.ResidualStores(); !reflect.DeepEqual(got, []string{control.ResidualControlJournal}) {
		t.Fatalf("residual stores after a restart: %v", got)
	}
}

// A deletion held by a legal hold has not begun: nothing is erased until the hold
// is released and the deletion resumed.
func TestHeldDeletionErasesNothingUntilItBegins(t *testing.T) {
	f := newEraseFx(t)
	const gone = "CANARYHELD7c41e90d2b86a"
	f.seedAll(f.newSeed(f.project, gone), 50)
	hold := f.placeHold(f.project)
	id := f.begin(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
	if !f.stateHolds(gone) {
		t.Fatal("a held deletion erased control payloads")
	}
	f.releaseHold(hold)
	payload, _ := json.Marshal(control.BeginFence{Operation: id, At: model.UnixNano(f.now.UnixNano())})
	if _, err := f.store.Transact(f.ctx, f.adminScope(), control.Command{CommandID: model.NewID(), ExpectedRevision: f.revision(), Kind: string(control.KindBeginFence), Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if f.stateHolds(gone) {
		t.Fatal("the resumed deletion left control payloads behind")
	}
}

// A failed deletion keeps its predicate active: its unsent deliveries are
// settled, not left pending without a body.
func TestFailedDeletionSettlesCoveredDeliveries(t *testing.T) {
	f := newEraseFx(t)
	s := f.newSeed(f.project, "CANARYFAILED7c41e90d2b86")
	delivery := f.commitDelivery(s, 45, 60)
	id := f.begin(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 40, End: 100})
	if _, err := f.store.FailDeletion(f.ctx, id, model.UnixNano(f.now.UnixNano()), "operator_failed"); err != nil {
		t.Fatal(err)
	}
	var d control.DeliveryRecord
	if err := f.store.View(f.ctx, func(st control.State) error {
		return json.Unmarshal(st.DeliveryBooks["delivery:"+delivery.String()], &d)
	}); err != nil {
		t.Fatal(err)
	}
	if d.Phase != control.DeliveryCancelled || d.Code != control.DeliveryReasonDeleted || !dropped(d.Body) {
		t.Fatalf("a covered delivery of a failed deletion: %+v", d)
	}
}

// A tombstone restored from the deletion authority erases the payloads of the
// restored state it covers, exactly as a live deletion does.
func TestImportedDeletionErasesRestoredPayloads(t *testing.T) {
	f := newEraseFx(t)
	const gone = "CANARYIMPORT7c41e90d2b86"
	f.seedAll(f.newSeed(f.project, gone), 50)
	pred := model.DeletePredicate{Operation: model.NewID(), Org: f.org, Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}, Generation: 1}
	if err := f.store.ImportDeletions(f.ctx, []model.DeletePredicate{pred}, model.UnixNano(f.now.UnixNano())); err != nil {
		t.Fatal(err)
	}
	if f.stateHolds(gone) {
		t.Fatal("an imported tombstone left the covered payloads in the control state")
	}
	if n := f.auditsOf("delete.control_erased"); n != 1 {
		t.Fatalf("erasing audits after an import: %d", n)
	}
	// Idempotent: importing the same tombstone again changes nothing.
	if err := f.store.ImportDeletions(f.ctx, []model.DeletePredicate{pred}, model.UnixNano(f.now.UnixNano())); err != nil {
		t.Fatal(err)
	}
	if n := f.auditsOf("delete.control_erased"); n != 1 {
		t.Fatalf("erasing audits after a repeated import: %d", n)
	}
}

// RedactControlCommand is the control machine's half of redacting the control
// group's retained commands: given a command committed before a deletion, it
// returns the same command without the payloads the deletion erased, and nothing
// else changed. (The replication layer does not call it yet: see the report.)
func TestRedactControlCommandErasesWhatTheCommittedDeletionsCover(t *testing.T) {
	f := newEraseFx(t)
	const gone, kept = "CANARYREDACT7c41e90d2b86", "CANARYKEEP51f0aa93c7de1"
	f.seedAll(f.newSeed(f.project, gone), 50)
	f.seedAll(f.newSeed(f.otherProject, kept), 50)
	// The retained command of the revision before any deletion: the whole dirty state.
	var original []byte
	if err := f.store.View(f.ctx, func(st control.State) error {
		var err error
		original, err = json.Marshal(struct {
			Expected model.Revision     `json:"expected"`
			State    model.ControlState `json:"state"`
			Keys     map[string][]byte  `json:"keys"`
		}{st.Revision, st, map[string][]byte{}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := f.store.RedactControlCommand(original); err != nil || changed {
		t.Fatalf("before any deletion nothing is covered: changed=%v err=%v", changed, err)
	}
	f.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
	replacement, changed, err := f.store.RedactControlCommand(original)
	if err != nil || !changed {
		t.Fatalf("a command committed before the deletion: changed=%v err=%v", changed, err)
	}
	if eraseDeep(replacement, []byte(gone), 3) {
		t.Fatal("the replacement still carries the erased payloads")
	}
	if !eraseDeep(replacement, []byte(kept), 3) {
		t.Fatal("the replacement lost a payload no deletion covers")
	}
	var shape struct {
		Expected model.Revision     `json:"expected"`
		State    model.ControlState `json:"state"`
	}
	if model.StrictJSON(replacement, &struct {
		Expected model.Revision     `json:"expected"`
		State    model.ControlState `json:"state"`
		Keys     map[string][]byte  `json:"keys"`
	}{}) != nil || json.Unmarshal(replacement, &shape) != nil || shape.State.Revision != shape.Expected {
		t.Fatal("the replacement is not the same command shape at the same revision")
	}
	// Redacting a redacted command changes nothing.
	again, changed, err := f.store.RedactControlCommand(replacement)
	if err != nil || changed || string(again) != string(replacement) {
		t.Fatalf("the redaction is not idempotent: changed=%v err=%v", changed, err)
	}
	if _, _, err := f.store.RedactControlCommand([]byte(`{"expected":1,"unknown":2}`)); err == nil {
		t.Fatal("a payload that is not a control command was accepted")
	}
}

// The worker's physical step is what scrubs control.db: it never records the
// operation as physically done while the replaced state is still in the file.
func TestPhysicalStepScrubsControlDB(t *testing.T) {
	f := newEraseFx(t)
	const gone = "CANARYPHYSICAL7c41e90d2b86"
	for range 12 {
		f.seedAll(f.newSeed(f.project, gone), 50)
	}
	id := f.begin(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
	f.complete(id)
	if len(controlDBHits(t, f.dir, gone)) == 0 {
		t.Fatal("fixture: bbolt kept no copy of the replaced state in control.db")
	}
	if _, err := f.store.RecordPhysicalCleanup(f.ctx, f.org, []model.ID{id}, model.UnixNano(f.now.UnixNano())); err != nil {
		t.Fatal(err)
	}
	if hits := controlDBHits(t, f.dir, gone); len(hits) != 0 {
		t.Fatalf("the physical step was recorded with the erased payloads still in %v", hits)
	}
}

// A held deletion has not begun, so a retained command is not redacted for it:
// the held data is still the hold's to keep.
func TestRedactControlCommandIgnoresAHeldDeletion(t *testing.T) {
	f := newEraseFx(t)
	f.seedAll(f.newSeed(f.project, "CANARYHELDREDACT7c41e90d2"), 50)
	hold := f.placeHold(f.project)
	f.begin(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
	var original []byte
	if err := f.store.View(f.ctx, func(st control.State) error {
		var err error
		original, err = json.Marshal(struct {
			Expected model.Revision     `json:"expected"`
			State    model.ControlState `json:"state"`
			Keys     map[string][]byte  `json:"keys"`
		}{st.Revision, st, map[string][]byte{}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := f.store.RedactControlCommand(original); err != nil || changed {
		t.Fatalf("a held deletion redacted a retained command: changed=%v err=%v", changed, err)
	}
	f.releaseHold(hold)
}
