// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"reflect"
	"testing"

	"soundpost/internal/model"
)

// A range tombstone restored from the deletion authority erases the restored
// opaque states exactly as a live deletion does (CD-9): the state whose window
// meets the range goes, the one whose evidence is all after its end stays, and a
// state with no window is erased and counted in the imported operation's
// over_erased.
func TestCD9ImportedRangeErasesExactlyAndCountsWhatHasNoWindow(t *testing.T) {
	f := newEraseFx(t)
	const inside, after, bare = "CANARYIMPORTIN7c41e90d2b86a", "CANARYIMPORTAFTER51f0aa93c7de", "CANARYIMPORTBARE9c7de151f0aa3"
	f.commitIncident(f.newSeed(f.project, inside), 60)
	f.commitIncident(f.newSeed(f.project, after), 1000)
	f.commitIncidentState(f.newSeed(f.project, bare), `"labels":{"host":"a"}`)
	pred := model.DeletePredicate{Operation: model.NewID(), Org: f.org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 40, End: 100, Generation: 1}
	if err := f.store.ImportDeletions(f.ctx, []model.DeletePredicate{pred}, model.UnixNano(f.now.UnixNano())); err != nil {
		t.Fatal(err)
	}
	if f.stateHolds(inside) || f.stateHolds(bare) {
		t.Fatal("an imported range kept a state inside it or one with no window")
	}
	if !f.stateHolds(after) {
		t.Fatal("an imported range erased a state whose evidence is all after its end")
	}
	op, found, err := f.store.DeletionOperation(f.ctx, pred.Operation)
	if err != nil || !found {
		t.Fatalf("imported operation: %v %v", found, err)
	}
	if want := []model.OverErased{{Book: model.OverErasedIncident, Count: 1}}; !reflect.DeepEqual(op.OverErased, want) {
		t.Fatalf("imported over_erased = %+v, want %+v", op.OverErased, want)
	}
	// A repeated import is a no-op: nothing is counted twice.
	if err := f.store.ImportDeletions(f.ctx, []model.DeletePredicate{pred}, model.UnixNano(f.now.UnixNano())); err != nil {
		t.Fatal(err)
	}
	if again, _, _ := f.store.DeletionOperation(f.ctx, pred.Operation); !reflect.DeepEqual(again.OverErased, op.OverErased) {
		t.Fatalf("a repeated import changed over_erased: %+v", again.OverErased)
	}
}
