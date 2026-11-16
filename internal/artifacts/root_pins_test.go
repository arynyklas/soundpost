// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts_test

import (
	"context"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// A journal pin answers per root (10.09-W4, review F-1): a pin holds the roots whose evidence lies
// in the journal it protects (a fragment committed after its high-water mark), not every root its
// group has. A root already inside the snapshots when the backup began is not held: erasing it
// cannot make the pinned history unreplayable, and a restore that finds its intent published again
// retires it (ReconcileRetired). A pin of another group never holds a root, a pin that recorded
// nothing (taken by an earlier build) holds every root of its group, and a pin that recorded roots
// still holds them.
func TestJournalPinsAnswerPerRoot(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	engine := f.app.Storage
	a := f.put(t, "pinned-a", false)
	am := a.Map.Manifest
	slotA := model.BlobOwnerSlot(am.Org, am.Project, a.ID)
	// a second root owned by another group
	var b artifactRoot
	for i := 0; b.id == (model.ID{}); i++ {
		if i > 200 {
			t.Fatal("no second group owns an uploaded map")
		}
		c := f.put(t, "pinned-b-"+string(rune('a'+i%26))+string(rune('a'+i/26)), false)
		if model.BlobOwnerSlot(c.Manifest.Org, c.Manifest.Project, c.ID) != slotA {
			b = artifactRoot{id: c.ID, m: c.Map.Manifest}
		}
	}
	slotB := model.BlobOwnerSlot(b.m.Org, b.m.Project, b.id)
	pinned := func(org, project, root model.ID) bool {
		t.Helper()
		got, err := engine.RootPinned(org, project, root)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if pinned(am.Org, am.Project, a.ID) || pinned(b.m.Org, b.m.Project, b.id) {
		t.Fatal("a root is pinned with no pin")
	}

	// a real backup pins every group; the two roots were committed before its high-water mark
	var revision model.Revision
	if err := f.app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	cut := storage.ControlCut{Revision: revision, Reservations: map[string]model.AdmissionReservation{}}
	for _, g := range engine.ReplicaGroups() {
		s := g.Status()
		cut.Processed = append(cut.Processed, model.Cursor{Group: s.Group, Index: s.ApplicationCursor.Index})
	}
	owner := model.NewID()
	backup, err := engine.BeginBackupOwned(ctx, owner, cut)
	if err != nil {
		t.Fatal(err)
	}
	infos, err := engine.JournalPins()
	if err != nil || len(infos) != 64 {
		t.Fatalf("pins %d %v", len(infos), err)
	}
	for _, in := range infos {
		if !in.RootsKnown || len(in.Roots) != 0 {
			t.Fatalf("a backup pin must answer by the evidence it protects and record no root set: %+v", in)
		}
	}
	if pinned(am.Org, am.Project, a.ID) || pinned(b.m.Org, b.m.Project, b.id) {
		t.Fatal("a root committed before the backup's high-water mark is held by its pin although none of its evidence is in the pinned journal")
	}
	late := f.put(t, "pinned-late", false) // committed after the pin: its fragments are in the journal the pin archives
	lm := late.Map.Manifest
	if !pinned(lm.Org, lm.Project, late.ID) {
		t.Fatal("a root written after a backup pin is not held by it")
	}
	backup.Abort()
	if pinned(lm.Org, lm.Project, late.ID) {
		t.Fatal("a root stays pinned after the backup released its pins")
	}

	// a single group's pin pins only that group's roots
	groups := engine.ReplicaGroups()
	after := uint64(groups[slotA].Status().ApplicationCursor.Index)
	pin, err := groups[slotA].PinJournalForRoots(after, owner, []model.ID{a.ID})
	if err != nil {
		t.Fatal(err)
	}
	if !pinned(am.Org, am.Project, a.ID) {
		t.Fatal("the root the pin recorded is not pinned")
	}
	if pinned(b.m.Org, b.m.Project, b.id) {
		t.Fatalf("a pin of group %d pins a root of group %d (the conservative group-wide answer)", slotA, slotB)
	}
	// a root of the pinned group that never existed is not held by a pin that recorded its roots,
	// and is held by one that recorded nothing
	var ghost model.ID
	for ghost = model.NewID(); model.BlobOwnerSlot(am.Org, am.Project, ghost) != slotA; ghost = model.NewID() {
	}
	if pinned(am.Org, am.Project, ghost) {
		t.Fatal("a root that never existed is pinned by a pin that recorded the roots")
	}
	_ = pin.Release()
	unknown, err := groups[slotA].PinJournalFor(after, owner)
	if err != nil {
		t.Fatal(err)
	}
	if !pinned(am.Org, am.Project, ghost) || !pinned(am.Org, am.Project, a.ID) {
		t.Fatal("a pin that recorded no roots does not hold every root of its group")
	}
	_ = unknown.Release()
	// the high-water mark decides: a pin that starts before the root's fragments holds it, one that
	// starts after them does not
	early, err := groups[slotA].PinJournalForRoots(0, owner, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !pinned(am.Org, am.Project, a.ID) {
		t.Fatal("a pin whose high-water mark precedes the root's fragments does not hold the root")
	}
	_ = early.Release()
	latePin, err := groups[slotA].PinJournalForRoots(after, owner, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pinned(am.Org, am.Project, a.ID) {
		t.Fatal("a pin whose high-water mark follows the root's fragments holds the root")
	}
	_ = latePin.Release()
	// a root has two blobs when it keeps private sources: a pin that starts between them still
	// holds the root through the later one
	private := f.put(t, "pinned-private", true)
	if private.Sources == nil {
		t.Fatal("fixture invalid: no private sources blob")
	}
	pm := private.Map.Manifest
	if private.Sources.Cursor.Index <= private.Map.Cursor.Index {
		t.Fatalf("fixture invalid: map at %d, sources at %d", private.Map.Cursor.Index, private.Sources.Cursor.Index)
	}
	between, err := groups[model.BlobOwnerSlot(pm.Org, pm.Project, private.ID)].PinJournalForRoots(uint64(private.Map.Cursor.Index), owner, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !pinned(pm.Org, pm.Project, private.ID) {
		t.Fatal("a pin that starts between a root's map and its private sources does not hold the root through the sources")
	}
	_ = between.Release()
}

type artifactRoot struct {
	id model.ID
	m  model.BlobManifest
}
