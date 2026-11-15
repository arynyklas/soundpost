// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts_test

import (
	"context"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// A journal pin answers per root (10.09-W4): a backup pin records the artifact roots its group
// holds; only a live pin of the group that owns a root, and that holds it, pins that root. A
// pin of another group never does, a pin that recorded no roots holds every root of its group,
// and a pin taken before a root existed still holds it (the journal it archives carries it).
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

	// a real backup pins every group and records each group's roots
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
	held := 0
	for _, in := range infos {
		if !in.RootsKnown {
			t.Fatalf("a backup pin recorded no roots: %+v", in)
		}
		held += len(in.Roots)
	}
	if held < 2 {
		t.Fatalf("the backup pins record %d roots, want at least the 2 uploaded", held)
	}
	if !pinned(am.Org, am.Project, a.ID) || !pinned(b.m.Org, b.m.Project, b.id) {
		t.Fatal("a root held by a live backup pin is not pinned")
	}
	backup.Abort()
	if pinned(am.Org, am.Project, a.ID) || pinned(b.m.Org, b.m.Project, b.id) {
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
	if !pinned(am.Org, am.Project, ghost) {
		t.Fatal("a pin that recorded no roots does not hold every root of its group")
	}
	_ = unknown.Release()
	// a pin taken before the root was written still holds it
	empty, err := groups[slotA].PinJournalForRoots(after, owner, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !pinned(am.Org, am.Project, a.ID) {
		t.Fatal("a pin that recorded an empty set does not hold a root written after it")
	}
	_ = empty.Release()
}

type artifactRoot struct {
	id model.ID
	m  model.BlobManifest
}
