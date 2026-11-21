// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// A voter that installs the leader's snapshot receives the leader's saved views
// whole, and the erasure hook still reaches every one of them in the installed
// state: the books are part of the snapshot, not a side table.
func TestSavedViewsSurviveSnapshotInstall(t *testing.T) {
	const canary = "SVSNAPCANARYd41c9e0a77b2"
	f := newInstallFx(t)
	other := model.ID{0x12}
	keyA := auth.SavedViewKey(f.org, f.project, model.ID{0x21})
	keyB := auth.SavedViewKey(f.org, other, model.ID{0x22})
	rec := func(name string) json.RawMessage { return json.RawMessage(`{"name":"` + name + `"}`) }

	st := f.leader(1, false, false)
	st.SavedViewBooks = map[string]json.RawMessage{keyA: rec(canary + "a"), keyB: rec(canary + "b")}
	f.install(st)

	got := f.state().SavedViewBooks
	if len(got) != 2 || !bytes.Equal(got[keyA], st.SavedViewBooks[keyA]) || !bytes.Equal(got[keyB], st.SavedViewBooks[keyB]) {
		t.Fatalf("the installed state holds %d saved views %v, want the leader's two", len(got), got)
	}

	// The same state round-trips through a real Snapshot of the installed store.
	raw, err := f.s.repl.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var snap controlSnapshot
	if err = model.StrictJSON(raw, &snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.State.SavedViewBooks) != 2 {
		t.Fatalf("Snapshot carries %d saved views, want 2", len(snap.State.SavedViewBooks))
	}

	// Erasing the project over the installed state drops its view and only its view.
	cur := f.state()
	dropped, err := eraseSavedViews(&cur, model.DeletePredicate{Org: f.org, Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
	if err != nil || dropped != 1 {
		t.Fatalf("erase dropped %d (%v), want 1", dropped, err)
	}
	if _, ok := cur.SavedViewBooks[keyA]; ok {
		t.Fatal("the retired project's view survived the erasure of the installed state")
	}
	if _, ok := cur.SavedViewBooks[keyB]; !ok {
		t.Fatal("another project's view was erased")
	}
}
