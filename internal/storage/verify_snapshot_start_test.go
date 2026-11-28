// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"testing"
)

// A start verifies what was written since the verified point (D15). The compact snapshot of each of the 64 groups names the open
// window of its slot, and the check of that snapshot used to derive the window from the stored commands whatever the verified record
// said: for each of up to 4,096 commands one random read of the payload log, 842 MB and 130,000 reads in all, on the cold disk of
// the single-host gate before the node could answer /readyz (L2w20Admission32: group opens were four seconds of the 7.4 s cold start
// of the data of the 900 s run on a warm-ish disk, and the cold kill -9 start of that run took 22.1 s). The window the verified record
// covers is below the point a start no longer re-verifies; a window with a command above the point, and a snapshot received while the
// node runs, are compared whole as before.
func TestStartDoesNotDeriveTheWindowsTheVerifiedRecordCovers(t *testing.T) {
	holdBackgroundVerification(t)
	defer SetSnapshotWindow(SetSnapshotWindow(512))
	w := newWindowEnv(t)
	w.add(500) // the open window of a slot almost full: the shape of the gate's groups
	m := &slotMachine{engine: w.e, slot: w.slot}
	state, err := m.CompactSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	derived := func(state []byte, starting bool) uint64 {
		t.Helper()
		w.e.ver.starting.Store(starting)
		before := w.e.ver.commands.Load()
		if err := m.VerifySnapshot(state); err != nil {
			t.Fatal(err)
		}
		return w.e.ver.commands.Load() - before
	}
	if got := derived(state, true); got != 500 {
		t.Fatalf("control: with no verified record a start derived %d commands of the open window, want 500", got)
	}
	if err = w.e.advanceVerified(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := derived(state, true); got != 0 {
		t.Fatalf("a start derived %d commands of a window the verified record covers: every one of them is a random read of the payload log on a cold disk", got)
	}
	if got := derived(state, false); got != 500 {
		t.Fatalf("a snapshot received while the node runs derived %d commands of the window, want it compared whole (500)", got)
	}
	w.add(5) // a cut after the last advance: commands above the verified point
	state, err = m.CompactSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if got := derived(state, true); got != 505 {
		t.Fatalf("a start derived %d commands of a window with commands above the verified point, want the window whole (505)", got)
	}
}
