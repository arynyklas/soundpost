// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// What a cut reads is the commands added since the cut before it, not the window it is in (L2w20Admission34). A group of the single-host
// gate cuts every 16 MiB of journal, about eight times in a window of 4,096 commands, and each cut used to derive the open window twice from
// the stored commands (the record, then the files): one random read of the payload log and a decode for each command, up to 8 GB of
// reads for the 64 groups in the 17 minutes a window takes to fill, from a disk once the scope's page cache was full. The read working
// set of a cut is bounded by the cut, not by the window or the history.
func TestCutReadsOnlyTheCommandsAddedSinceTheLastCut(t *testing.T) {
	defer SetSnapshotWindow(SetSnapshotWindow(32))
	w := newWindowEnv(t)
	ctx := context.Background()
	const step, total = 4, 96 // three windows, a cut every four commands
	before := windowCommandsDerived.Load()
	for done := 0; done < total; done += step {
		w.add(step)
		if _, err := w.e.CreateSnapshots(ctx); err != nil {
			t.Fatal(err)
		}
	}
	derived := windowCommandsDerived.Load() - before
	t.Logf("%d cuts of %d commands (window %d) read %d commands", total/step, step, snapshotWindow, derived)
	// Each command is read once to extend the record and once to write the file, and a window's first cut writes its file whole (its
	// few commands): 2 reads a command and one cut's commands a window. Deriving the open window at every cut is about 800.
	if limit := uint64(2*total + 3*step); derived > limit {
		t.Fatalf("%d cuts of %d commands each (window %d) read %d commands, at most %d are the commands added", total/step, step, snapshotWindow, derived, limit)
	}
}

// The files a cut writes from the previous snapshot's file and the commands added since are the files of a derivation of the whole
// window, and so is the record the table names (the cut verifies it, and the snapshot stays restorable by a node that derives).
func TestIncrementalWindowFilesAreThoseOfAWholeDerivation(t *testing.T) {
	defer SetSnapshotWindow(SetSnapshotWindow(8))
	w := newWindowEnv(t)
	ctx := context.Background()
	for range 5 {
		w.add(3)
		if _, err := w.e.CreateSnapshots(ctx); err != nil {
			t.Fatal(err)
		}
	}
	cut, err := w.e.CreateSnapshots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snap := cut.Slots[w.slot]
	st, compact, err := compactState(snap)
	if err != nil || !compact {
		t.Fatalf("compact state: %v compact=%v", err, compact)
	}
	w.e.dropWindowCaches() // the next derivation is from the commands
	w.e.mu.Lock()
	application := w.e.indexes[w.slot]
	w.e.mu.Unlock()
	table, err := w.e.windowTableAt(w.slot, application)
	if err != nil {
		t.Fatal(err)
	}
	if application != uint64(snap.Manifest.Cursor.Index) || len(table) != len(st.Windows) || len(table) != 2 {
		t.Fatalf("table of %d windows at %d, snapshot %d windows at %d (want 2 windows over 15 commands)", len(table), application, len(st.Windows), snap.Manifest.Cursor.Index)
	}
	for i, rec := range table {
		if rec.windowRef != st.Windows[i] {
			t.Fatalf("window %d: the snapshot's record %+v is not the derivation's %+v", rec.N, st.Windows[i], rec.windowRef)
		}
		var file bytes.Buffer
		var side []byte
		err = w.e.db.View(func(tx *bolt.Tx) error {
			var derr error
			_, side, derr = computeWindow(tx.Bucket([]byte("replica_commands")), w.slot, rec.N, rec.First, rec.Count, w.e.windowPartSpan(snapshotWindow), &file, nil)
			return derr
		})
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(snap.Dir(), "files", winName(rec.N)))
		if err != nil || !bytes.Equal(got, file.Bytes()) {
			t.Fatalf("window %d: the file the cut wrote is not the file of a whole derivation (%v)", rec.N, err)
		}
		ev, err := os.ReadFile(filepath.Join(snap.Dir(), "files", evName(rec.N)))
		if err != nil || !bytes.Equal(ev, side) {
			t.Fatalf("window %d: the evidence the cut wrote is not that of a whole derivation (%v)", rec.N, err)
		}
	}
}
