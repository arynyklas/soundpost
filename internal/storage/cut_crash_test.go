// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// A cut writes its window files once, into a staging directory, and the snapshot store moves them into the snapshot directory it builds.
// Stop the process at every step of that: before each window's files are written, in the middle of a file (at each chunk sync), after
// they are, at the move of each file, at each durability boundary of the store, and while the journal is compacted onto the snapshot.
// What is left must open, hold every acknowledged batch, hand the original receipt to a retry, and cut and compact again; and the
// snapshot it selects verifies, with window files the commands still name.
func TestWindowCutCrashPointsLeaveAStateOpenAccepts(t *testing.T) {
	defer SetSnapshotWindow(SetSnapshotWindow(8))
	defer func(old int) { windowSyncChunk = old }(windowSyncChunk)
	windowSyncChunk = 1 << 10 // a window file of a few KB is synced in several chunks
	type point struct {
		hook       string
		occurrence int
	}
	var points []point
	for _, h := range []string{"window_stage_begin", "window_stage_sync", "window_stage_written"} {
		for _, n := range []int{1, 2} {
			points = append(points, point{h, n})
		}
	}
	for _, h := range []string{replica.HookSnapshotCut, replica.HookSnapshotPin, replica.HookSnapshotFileWrite, replica.HookSnapshotFileSync, replica.HookSnapshotManifestWrite, replica.HookSnapshotDirSync, replica.HookSnapshotSwitch, replica.HookSnapshotRenamed, replica.HookSnapshotCurrentWrite, replica.HookSnapshotCurrentSwitch, replica.HookSnapshotPublished, replica.HookCompactBegin, replica.HookCompactWrite, replica.HookCompactSync, replica.HookCompactSwitch, replica.HookCompactRenamed, replica.HookCompactMemory} {
		points = append(points, point{h, 1})
	}
	// The move of the files of a cut that seals a window and opens the next: each of the four window files is a file_write.
	for _, n := range []int{2, 3, 4} {
		points = append(points, point{replica.HookSnapshotFileWrite, n})
	}
	for _, p := range points {
		t.Run(fmt.Sprintf("%s#%d", p.hook, p.occurrence), func(t *testing.T) {
			if testing.Short() && p.occurrence > 1 {
				t.Skip("the later occurrences run without -short")
			}
			store, service, cred, desc := fixture(t)
			dir := t.TempDir()
			e, err := openTestEngine(t, dir, service, store)
			if err != nil {
				t.Fatal(err)
			}
			if err = store.BindAdmissionOwner(e); err != nil {
				t.Fatal(err)
			}
			w := &windowEnv{t: t, store: store, service: service, cred: cred, desc: desc, e: e, producer: model.NewID(), next: 1}
			var batches []model.NormalizedBatch
			var lastScope auth.Scope
			receipts := map[model.ID][]byte{}
			add := func(n int) {
				for range n {
					scope, b := normalizedAs(t, store, service, cred, desc, w.producer, w.next)
					w.next++
					w.slot = b.RouteSlot
					r, err := w.e.Append(context.Background(), scope, b)
					if err != nil {
						t.Fatal(err)
					}
					batches, lastScope = append(batches, b), scope
					receipts[b.ID] = mustJSON(t, r)
				}
			}
			ctx := context.Background()
			add(5)
			if _, err = w.e.CreateSnapshots(ctx); err != nil { // an earlier cut: the next one extends its window file
				t.Fatal(err)
			}
			if err = w.e.CompactJournals(ctx); err != nil {
				t.Fatal(err)
			}
			add(6) // window 0 seals (8 commands), window 1 opens
			w.e.setFault(onceAt(p.hook, p.occurrence))
			_, err = w.e.CreateSnapshots(ctx)
			if err == nil {
				err = w.e.CompactJournals(ctx)
			}
			if err == nil {
				t.Fatalf("hook %s#%d never fired", p.hook, p.occurrence)
			}
			if err = w.e.Close(); err != nil {
				t.Fatal(err)
			}
			restarted, err := openTestEngine(t, dir, service, store)
			if err != nil {
				t.Fatalf("open after a crash at %s#%d: %v", p.hook, p.occurrence, err)
			}
			scope := lastScope
			for _, b := range batches {
				retry, err := restarted.Append(ctx, scope, b)
				if err != nil || !bytes.Equal(mustJSON(t, retry), receipts[b.ID]) {
					t.Fatalf("receipt lost or changed after a crash at %s#%d: %v", p.hook, p.occurrence, err)
				}
			}
			cut, err := restarted.CreateSnapshots(ctx)
			if err != nil || len(cut.Slots) != 64 {
				t.Fatalf("cut after a crash at %s#%d: %v", p.hook, p.occurrence, err)
			}
			if err = restarted.CompactJournals(ctx); err != nil {
				t.Fatalf("compaction after a crash at %s#%d: %v", p.hook, p.occurrence, err)
			}
			for slot, g := range restarted.repl.groups {
				if _, err := g.Snapshots().Verify(); err != nil {
					t.Fatalf("slot %d: the selected snapshot does not verify after a crash at %s#%d: %v", slot, p.hook, p.occurrence, err)
				}
			}
			// The window files of the selected snapshot are those of a derivation of the commands.
			snap := cut.Slots[w.slot]
			st, compact, err := compactState(snap)
			if err != nil || !compact || len(st.Windows) != 2 {
				t.Fatalf("snapshot of the slot after a crash at %s#%d: %+v compact=%v %v", p.hook, p.occurrence, st.Windows, compact, err)
			}
			restarted.dropWindowCaches()
			restarted.mu.Lock()
			application := restarted.indexes[w.slot]
			restarted.mu.Unlock()
			table, err := restarted.windowTableAt(w.slot, application)
			if err != nil {
				t.Fatal(err)
			}
			for i, rec := range table {
				if rec.windowRef != st.Windows[i] {
					t.Fatalf("window %d of the snapshot is not that of the commands after a crash at %s#%d", rec.N, p.hook, p.occurrence)
				}
				if _, err := os.Stat(filepath.Join(snap.Dir(), "files", winName(rec.N))); err != nil {
					t.Fatal(err)
				}
			}
			if left, _ := os.ReadDir(filepath.Join(dir, "snapshot-stage")); len(left) != 0 {
				// A stage a crash left is removed when replication is enabled; a cut that ran after must not leave one.
				t.Fatalf("%d staging directories left after the cut that followed a crash at %s#%d", len(left), p.hook, p.occurrence)
			}
		})
	}
}
