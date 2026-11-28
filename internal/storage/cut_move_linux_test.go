// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// windowFileLinks lists, for the snapshot a slot has selected, the number of names each of its open-window files has.
func windowFileLinks(t *testing.T, e *Engine, slot uint16) map[string]uint64 {
	t.Helper()
	snap, ok := e.repl.groups[slot].Snapshots().Current()
	if !ok {
		t.Fatalf("slot %d has no selected snapshot", slot)
	}
	out := map[string]uint64{}
	for _, f := range snap.Manifest.Files {
		if !strings.HasPrefix(f.Name, "files/win-") {
			continue
		}
		info, err := os.Stat(filepath.Join(snap.Dir(), filepath.FromSlash(f.Name)))
		if err != nil {
			t.Fatal(err)
		}
		out[f.Name] = uint64(info.Sys().(*syscall.Stat_t).Nlink)
	}
	return out
}

// The window files a cut moves into its snapshot are the snapshot's alone: no inode is shared with the staging directory (removed with
// the cut) nor, for the open window, with the previous snapshot, so nothing that rewrites one name can change another. An erasure after
// the move therefore leaves no erased byte in any snapshot once the cut that follows it has replaced the earlier ones: the cut after an
// erasure rebuilds the window from the rewritten commands (the erasure bumps the cache epoch), not from the file the earlier cut
// wrote, and the staging directory holds nothing at any point.
func TestAnErasureAfterACutThatMovedItsWindowFilesLeavesNoErasedBytes(t *testing.T) {
	x := newCheckpointEnv(t)
	ctx := context.Background()
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	slot := hit.batch.RouteSlot
	pred := x.rangePredicate(0, 10, model.Metric)
	barrierAll(t, x.e, pred)
	x.coldCanary(eraseCanary)
	x.cut() // moves the open window of the slot into its snapshot
	if len(x.raftHits(eraseCanary)) == 0 {
		t.Fatal("fixture invalid: the cut does not hold the canary, so the search proves nothing")
	}
	for name, links := range windowFileLinks(t, x.e, slot) {
		if links != 1 {
			t.Fatalf("%s has %d names after the cut that wrote it, want one", name, links)
		}
	}
	if left, _ := os.ReadDir(filepath.Join(x.dir, "snapshot-stage")); len(left) != 0 {
		t.Fatalf("%d staging directories left after the cut", len(left))
	}
	if report, err := x.e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil || report.Records < 1 {
		t.Fatalf("erase %+v %v", report, err)
	}
	if err := x.e.CheckpointErasure(ctx, pred); err != nil {
		t.Fatal(err)
	}
	x.cut()
	if _, err := x.e.DropSupersededSnapshots(ctx); err != nil {
		t.Fatal(err)
	}
	if err := x.e.CompactJournals(ctx); err != nil {
		t.Fatal(err)
	}
	if left := x.raftHits(eraseCanary); len(left) != 0 {
		t.Fatalf("a file still holds the erased bytes after the erasure and the cut that followed it: %v", left)
	}
	for name, links := range windowFileLinks(t, x.e, slot) {
		if links != 1 {
			t.Fatalf("%s has %d names after the cut that followed the erasure, want one", name, links)
		}
	}
	if left, _ := os.ReadDir(filepath.Join(x.dir, "snapshot-stage")); len(left) != 0 {
		t.Fatalf("%d staging directories left after the second cut", len(left))
	}
}
