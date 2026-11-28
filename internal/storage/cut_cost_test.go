// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// A window file is synced every windowSyncChunk bytes while it is written, not once at its end: a cut that writes 50 MB hands the disk
// that much in steps, and the bytes of the file are what they were.
func TestWindowFilesAreSyncedInChunks(t *testing.T) {
	defer func(old int) { windowSyncChunk = old }(windowSyncChunk)
	windowSyncChunk = 4096
	f, err := os.Create(filepath.Join(t.TempDir(), "w"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	syncs := 0
	w := &chunkSyncWriter{f: f, before: func() error { syncs++; return nil }}
	for range 10 {
		if _, err := w.Write(make([]byte, 1024)); err != nil {
			t.Fatal(err)
		}
	}
	if syncs != 2 {
		t.Fatalf("%d syncs for 10 KiB with a chunk of 4 KiB, want 2", syncs)
	}
	stop := errors.New("stopped at the sync")
	w = &chunkSyncWriter{f: f, before: func() error { return stop }}
	if _, err := w.Write(make([]byte, 4096)); !errors.Is(err, stop) {
		t.Fatalf("a failing step before the sync: %v", err)
	}
}

// A cut writes the files of the windows it changed: the open window of a slot, which grows by the commands since the cut before. The bytes of
// that file were written twice, into a staging directory by the machine and again from there into the snapshot directory by the store, each
// of the 64 groups every 16 MiB of journal; at the 5k records/s gate that is 2 x 50 MB per group by the end of a window and 200 MB/s of cut
// writes on a node (latgrow-report). Every byte of a window file is written once now.
func TestCutWritesEachByteOfTheOpenWindowOnce(t *testing.T) {
	defer SetSnapshotWindow(SetSnapshotWindow(256))
	w := newWindowEnv(t)
	ctx := context.Background()
	w.add(30)
	prev, err := w.e.CreateSnapshots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for round := range 6 {
		w.add(20)
		stagedBefore, copiedBefore := windowBytesStaged.Load(), replica.SnapshotBytesCopied()
		cut, err := w.e.CreateSnapshots(ctx)
		if err != nil {
			t.Fatal(err)
		}
		written := windowBytesStaged.Load() - stagedBefore + replica.SnapshotBytesCopied() - copiedBefore
		had := map[string]model.Hash{}
		for _, f := range prev.Slots[w.slot].Manifest.Files {
			had[f.Name] = f.SHA256
		}
		var fresh uint64
		for _, f := range cut.Slots[w.slot].Manifest.Files {
			if strings.HasPrefix(f.Name, "files/win-") && had[f.Name] != f.SHA256 {
				fresh += f.Size
			}
		}
		t.Logf("cut %d: window files of %d bytes new to the snapshot, %d bytes written for them", round, fresh, written)
		if fresh == 0 {
			t.Fatal("fixture invalid: the cut wrote no window file")
		}
		if limit := fresh + fresh/8 + 8<<10; written > limit {
			t.Fatalf("cut %d wrote %d bytes for window files of %d bytes, want each byte once (at most %d)", round, written, fresh, limit)
		}
		prev = cut
	}
}

// The window that seals is derived from the open window the cache holds, in the cut that crosses the seal, not from the commands: the
// first cut after a seal used to decode the whole window again, and so did the settlement pass, for each of the 64 slots of a node together
// (190 CPU-s per node, a stall of 150 s at the 5k records/s gate).
func TestSealDerivesTheWindowFromTheCacheNotFromScratch(t *testing.T) {
	defer SetSnapshotWindow(SetSnapshotWindow(64))
	w := newWindowEnv(t)
	ctx := context.Background()
	w.add(56)
	if _, err := w.e.CreateSnapshots(ctx); err != nil {
		t.Fatal(err)
	}
	const added = 20 // 8 of them seal window 0, 12 open window 1
	w.add(added)
	before := windowCommandsDerived.Load()
	cut, err := w.e.CreateSnapshots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	derived := windowCommandsDerived.Load() - before
	if st, _, err := compactState(cut.Slots[w.slot]); err != nil || len(st.Windows) != 2 || st.Windows[0].Count != 64 {
		t.Fatalf("fixture invalid: %+v %v", st.Windows, err)
	}
	// Each command added is read once to extend the record and once to write the file; a window derived whole reads its 64 commands twice.
	t.Logf("the cut that seals a window of 64 commands after %d new ones read %d commands", added, derived)
	if limit := uint64(2*added + 4); derived > limit {
		t.Fatalf("the cut that sealed a window read %d commands for %d added, at most %d", derived, added, limit)
	}
	// The settlement pass finds the sealed window recorded: it reads nothing.
	before = windowCommandsDerived.Load()
	if _, err := w.e.SettleCandidates(ctx); err != nil {
		t.Fatal(err)
	}
	if got := windowCommandsDerived.Load() - before; got != 0 {
		t.Fatalf("the settlement pass after the seal read %d commands, want none", got)
	}
}

// A settlement pass that reaches a window the moment it sealed, before any cut did, derives it from the cache too, and the cut after
// it still writes the sealed file from the previous snapshot's file and the commands added since.
func TestSettlementBeforeTheCutDerivesTheSealedWindowIncrementally(t *testing.T) {
	defer SetSnapshotWindow(SetSnapshotWindow(64))
	w := newWindowEnv(t)
	ctx := context.Background()
	w.add(56)
	if _, err := w.e.CreateSnapshots(ctx); err != nil {
		t.Fatal(err)
	}
	const added = 20
	w.add(added)
	before := windowCommandsDerived.Load()
	if _, err := w.e.SettleCandidates(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := w.e.CreateSnapshots(ctx); err != nil {
		t.Fatal(err)
	}
	derived := windowCommandsDerived.Load() - before
	t.Logf("settlement then cut after a seal with %d new commands read %d commands", added, derived)
	if limit := uint64(2*added + 4); derived > limit {
		t.Fatalf("settlement and cut read %d commands for %d added, at most %d", derived, added, limit)
	}
}

// The 64 groups of a node cut within seconds of one another. However many reach their bound together, the engine runs at most
// DefaultCutConcurrency window derivations and window writes at once.
func TestConcurrentCutsOfTheGroupsAreCapped(t *testing.T) {
	defer SetSnapshotWindow(SetSnapshotWindow(8))
	w := newWindowEnv(t)
	var names [64]string
	for i, found := 0, 0; found < 64; i++ {
		if i == 1<<16 {
			t.Fatalf("series for %d of the 64 slots among the first %d names", found, i)
		}
		name := fmt.Sprintf("gate_series_%d", i)
		if slot := ackPagesSlotOf(t, w.desc, name); names[slot] == "" {
			names[slot] = name
			found++
		}
	}
	for slot := range names {
		producer := model.NewID()
		for j := range 11 { // a sealed window and three commands of the next, in every slot
			scope, b := settleBatch(t, w.store, w.service, w.cred, w.desc, producer, model.UnixNano(j+1), names[slot])
			if _, err := w.e.Append(context.Background(), scope, b); err != nil {
				t.Fatal(err)
			}
		}
	}
	w.e.cutGate.resetPeak()
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	begin := make(chan struct{})
	for slot, g := range w.e.repl.groups {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-begin
			_, err := g.CreateSnapshot(context.Background(), g.Status().ApplicationCursor)
			if err != nil {
				errs <- fmt.Errorf("slot %d: %w", slot, err)
			}
		}()
	}
	close(begin)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	peak := w.e.cutGate.peakHolders()
	t.Logf("64 groups cut together: at most %d derivations or writes at once", peak)
	if peak > DefaultCutConcurrency {
		t.Fatalf("%d window derivations or writes ran at once, want at most %d", peak, DefaultCutConcurrency)
	}
	if peak == 0 {
		t.Fatal("fixture invalid: the cuts did not pass the gate")
	}
}
