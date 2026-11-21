// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// The restore-quota marker is written with temp + fsync + rename like every other durable file
// of the engine, never truncated in place: a crash mid-write must leave the previous marker or
// the new one, never a short one that bricks reconciliation (review item MIN-3). A reader that
// already holds the old file therefore keeps seeing the old bytes.
func TestRestoreHoldMarkerIsReplacedAtomically(t *testing.T) {
	store, a, _, _ := fixture(t)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	path := filepath.Join(e.dir, restorePendingFile)
	old := model.HashCanonical([]byte("old backup"))
	if err = e.writeHold(old); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	next := model.HashCanonical([]byte("new backup"))
	if err = e.writeHold(next); err != nil {
		t.Fatal(err)
	}
	prior := make([]byte, 128)
	n, _ := held.Read(prior)
	if string(prior[:n]) != old.String() {
		t.Fatalf("the marker was rewritten in place: an open handle now reads %q, want the old digest", prior[:n])
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != next.String() {
		t.Fatalf("marker = %q, %v; want the new digest", got, err)
	}
	if entries, _ := filepath.Glob(filepath.Join(e.dir, restorePendingFile+".*")); len(entries) != 0 {
		t.Fatalf("temporary marker files left behind: %v", entries)
	}
}

// A crash between writing the marker temporary and renaming it leaves no marker, yet intake
// must stay closed: the restore never completed its quota stamp.
func TestLeftoverRestoreHoldTemporaryKeepsIntakeClosed(t *testing.T) {
	store, a, _, _ := fixture(t)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err = e.RestoreReady(); err != nil {
		t.Fatalf("a fresh engine is not ready: %v", err)
	}
	if err = os.WriteFile(filepath.Join(e.dir, restorePendingFile+".tmp"), []byte("torn"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = e.loadRestoreHold(); err != nil {
		t.Fatal(err)
	}
	if err = e.RestoreReady(); err == nil {
		t.Fatal("intake opened despite an unfinished restore-quota stamp")
	}
}

// Retired manifest-<id>.json files do not accumulate: after each publication only the live
// one remains (review item MIN-4).
func TestRetiredManifestFilesArePruned(t *testing.T) {
	store, a, c, d := fixture(t)
	write, b := normalized(t, store, a, c, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err = e.Append(context.Background(), write, b); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err = e.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err = e.Compact(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(e.dir, "manifest-*.json"))
	if len(files) != 1 || filepath.Base(files[0]) != e.catalog.File {
		t.Fatalf("manifest files %v, want only the live %s", files, e.catalog.File)
	}
}
