// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// After a failed fsync the kernel keeps serving the cached bytes of the journal although the
// device may not hold them, so a node that restarts must not trust what it reads until the journal
// has been synced once more: a journal that cannot be synced is refused, never reused.
func TestAReopenedJournalIsSyncedBeforeItIsTrusted(t *testing.T) {
	dir, group := t.TempDir(), model.NewID()
	w, _, err := openReadyWAL(dir, group, 1, soloMembers(), []byte("seed"), 0, 1, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	var points []string
	failing := func(at string) error {
		points = append(points, at)
		if at == "wal_open_sync" {
			return errors.New("injected EIO on fsync")
		}
		return nil
	}
	if _, _, err = openReadyWAL(dir, group, 1, soloMembers(), nil, 0, 0, 0, failing, nil); err == nil {
		t.Fatal("a journal whose verification sync failed was reopened and trusted")
	}
	if len(points) == 0 || points[len(points)-1] != "wal_open_sync" {
		t.Fatalf("fault points seen at reopen: %v, want the verification sync last", points)
	}
	healthy := func(string) error { return nil }
	w, _, err = openReadyWAL(dir, group, 1, soloMembers(), nil, 0, 0, 0, healthy, nil)
	if err != nil {
		t.Fatalf("the same journal on a healthy disk is refused: %v", err)
	}
	w.Close()
}
