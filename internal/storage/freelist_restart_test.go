// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// A graceful close writes the freelist of apply.db (D91; the commits of a running engine do not). The restart test: the receipts of
// acknowledged appends survive a graceful restart and a crash image of the file, the freelist lets later commits reuse pages (the
// file does not grow by the whole history again), and a retry of an acknowledged append returns the original receipt.
func TestRestartReusesPersistedFreelist(t *testing.T) {
	store, service, cred, desc := fixture(t)
	dir := t.TempDir()
	const per = 120
	receipts := map[string]string{}
	var all []preparedAppend
	next := 0
	appendMore := func(e *Engine) {
		for i := 0; i < per; i++ {
			p := preparedAppend{}
			p.scope, p.batch = settleBatch(t, store, service, cred, desc, model.NewID(), 1, fmt.Sprintf("series_%d", next))
			next++
			r, err := e.Append(context.Background(), p.scope, p.batch)
			if err != nil {
				t.Fatalf("append %d: %v", next, err)
			}
			receipts[p.batch.ID.String()] = string(mustJSON(t, r))
			all = append(all, p)
		}
	}
	size := func() int64 {
		fi, err := os.Stat(filepath.Join(dir, "apply.db"))
		if err != nil {
			t.Fatal(err)
		}
		return fi.Size()
	}
	var sizes []int64
	for round := 0; round < 4; round++ {
		e, err := openTestEngine(t, dir, service, store)
		if err != nil {
			t.Fatalf("open round %d: %v", round, err)
		}
		if round > 0 {
			free := e.db.Stats().FreePageN
			if free == 0 {
				t.Fatalf("round %d: the freelist read at open holds no page", round)
			}
		}
		for _, p := range all { // a retry of any acknowledged append returns the receipt it got
			r, err := e.Append(context.Background(), p.scope, p.batch)
			if err != nil || string(mustJSON(t, r)) != receipts[p.batch.ID.String()] {
				t.Fatalf("round %d: retry of %s: %v", round, p.batch.ID, err)
			}
		}
		appendMore(e)
		if err = e.Close(); err != nil {
			t.Fatal(err)
		}
		sizes = append(sizes, size())
	}
	t.Logf("apply.db size after each round of %d appends: %v", per, sizes)
	// The file grows in steps of a doubling mapping (2, 4, 8 MiB), so the growth of the second round can be zero
	// whatever it wrote; the first round, which starts from an empty file, is what a round of this size needs.
	growth := sizes[3] - sizes[1]
	if growth > 2*sizes[0]+1<<20 {
		t.Fatalf("pages freed in earlier rounds were not reused after restart: sizes %v", sizes)
	}
	// A crash image: the file as the last commit left it, copied without the engine's Close.
	e, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	appendMore(e)
	image := filepath.Join(t.TempDir(), "apply.db")
	raw, err := os.ReadFile(filepath.Join(dir, "apply.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(image, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	e.Close()
	db, err := bolt.Open(image, 0o600, &bolt.Options{FreelistType: bolt.FreelistMapType})
	if err != nil {
		t.Fatalf("crash image does not open: %v", err)
	}
	defer db.Close()
	if err = db.View(func(tx *bolt.Tx) error {
		for err := range tx.Check() {
			return err
		}
		n := logicalCount(t, tx, "receipts")
		if n != len(all) {
			return fmt.Errorf("crash image holds %d receipts, %d were acknowledged", n, len(all))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// apply.db is opened without a per-commit freelist (D91: TestCommitBytesDoNotGrowWithTheFreePagesOfTheFile) and with the freelist
// loaded at open, so that the pass over the tree a start after a crash needs is paid before the engine answers, not by the first
// write; a graceful close writes it (TestFreelistIsWrittenByAGracefulCloseAndRebuiltAfterACrash). The test that kept the freelist in
// the file on every commit (40 s of a 99-139 s restart on the 2.3 GB file of L2w20Admission7) is replaced: the file of the layout
// since D81 keeps its blocks as overflow nodes, and the measurement of the pass is in docs/operations/durability.md.
func TestApplyDBDoesNotPersistItsFreelistPerCommit(t *testing.T) {
	store, service, _, _ := fixture(t)
	e, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if !e.db.NoFreelistSync {
		t.Fatal("apply.db persists its freelist with every commit: the write set of a commit grows with the free pages of the file")
	}
}
