// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// freelistProbeBucket holds the churn the test frees to make the file mostly free pages.
var freelistProbeBucket = []byte("zz_freelist_probe")

// inflateFreePages writes mb megabytes into a bucket and deletes it, then runs one more commit so that the pages the delete
// freed are free and no longer pending: the file the single-host gate leaves holds 166,000 free pages of 206,000 after the merges
// of its first minutes (L2w20Admission26).
func inflateFreePages(t *testing.T, e *Engine, mb int) {
	t.Helper()
	chunk := make([]byte, 1<<20)
	if err := e.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket(freelistProbeBucket)
		if err != nil {
			return err
		}
		for i := range mb {
			binary.BigEndian.PutUint64(chunk, uint64(i)+1)
			if err = b.Put(fmt.Appendf(nil, "k%05d", i), chunk); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for range 2 { // the delete frees the pages (pending), the next commit releases them
		if err := e.db.Update(func(tx *bolt.Tx) error {
			if tx.Bucket(freelistProbeBucket) != nil {
				return tx.DeleteBucket(freelistProbeBucket)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// bytesPerCommit appends the batches one to a commit and returns the bytes bolt allocated for the dirty pages of a commit (every
// page it writes: the dirty pages of the trees, the freelist page, not the two meta pages).
func bytesPerCommit(t *testing.T, e *Engine, batches []preparedAppend) float64 {
	t.Helper()
	e.stopIndexMerger()
	before := e.db.Stats()
	commits, applies := appendInCommits(t, e, batches, 1)
	if commits != uint64(len(batches)) || applies != uint64(len(batches)) {
		t.Fatalf("%d appends made %d commits of %d applies", len(batches), commits, applies)
	}
	after := e.db.Stats()
	d := after.Sub(&before)
	return float64(d.TxStats.GetPageAlloc()) / float64(len(batches))
}

// TestCommitBytesDoNotGrowWithTheFreePagesOfTheFile is the red test of D91. A bolt commit writes the pages it dirtied and, when the
// engine persists the freelist, one more node that lists every free and pending page id of the file, 8 bytes each: the write set of
// a commit is then a function of how much of the file is free, and a file that churned (the merges of the index runs free their
// inputs) is mostly free. The single-host gate measured it: 166,000 free ids, a 1.3 MB node (325 pages) per commit at 100 commits a
// second, 2.07 GB of the 3.25 GB the server wrote in 12 s (64 %), against 20 dirty pages (80 KB) a commit for everything else.
//
// The bound: a commit writes the same bytes whatever the file frees. Two engines run the same appends, one commit each; the second
// first frees 96 MB (24,576 pages, a 192 KB freelist node: 48 pages, more than twice what the fresh engine's whole commit writes).
// Its commits may write at most one page more than the fresh engine's (the tree of the second engine is not the same tree).
func TestCommitBytesDoNotGrowWithTheFreePagesOfTheFile(t *testing.T) {
	const warm, measured, freeMB = 40, 60, 96
	run := func(inflate bool) (perCommit float64, free int) {
		store, service, cred, desc := fixture(t)
		e, err := openTestEngine(t, t.TempDir(), service, store)
		if err != nil {
			t.Fatal(err)
		}
		if err = store.BindAdmissionOwner(e); err != nil {
			t.Fatal(err)
		}
		batches := make([]preparedAppend, warm+measured)
		for i := range batches {
			batches[i].scope, batches[i].batch = settleBatch(t, store, service, cred, desc, model.NewID(), 1, fmt.Sprintf("series_%d", i))
		}
		if inflate {
			inflateFreePages(t, e, freeMB)
		}
		bytesPerCommit(t, e, batches[:warm])
		perCommit = bytesPerCommit(t, e, batches[warm:])
		return perCommit, e.db.Stats().FreePageN
	}
	fresh, freshFree := run(false)
	inflated, inflatedFree := run(true)
	t.Logf("fresh file: %d free pages, %.0f bytes allocated per commit; churned file: %d free pages, %.0f bytes per commit", freshFree, fresh, inflatedFree, inflated)
	if inflatedFree < freeMB*256*9/10 {
		t.Fatalf("the churned file holds %d free pages, fewer than the %d the test frees: it does not describe what it claims", inflatedFree, freeMB*256)
	}
	if inflated > fresh+4096 {
		t.Fatalf("a commit writes %.0f bytes on a file with %d free pages and %.0f on a fresh one: the free pages of the file are part of the write set of every commit", inflated, inflatedFree, fresh)
	}
}

// metaFreelists returns the freelist page id of the two meta pages of the file, indexed by meta page, and the txid of each (bolt's
// meta: page header 16 bytes, then magic, version, page size, flags, root bucket (page, sequence), freelist, high-water mark, txid).
func metaFreelists(t *testing.T, path string) (freelist, txid [2]uint64, pageSize int) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	head := make([]byte, 4096)
	if _, err = f.ReadAt(head, 0); err != nil {
		t.Fatal(err)
	}
	pageSize = int(binary.LittleEndian.Uint32(head[16+8:]))
	for i := range 2 {
		buf := make([]byte, 80)
		if _, err = f.ReadAt(buf, int64(i*pageSize)); err != nil {
			t.Fatal(err)
		}
		freelist[i] = binary.LittleEndian.Uint64(buf[16+16+16:])
		txid[i] = binary.LittleEndian.Uint64(buf[16+16+16+16:])
	}
	return
}

// newestMetaHasFreelist is whether the meta page of the highest transaction names a freelist page.
func newestMetaHasFreelist(t *testing.T, path string) bool {
	t.Helper()
	fl, tx, _ := metaFreelists(t, path)
	newest := 0
	if tx[1] > tx[0] {
		newest = 1
	}
	return fl[newest] != ^uint64(0)
}

// TestFreelistIsWrittenByAGracefulCloseAndRebuiltAfterACrash: the commits of a running engine leave the freelist out of the file; a
// graceful close writes it, and the next start reads it (no walk of the tree: the file of the next start has it); a copy of the file
// taken while the engine runs (a crash image) names none, and its start rebuilds the same free pages from the live tree and keeps
// every acknowledged receipt.
func TestFreelistIsWrittenByAGracefulCloseAndRebuiltAfterACrash(t *testing.T) {
	store, service, cred, desc := fixture(t)
	dir := t.TempDir()
	e, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindAdmissionOwner(e); err != nil {
		t.Fatal(err)
	}
	const n = 80
	batches := make([]preparedAppend, n)
	for i := range batches {
		batches[i].scope, batches[i].batch = settleBatch(t, store, service, cred, desc, model.NewID(), 1, fmt.Sprintf("series_%d", i))
	}
	appendInCommits(t, e, batches, 1)
	inflateFreePages(t, e, 8)
	path := filepath.Join(dir, "apply.db")
	if newestMetaHasFreelist(t, path) {
		t.Fatalf("the newest meta page of a running engine names a freelist: every commit persists it")
	}
	runningFree := e.db.Stats().FreePageN
	if runningFree < 2000 {
		t.Fatalf("the running engine holds %d free pages", runningFree)
	}
	crash := filepath.Join(t.TempDir(), "crash")
	if err = os.MkdirAll(crash, 0o700); err != nil {
		t.Fatal(err)
	}
	copyTree(t, dir, crash)
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	if !newestMetaHasFreelist(t, path) {
		t.Fatalf("after a graceful close the newest meta page names no freelist")
	}
	reopened, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.db.Stats().FreePageN; got < runningFree*9/10 { // the close commits its own few pages
		t.Fatalf("a start after a graceful close reads %d free pages, the running engine held %d", got, runningFree)
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if newestMetaHasFreelist(t, filepath.Join(crash, "apply.db")) {
		t.Fatalf("the crash image names a freelist")
	}
	rebuilt, err := openTestEngine(t, crash, service, store)
	if err != nil {
		t.Fatalf("start on the crash image: %v", err)
	}
	defer rebuilt.Close()
	if got := rebuilt.db.Stats().FreePageN; got < runningFree*9/10 {
		t.Fatalf("a start on a crash image rebuilds %d free pages, the running engine held %d", got, runningFree)
	}
	for i, p := range batches {
		if _, err = rebuilt.Append(t.Context(), p.scope, p.batch); err != nil {
			t.Fatalf("retry of acknowledged append %d after the crash image start: %v", i, err)
		}
	}
}

// copyTree copies the regular files of the directory tree src into dst, byte for byte.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}
