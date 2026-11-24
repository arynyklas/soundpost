// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/durablefs"
	bolt "go.etcd.io/bbolt"
)

var freelistProbeBucket = []byte("zz_freelist_probe")

// inflateFreePages writes mb megabytes into a bucket of the file and deletes it, then runs one more commit so that the pages the
// delete freed are free and no longer pending: the control.db the single-host gate leaves holds 57,000 free pages of 267,000 after an
// hour (L2w20Admission27, g3-shape), the freelist node of every commit 111 pages.
func inflateFreePages(t *testing.T, db *trackedDB, mb int) {
	t.Helper()
	chunk := make([]byte, 1<<20)
	if err := db.Update(func(tx *bolt.Tx) error {
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
		if err := db.Update(func(tx *bolt.Tx) error {
			if tx.Bucket(freelistProbeBucket) != nil {
				return tx.DeleteBucket(freelistProbeBucket)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestControlCommitBytesDoNotGrowWithTheFreePagesOfTheFile is the red test of the freelist of control.db (D91 for the second file). A bolt
// commit writes the pages it dirtied and, when the file persists its freelist, one more node that lists every free and pending page id,
// 8 bytes each: the write set of a commit is then a function of how much of the file is free. control.db of the single-host gate after
// the hour of its load: 267,000 pages, 57,000 of them free, a 455 KB node (111 pages) written by each of the 57 commits a second, 25 MB/s
// beside the 20 MB/s of everything else the file wrote (L2w20Admission27, G3's control.db; the apply.db of D91 had 64 % of its bytes in
// it). Two stores take the same small commits; the second first frees 96 MB (24,576 pages: a 192 KB node, 48 pages) and its commits may
// write one page more than the first's.
func TestControlCommitBytesDoNotGrowWithTheFreePagesOfTheFile(t *testing.T) {
	const commits, freeMB = 60, 96
	run := func(inflate bool) (perCommit float64, free int) {
		s, err := Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if inflate {
			inflateFreePages(t, s.db, freeMB)
		}
		put := func(i int) {
			if err := s.db.Update(func(tx *bolt.Tx) error {
				b, err := tx.CreateBucketIfNotExists([]byte("zz_commit_probe"))
				if err != nil {
					return err
				}
				return b.Put(fmt.Appendf(nil, "k%06d", i), []byte("v"))
			}); err != nil {
				t.Fatal(err)
			}
		}
		for i := range 10 { // the bucket exists, the tree has its shape
			put(i)
		}
		before := s.db.Stats()
		for i := range commits {
			put(100 + i)
		}
		after := s.db.Stats()
		d := after.Sub(&before)
		return float64(d.TxStats.GetPageAlloc()) / commits, after.FreePageN
	}
	fresh, freshFree := run(false)
	inflated, inflatedFree := run(true)
	t.Logf("fresh file: %d free pages, %.0f bytes allocated per commit; churned file: %d free pages, %.0f bytes per commit", freshFree, fresh, inflatedFree, inflated)
	if inflatedFree < freeMB*256*9/10 {
		t.Fatalf("the churned file holds %d free pages, fewer than the %d the test frees: it does not describe what it claims", inflatedFree, freeMB*256)
	}
	if inflated > fresh+4096 {
		t.Fatalf("a commit writes %.0f bytes on a file with %d free pages and %.0f on a fresh one: the free pages of control.db are part of the write set of every commit", inflated, inflatedFree, fresh)
	}
}

// metaFreelist returns the freelist page id of the newest meta page of a bolt file (bolt's meta: page header 16 bytes, then magic,
// version, page size, flags, root bucket (page, sequence), freelist, high-water mark, txid).
func metaFreelist(t *testing.T, path string) uint64 {
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
	pageSize := int(binary.LittleEndian.Uint32(head[16+8:]))
	var best, bestTx uint64
	for i := range 2 {
		buf := make([]byte, 80)
		if _, err = f.ReadAt(buf, int64(i*pageSize)); err != nil {
			t.Fatal(err)
		}
		fl, tx := binary.LittleEndian.Uint64(buf[16+16+16:]), binary.LittleEndian.Uint64(buf[16+16+16+16:])
		if tx >= bestTx {
			best, bestTx = fl, tx
		}
	}
	return best
}

// TestControlFreelistIsWrittenByAGracefulCloseAndRebuiltAfterACrash: the commits of a running store leave the freelist out of
// control.db; a graceful close writes it, and the next start reads it; a copy of the file taken while the store runs (a crash image)
// names none, and its start rebuilds the free pages from the live tree and keeps the state.
func TestControlFreelistIsWrittenByAGracefulCloseAndRebuiltAfterACrash(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	inflateFreePages(t, s.db, 8)
	path := filepath.Join(dir, "control.db")
	if metaFreelist(t, path) != ^uint64(0) {
		t.Fatalf("the newest meta page of a running store names a freelist: every commit persists it")
	}
	running := s.db.Stats().FreePageN
	if running < 2000 {
		t.Fatalf("the running store holds %d free pages", running)
	}
	installation, revision, err := s.head()
	if err != nil {
		t.Fatal(err)
	}
	crashDir := t.TempDir()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(crashDir, "control.db"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if metaFreelist(t, path) == ^uint64(0) {
		t.Fatalf("after a graceful close the newest meta page names no freelist")
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.db.Stats().FreePageN; got < running*9/10 { // the close commits its own few pages
		t.Fatalf("a start after a graceful close reads %d free pages, the running store held %d", got, running)
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := Open(crashDir)
	if err != nil {
		t.Fatalf("start on the crash image: %v", err)
	}
	defer rebuilt.Close()
	if got := rebuilt.db.Stats().FreePageN; got < running*9/10 {
		t.Fatalf("a start on a crash image rebuilds %d free pages, the running store held %d", got, running)
	}
	if i2, r2, err := rebuilt.head(); err != nil || i2 != installation || r2 != revision {
		t.Fatalf("the crash image holds installation %s revision %d, the running store held %s %d (%v)", i2, r2, installation, revision, err)
	}
}

// startupBudget is what a start of the product may take before it answers /readyz (design section 13); the freelist rebuild of control.db
// may take a quarter of it on a cold cache (apply.db's share is half, storage/crash_restart_gate_test.go).
const startupBudget = 20 * time.Second

// TestCrashRestartOnAGateSizedControlDBRebuildsItsFreelistWithinTheBudget: control.db after the hour of the gate's load (L2w20Admission27,
// G3's file) is 1.09 GB with ~200,000 live nodes: 123,000 of the reservation rows (308,000 of ~1.5 KB, two to a page), ~70,000 of the
// key and series tables (1.2 million small rows in random order). Written with the options of the store and closed the way a kill leaves it,
// a start rebuilds the freelist from the live tree: within a quarter of the budget from a cold cache, with every free page found. TMPDIR
// must be on a disk: the cache of a file on tmpfs cannot be dropped (and a tmpfs of a few GB does not hold the file).
func TestCrashRestartOnAGateSizedControlDBRebuildsItsFreelistWithinTheBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 1.1 GB file")
	}
	path := filepath.Join(t.TempDir(), "control.db")
	db, err := bolt.Open(path, 0600, durablefs.BoltOptions())
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewPCG(13, 17))
	big, small := make([]byte, 1500), make([]byte, 40)
	const perTx = 50_000
	fill := func(name string, rows int, value []byte, keyLen int) {
		for done := 0; done < rows; done += perTx {
			if err = db.Update(func(tx *bolt.Tx) error {
				b, err := tx.CreateBucketIfNotExists([]byte(name))
				if err != nil {
					return err
				}
				for range min(perTx, rows-done) {
					key := make([]byte, keyLen)
					binary.BigEndian.PutUint64(key, rng.Uint64())
					if err = b.Put(key, value); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	fill("adm_res", 308_000, big, 16)
	fill("adm_keys", 1_200_000, small, 32)
	runningFree := db.Stats().FreePageN
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if metaFreelist(t, path) != ^uint64(0) {
		t.Fatalf("the file of the store's options names a freelist: its commits write it")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	durablefs.DropCachedPages(f) // every commit synced the file: the start reads it from the device
	f.Close()
	began := time.Now()
	reopened, err := openControlDB(path)
	took := time.Since(began)
	if err != nil {
		t.Fatalf("the crash image does not open: %v", err)
	}
	defer reopened.Close()
	fi, _ := os.Stat(path)
	t.Logf("control.db %d MiB: rebuilt %d free pages (running: %d) in %v, the file not in the page cache", fi.Size()>>20, reopened.Stats().FreePageN, runningFree, took)
	bound := startupBudget / 4
	if raceBuild {
		bound *= 2 // the race detector slows the page walk of the rebuild (5.4-5.9 s measured on 4 CPUs, above the plain bound)
	}
	if took > bound {
		t.Errorf("the freelist of a gate-sized control.db took %v to rebuild from a cold cache, more than %v (a quarter of the %v startup budget, doubled under the race detector)", took, bound, startupBudget)
	}
	if got := reopened.Stats().FreePageN; got < runningFree {
		t.Errorf("a start on the crash image rebuilds %d free pages, the running file held %d", got, runningFree)
	}
}
