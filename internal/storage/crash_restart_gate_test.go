// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

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

// startupBudget is what a start of the product may take before it answers /readyz (design section 13). A start after a crash reads the
// journals of its 64 groups and rebuilds the freelists of apply.db and control.db; this test is the share of apply.db, and takes none of the
// others: it fails at half of the budget, the other half being what is left for the journals and control.db of a start that is cold.
const startupBudget = 20 * time.Second

// gateApplyDB is the shape of the apply.db of the single-host gate after the hour of its load: what a start without a freelist walks is
// the live tree (every branch and leaf node, an overflow node by its first page), not the file. Measured on the file G3 left
// (L2w20Admission27/probe-g3/shape.txt): 5.39 GB, 1,153,845 of its 1,315,000 pages free, 107,435 live nodes (157,571 pages: 100,000 of the
// nodes are the trees of replica_commands, replica_data and jobs, 1.7 million rows of ~100 bytes, and ~3,000 are the values of the runs
// that span pages, 18 pages each).
var gateApplyDB = struct {
	fileBytes     int64 // the size of the file: the live tree and the pages it freed
	leafRows      int   // small rows (a command, a receipt, a job: ~180 bytes) of the live tree, in random key order: ~107,000 nodes
	overflowNodes int   // values that span pages (a block of a run): one node each
	overflowBytes int   // the size of such a value: 18 pages
}{fileBytes: 5_390_000_000, leafRows: 1_500_000, overflowNodes: 3000, overflowBytes: 72_000}

// buildGateShapedFile writes a bolt file of the gate's shape with the options of apply.db and closes it the way a kill leaves it: the
// commits did not write the freelist, so the file names none.
func buildGateShapedFile(t *testing.T, path string) (freePages int) {
	t.Helper()
	db, err := bolt.Open(path, 0600, durablefs.BoltOptions())
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewPCG(7, 11))
	row := make([]byte, 180)
	const perTx = 100_000
	for done := 0; done < gateApplyDB.leafRows; done += perTx {
		if err = db.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte("rows"))
			if err != nil {
				return err
			}
			for range min(perTx, gateApplyDB.leafRows-done) {
				key := binary.BigEndian.AppendUint64(nil, rng.Uint64())
				binary.BigEndian.PutUint64(row, rng.Uint64())
				if err = b.Put(key, row); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	block := make([]byte, gateApplyDB.overflowBytes)
	for done := 0; done < gateApplyDB.overflowNodes; done += 50 {
		if err = db.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte("blocks"))
			if err != nil {
				return err
			}
			for i := done; i < min(done+50, gateApplyDB.overflowNodes); i++ {
				binary.BigEndian.PutUint64(block, uint64(i))
				if err = b.Put(binary.BigEndian.AppendUint64(nil, uint64(i)), block); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	// The pages the file freed: a bucket written in commits of 64 MB until the file has the size of the gate's, then deleted (and one
	// more commit, so that the pages are free and not pending).
	churn := make([]byte, 1_024_000)
	for n := 0; fileSize(path) < gateApplyDB.fileBytes; n++ {
		if err = db.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte("churn"))
			if err != nil {
				return err
			}
			for i := range 64 {
				binary.BigEndian.PutUint64(churn, uint64(n*64+i))
				if err = b.Put(binary.BigEndian.AppendUint64(nil, uint64(n*64+i)), churn); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err = db.Update(func(tx *bolt.Tx) error {
			if tx.Bucket([]byte("churn")) != nil {
				return tx.DeleteBucket([]byte("churn"))
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	live := db.Stats()
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if newestMetaHasFreelist(t, path) {
		t.Fatalf("the file of the engine's options names a freelist: the commits of apply.db write it")
	}
	return live.FreePageN
}

// TestCrashRestartOnAGateSizedApplyDBRebuildsItsFreelistWithinTheBudget is the crash-restart test of D91 at the size of the gate: apply.db
// does not carry its freelist (the commits that wrote it were 64 % of the bytes the server wrote), so a start after a crash rebuilds it
// from the live tree before the engine answers. On a file of the gate's size (5.4 GB, 1.5 million rows and 3,000 values that span pages live)
// that start (1) finishes within half of the startup budget with the file out of the page cache (the cold start of a crash: the live
// procedure's `--cold-restart` of the single-host harness drops the whole cache before every restart, and docs/operations/durability.md
// records that measurement), (2) finds every free page of the file that the running engine held, so that (3) the commits
// that follow reuse the file's pages and the file does not grow by what they free again. TMPDIR must be on a disk with 12 GB free: the
// cache of a file on tmpfs cannot be dropped, and a tmpfs of a few GB does not hold the file.
func TestCrashRestartOnAGateSizedApplyDBRebuildsItsFreelistWithinTheBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 5.4 GB file")
	}
	path := filepath.Join(t.TempDir(), "apply.db")
	freeWhenKilled := buildGateShapedFile(t, path)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	durablefs.DropCachedPages(f) // the file is clean (every commit synced it): the start reads it from the device, as after a crash
	f.Close()
	began := time.Now()
	db, err := openApplyDB(path)
	took := time.Since(began)
	if err != nil {
		t.Fatalf("the crash image does not open: %v", err)
	}
	defer db.Close()
	free := db.Stats().FreePageN
	t.Logf("apply.db %d MiB: rebuilt %d free pages (the running file held %d) in %v, the file not in the page cache", fileSize(path)>>20, free, freeWhenKilled, took)
	if took > startupBudget/2 {
		t.Errorf("the freelist of a gate-sized apply.db took %v to rebuild from a cold cache, more than half of the %v startup budget", took, startupBudget)
	}
	if free < freeWhenKilled*99/100 {
		t.Errorf("a start on the crash image rebuilds %d free pages, the running file held %d: pages the file freed are lost to it", free, freeWhenKilled)
	}
	sizeBefore := fileSize(path)
	block := make([]byte, 1_024_000)
	for round := range 4 {
		if err = db.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte("after"))
			if err != nil {
				return err
			}
			for i := range 64 {
				binary.BigEndian.PutUint64(block, uint64(round*64+i))
				if err = b.Put(fmt.Appendf(nil, "k%d-%d", round, i), block); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if grown := fileSize(path) - sizeBefore; grown > 1<<20 {
		t.Errorf("256 MB written after the restart grew the file by %d bytes: the rebuilt freelist is not used", grown)
	}
}
