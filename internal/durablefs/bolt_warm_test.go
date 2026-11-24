// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package durablefs

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// metaHighWater is the high-water page of the newest meta page of the file (bolt's meta: page header 16 bytes, then magic, version, page
// size, flags, root bucket (page, sequence), freelist, high-water mark, txid).
func metaHighWater(t *testing.T, path string) uint64 {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pageSize := int(binary.LittleEndian.Uint32(raw[boltPageHeader+8:]))
	var best, bestTx uint64
	for i := range 2 {
		m := raw[i*pageSize+boltPageHeader:]
		if tx := binary.LittleEndian.Uint64(m[48:]); tx >= bestTx {
			best, bestTx = binary.LittleEndian.Uint64(m[40:]), tx
		}
	}
	return best
}

// TestWarmBoltTreeReadsExactlyTheLiveTree: the pages the warm-up reads are the pages bolt itself finds reachable from the newest meta page,
// whatever the tree is made of: branch and leaf nodes, nested buckets that are inline and ones that are not, values that span pages, and a
// file full of pages that were freed. bolt counts the others as free when it rebuilds the freelist of a file that has none, so the
// reachable pages are the file's pages without the two metas and without the free ones.
func TestWarmBoltTreeReadsExactlyTheLiveTree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.db")
	opts := &bolt.Options{NoFreelistSync: true, PreLoadFreelist: true}
	db, err := bolt.Open(path, 0600, opts)
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewPCG(3, 5))
	row := make([]byte, 150)
	value := make([]byte, 700_000)
	for round := range 40 {
		if err = db.Update(func(tx *bolt.Tx) error {
			rows, err := tx.CreateBucketIfNotExists([]byte("rows"))
			if err != nil {
				return err
			}
			for range 4000 {
				if err = rows.Put(binary.BigEndian.AppendUint64(nil, rng.Uint64()), row); err != nil {
					return err
				}
			}
			blocks, err := tx.CreateBucketIfNotExists([]byte("blocks"))
			if err != nil {
				return err
			}
			if err = blocks.Put(fmt.Appendf(nil, "b%03d", round), value); err != nil {
				return err
			}
			runs, err := tx.CreateBucketIfNotExists([]byte("runs"))
			if err != nil {
				return err
			}
			for i := range 6 { // the nested buckets of the index runs: small ones are inline in their parent's page, one is not
				nested, err := runs.CreateBucketIfNotExists(fmt.Appendf(nil, "r%03d_%d", round, i))
				if err != nil {
					return err
				}
				for k := range 3 + 200*(i/5) {
					if err = nested.Put(fmt.Appendf(nil, "k%05d", k), row); err != nil {
						return err
					}
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if round%3 == 2 { // free some of it: the file keeps pages that no tree holds
			if err = db.Update(func(tx *bolt.Tx) error {
				if err := tx.Bucket([]byte("blocks")).Delete(fmt.Appendf(nil, "b%03d", round-1)); err != nil {
					return err
				}
				return tx.Bucket([]byte("runs")).DeleteBucket(fmt.Appendf(nil, "r%03d_5", round-2))
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err = db.Update(func(*bolt.Tx) error { return nil }); err != nil { // release the pending pages
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() < boltMinWarmBytes {
		t.Fatalf("the file is %d bytes, below the %d the warm-up reads", fi.Size(), boltMinWarmBytes)
	}
	got := WarmBoltTree(path)
	db, err = bolt.Open(path, 0600, opts) // no freelist in the file: bolt rebuilds it from the live tree
	if err != nil {
		t.Fatal(err)
	}
	free := int64(db.Stats().FreePageN)
	db.Close()
	if want := int64(metaHighWater(t, path)) - 2 - free; got != want || got < 1000 {
		t.Fatalf("the warm-up reads %d pages, bolt finds %d reachable (%d free of a high-water mark of %d)", got, want, free, metaHighWater(t, path))
	}
}

// A file that carries its freelist (a graceful close wrote it), a small file and a file that is no bolt file are not read.
func TestWarmBoltTreeLeavesTheOtherFilesAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.db")
	db, err := bolt.Open(path, 0600, nil) // the freelist is written by every commit
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket([]byte("b"))
		if err != nil {
			return err
		}
		return b.Put([]byte("k"), make([]byte, 40<<20))
	}); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if got := WarmBoltTree(path); got != 0 {
		t.Errorf("read %d pages of a file that carries its freelist", got)
	}
	junk := filepath.Join(dir, "junk")
	if err = os.WriteFile(junk, make([]byte, 40<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := WarmBoltTree(junk); got != 0 {
		t.Errorf("read %d pages of a file that is no bolt file", got)
	}
	if got := WarmBoltTree(filepath.Join(dir, "absent")); got != 0 {
		t.Errorf("read %d pages of a file that is not there", got)
	}
}
