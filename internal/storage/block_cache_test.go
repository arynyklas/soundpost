// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"sort"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// blockCacheFixture is an index of final runs whose blocks are records of the payload log, with the keys written.
func blockCacheFixture(t *testing.T) (*bolt.DB, *payloadLog, [][]byte, [][]byte) {
	t.Helper()
	old := indexRunBlockBytes
	indexRunBlockBytes = 2 << 10
	t.Cleanup(func() { indexRunBlockBytes = old })
	db := ioOpen(t)
	pl := openLogForRuns(t, db)
	keys := finalRunsInLog(t, db, pl, 3, 100)
	var refs [][]byte
	ready, _ := irRegistry(t, db, irIndex)
	if err := db.View(func(tx *bolt.Tx) error {
		for _, e := range ready {
			if err := tx.Bucket(indexRunBucketName(irIndex, e.id)).ForEach(func(_, v []byte) error {
				if isPayloadRef(v) {
					refs = append(refs, bytes.Clone(v))
				}
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(refs) < 24 {
		t.Fatalf("the fixture has %d blocks in the log: too few", len(refs))
	}
	return db, pl, keys, refs
}

// seekEvery looks every key up with one Seek of the cursor open makes, and reports the records the payload log
// read for it.
func seekEvery(t *testing.T, db *bolt.DB, pl *payloadLog, keys [][]byte, open func(*bolt.Tx, string) (orderedCursor, error)) (reads int64) {
	t.Helper()
	before := pl.nreads.Load()
	if err := db.View(func(tx *bolt.Tx) error {
		cur, err := open(tx, irIndex)
		if err != nil {
			return err
		}
		for _, k := range keys {
			probe := k[:len(k)-1]
			want := keys[sort.Search(len(keys), func(i int) bool { return bytes.Compare(keys[i], probe) >= 0 })]
			if got, _ := cur.Seek(probe); !bytes.Equal(got, want) {
				t.Fatalf("Seek(%x) stands on %x, want %x", probe, got, want)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return pl.nreads.Load() - before
}

// Every chunk of every scan fetched the blocks that hold its keys from the payload log: a record read, a zeroed
// buffer of 128 KiB and a checksum of it, each time, for the same few thousand blocks (154 of the 458 CPU
// seconds of the Queries gate mix). A scan's cursor reads a block from the log once, and the next scan finds it
// in memory. The verification of the indexes does not use the cache: it is there to read what the disk holds.
func TestScanCursorsFetchEachIndexBlockFromTheLogOnce(t *testing.T) {
	db, pl, keys, refs := blockCacheFixture(t)
	first := seekEvery(t, db, pl, keys, openScanCursor)
	if first < int64(len(refs)) {
		t.Fatalf("the first scan read %d records for %d blocks", first, len(refs))
	}
	for i := range 3 {
		if again := seekEvery(t, db, pl, keys, openScanCursor); again != 0 {
			t.Fatalf("scan %d read %d records of the log for blocks the first scan read (it read %d)", i+2, again, first)
		}
	}
	if verify := seekEvery(t, db, pl, keys, openOrderedCursor); verify < int64(len(refs)) {
		t.Fatalf("the verification's cursor read %d records of %d blocks: it must read the disk", verify, len(refs))
	}
}

// A block whose record is owed a zeroing is forgotten by the transaction that owes it, and a reader that began
// before that transaction committed does not put it back: no copy of an erased block outlives the erasure, and
// once the record is zeroed nobody is served its old bytes.
func TestCachedBlockDoesNotOutliveTheTransactionThatOwesItsZeroing(t *testing.T) {
	db, pl, keys, refs := blockCacheFixture(t)
	seekEvery(t, db, pl, keys, openScanCursor) // every block is cached
	victim := refs[len(refs)/2]
	read := func(label string, tx *bolt.Tx) int64 {
		t.Helper()
		before := pl.nreads.Load()
		if storedBlockTx(tx, victim) == nil {
			t.Fatalf("%s: the block cannot be read", label)
		}
		return pl.nreads.Load() - before
	}

	// The write that follows must not need the file to grow (a write that remaps waits for the readers): the bucket it writes
	// exists before the older reader begins.
	if err := db.Update(func(tx *bolt.Tx) error { return owePayloadScrub(tx, refs[0]) }); err != nil {
		t.Fatal(err)
	}
	// A reader that began before the commit that owes the zeroing.
	older, err := db.Begin(false)
	if err != nil {
		t.Fatal(err)
	}
	defer older.Rollback()
	if err = db.Update(func(tx *bolt.Tx) error { return owePayloadScrub(tx, victim) }); err != nil {
		t.Fatal(err)
	}
	if got := read("older reader", older); got != 1 {
		t.Fatalf("the older reader read %d records, want 1: the owed block was still served from memory", got)
	}
	if got := read("older reader again", older); got != 1 {
		t.Fatalf("the older reader read %d records the second time, want 1: it put the owed block back", got)
	}

	// A write transaction neither reads from the cache nor fills it.
	other := refs[len(refs)/3]
	if err = db.Update(func(tx *bolt.Tx) error {
		before := pl.nreads.Load()
		if storedBlockTx(tx, other) == nil || pl.nreads.Load()-before != 1 {
			t.Fatalf("a write transaction was served a cached block")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Zeroed in the log: nothing serves the old bytes, and the cursor reports the damage, as it does for any damaged block.
	if err = pl.scrub(victim); err != nil {
		t.Fatal(err)
	}
	if storedBlockTx(older, victim) != nil {
		t.Fatal("a zeroed block was served from memory")
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i], keys[j]) < 0 })
	if err = db.View(func(tx *bolt.Tx) error {
		set, err := openIndexSet(tx, irIndex)
		if err != nil {
			return err
		}
		cur := set.CursorCached()
		damaged := false
		for _, k := range keys {
			cur.Seek(k[:len(k)-1])
			if cur.Err() != nil {
				damaged = true
				break
			}
		}
		if !damaged {
			t.Fatal("no Seek met the zeroed block")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
