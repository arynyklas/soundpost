// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"math/rand"
	"path/filepath"
	"sort"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// The verification of the tail (a start's, and the advance of the verified point once a minute) looks up the index entries of every page
// above the point with one Seek of the scan_time index per page. A Seek of the merged cursor is a Seek of every run, and a run of the
// log layout answered it by fetching the 128 KiB block that holds the key from the payload log, whichever block the previous Seek had
// stood on: at the single-host gate (L2w20Admission34, G7) each advance read 46,600 pages x one block per sealed window, 6 GB of block
// reads a minute for each sealed window, more of them every 17 minutes, 18-30 s of one thread holding a read transaction, and the
// restart after the hour spent its first 40 s in the same loop (one thread, 9 MB/s from the disk, nothing else running).

// finalRunsInLog fills the index of db with runs of the log layout: pairs written as level-0 runs two at a time, each pair merged into
// a final run whose blocks are payload records. It returns every key written, sorted.
func finalRunsInLog(t *testing.T, db *bolt.DB, pl *payloadLog, rounds, perRun int) [][]byte {
	t.Helper()
	r := rand.New(rand.NewSource(7))
	prefixes := ioPrefixes(r)
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(irIndex))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var keys [][]byte
	for range rounds {
		var size int64
		for range 2 {
			pairs := ioPairs(r, prefixes, perRun)
			for _, p := range pairs {
				keys = append(keys, bytes.Clone(p.Key))
				size += int64(len(p.Key) + len(p.Value))
			}
			if err := db.Update(func(tx *bolt.Tx) error { return writeIndexRun(tx, irIndex, pairs) }); err != nil {
				t.Fatal(err)
			}
		}
		// Two runs of size/2 merge when their sum reaches MaxRunBytes: the output is a final run, its blocks go to the log.
		if did, err := compactIndexRuns(db, irIndex, compactOptions{Fanout: 2, MaxRunBytes: size, Payload: pl}); err != nil || !did {
			t.Fatalf("merge: %v %v", did, err)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i], keys[j]) < 0 })
	return keys
}

func openLogForRuns(t *testing.T, db *bolt.DB) *payloadLog {
	t.Helper()
	pl, err := openPayloadLog(filepath.Join(t.TempDir(), payloadDirName))
	if err != nil {
		t.Fatal(err)
	}
	payloadLogs.Store(db, pl)
	t.Cleanup(func() { payloadLogs.Delete(db); pl.close() })
	return pl
}

// Seeks in ascending order, which is what the verification of a tail makes, fetch each block of a run once: a Seek that lands in the block
// the cursor already holds is answered from it. Whatever the order of the keys, the answer is the one bolt's Seek gives.
func TestMergedCursorSeeksInOrderFetchEachBlockOnce(t *testing.T) {
	old := indexRunBlockBytes
	indexRunBlockBytes = 2 << 10
	t.Cleanup(func() { indexRunBlockBytes = old })
	db := ioOpen(t)
	pl := openLogForRuns(t, db)
	keys := finalRunsInLog(t, db, pl, 3, 100)
	var blocks int
	ready, _ := irRegistry(t, db, irIndex)
	if err := db.View(func(tx *bolt.Tx) error {
		for _, e := range ready {
			blocks += tx.Bucket(indexRunBucketName(irIndex, e.id)).Stats().KeyN
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if blocks < 3*8 {
		t.Fatalf("the fixture has %d blocks: too few to tell a Seek per key from a fetch per block", blocks)
	}
	probes := make([][]byte, 0, len(keys)*2)
	for _, k := range keys {
		probes = append(probes, k, append(bytes.Clone(k[:len(k)-1]), k[len(k)-1]-1)) // each key, and a key just below it
	}
	sort.Slice(probes, func(i, j int) bool { return bytes.Compare(probes[i], probes[j]) < 0 })
	want := func(probe []byte) []byte {
		i := sort.Search(len(keys), func(i int) bool { return bytes.Compare(keys[i], probe) >= 0 })
		if i == len(keys) {
			return nil
		}
		return keys[i]
	}
	seekAll := func(order [][]byte) (reads int64) {
		before := pl.nreads.Load()
		if err := db.View(func(tx *bolt.Tx) error {
			set, err := openIndexSet(tx, irIndex)
			if err != nil {
				return err
			}
			cur := set.Cursor()
			for _, p := range order {
				k, _ := cur.Seek(p)
				if !bytes.Equal(k, want(p)) {
					t.Fatalf("Seek(%x) stands on %x, want %x", p, k, want(p))
				}
			}
			return cur.Err()
		}); err != nil {
			t.Fatal(err)
		}
		return pl.nreads.Load() - before
	}
	// Each key is looked for by a key just below it, the way a page is looked for by the start of its range: the entry that the Seek
	// returns is not looked for again.
	ascending := make([][]byte, 0, len(keys))
	for _, k := range keys {
		ascending = append(ascending, k[:len(k)-1])
	}
	if reads := seekAll(ascending); reads > int64(blocks)+int64(blocks)/2 {
		t.Fatalf("%d ascending Seeks over %d blocks fetched %d blocks", len(ascending), blocks, reads)
	}
	shuffled := append([][]byte(nil), probes...)
	rand.New(rand.NewSource(3)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	seekAll(shuffled) // any order: the same answers
	// Next after a Seek that reused the block goes on in key order.
	if err := db.View(func(tx *bolt.Tx) error {
		set, _ := openIndexSet(tx, irIndex)
		cur := set.Cursor()
		mid := len(keys) / 2
		cur.Seek(keys[mid-5])
		k, _ := cur.Seek(keys[mid])
		if !bytes.Equal(k, keys[mid]) {
			t.Fatalf("Seek after a Seek stands on %x, want %x", k, keys[mid])
		}
		for i := mid + 1; i < mid+40; i++ {
			if k, _ = cur.Next(); !bytes.Equal(k, keys[i]) {
				t.Fatalf("Next stands on %x, want key %d", k, i)
			}
		}
		return cur.Err()
	}); err != nil {
		t.Fatal(err)
	}
}

func (x *eraseEnv) adoptPayload() {
	x.t.Helper()
	if x.e.payloadOn.Load() {
		return
	}
	if err := x.e.adoptRunsLayout(); err != nil {
		x.t.Fatal(err)
	}
	if err := x.e.adoptPayloadLayout(); err != nil {
		x.t.Fatal(err)
	}
}

// The advance reads, for each page above the point, the page's record of the log once and the index blocks that hold its entries: the
// reads do not grow with the number of sealed index runs.
func TestAdvanceReadsGrowWithBlocksNotWithPagesTimesRuns(t *testing.T) {
	holdBackgroundVerification(t)
	x := newEraseEnv(t)
	x.adoptPayload()
	const pages = 24
	x.appendN(pages, 100)
	ready, _ := irRegistry(t, x.e.db.DB, "scan_time")
	var most int64
	for _, e := range ready {
		most = max(most, e.meta.Bytes)
	}
	merges := 0
	for { // pairs of runs merge into final runs of the log
		did, err := compactIndexRuns(x.e.db.DB, "scan_time", compactOptions{Fanout: 2, MaxRunBytes: most + 1, Payload: x.e.payload})
		if err != nil {
			t.Fatal(err)
		}
		if !did {
			break
		}
		merges++
	}
	if merges < 6 {
		t.Fatalf("only %d merges", merges)
	}
	before := x.e.payload.nreads.Load()
	if err := x.e.advanceVerified(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, want := recordedTotal(t, x), totalApplied(x.e); got != want || got < pages {
		t.Fatalf("recorded %d commands after the advance, applied %d", got, want)
	}
	if reads := x.e.payload.nreads.Load() - before; reads > 4*pages {
		t.Fatalf("the advance over %d pages and %d merges read %d records of the log", pages, merges, reads)
	}
}

// A graceful close leaves the verified point at what the node applied, so that the start after it verifies nothing (L2w20Admission35):
// the point used to be up to a minute behind (the advance runs once a minute), and the start after the hour verified that minute, one
// thread, before it answered /readyz.
func TestGracefulCloseMovesTheVerifiedPointToWhatWasApplied(t *testing.T) {
	holdBackgroundVerification(t)
	x := newEraseEnv(t)
	x.appendN(8, 100)
	if before := recordedTotal(t, x); before != 0 {
		t.Fatalf("the record covers %d commands before the close", before)
	}
	applied := totalApplied(x.e)
	x.closeEngine()
	if got := recordedTotal(t, x); got != applied {
		t.Fatalf("the record after the close covers %d commands, the node applied %d", got, applied)
	}
	if _, err := x.open(); err != nil {
		t.Fatal(err)
	}
	if v := x.e.StartupVerification(); v.Full || v.Commands != 0 || v.IndexEntries != 0 {
		t.Fatalf("the start after a graceful close still verified %+v", v)
	}
}
