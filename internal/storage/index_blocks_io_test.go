// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"math/rand"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// The data engine is bound by the number of scattered dirty 4 KB bolt pages one acknowledged request
// writes. These tests pin the I/O shape of the run format through bolt's own counters
// (TxStats.GetWrite is the number of WriteAt calls of the commits, GetPageCount the pages they allocated).

const (
	ioKeyLen   = 180
	ioValueLen = 22
)

// ioPairs returns n realistic index pairs: a key of ioKeyLen bytes (a shared 40-byte prefix chosen among a
// few, then random bytes) and a value of ioValueLen bytes.
func ioPairs(r *rand.Rand, prefixes [][]byte, n int) []indexPair {
	pairs := make([]indexPair, n)
	for i := range pairs {
		key := make([]byte, ioKeyLen)
		copy(key, prefixes[r.Intn(len(prefixes))])
		r.Read(key[len(prefixes[0]):])
		val := make([]byte, ioValueLen)
		r.Read(val)
		pairs[i] = indexPair{Key: key, Value: val}
	}
	return pairs
}

func ioPrefixes(r *rand.Rand) [][]byte {
	prefixes := make([][]byte, 6)
	for i := range prefixes {
		prefixes[i] = make([]byte, 40)
		r.Read(prefixes[i])
	}
	return prefixes
}

// ioOpen opens a database with the options of the engine's apply.db (map freelist, no freelist written by the commits, D91) but
// without fsync, which the counters do not need.
func ioOpen(t testing.TB) *bolt.DB {
	t.Helper()
	db, err := bolt.Open(filepath.Join(t.TempDir(), "io.db"), 0o600,
		&bolt.Options{NoSync: true, NoFreelistSync: true, FreelistType: bolt.FreelistMapType})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// One commit that writes one run of about 600 realistic keys is a handful of contiguous writes, however
// scattered the free pages of a database with a long history are.
func TestIndexRunCommitIsContiguous(t *testing.T) {
	r := rand.New(rand.NewSource(14))
	prefixes := ioPrefixes(r)
	db := ioOpen(t)
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucket([]byte(irIndex))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// A history: a few hundred earlier runs, then every second one dropped (what a merge does to its
	// inputs), which leaves the free pages scattered over the whole file.
	const history = 300
	for range history {
		pairs := ioPairs(r, prefixes, 25)
		if err := db.Update(func(tx *bolt.Tx) error { return writeIndexRun(tx, irIndex, pairs) }); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		reg := tx.Bucket([]byte(runsRegistry))
		runs, err := listIndexRuns(reg, irIndex)
		if err != nil {
			return err
		}
		for i, e := range runs {
			if i%2 == 0 {
				if err := dropIndexRun(tx, reg, irIndex, e.id); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The pages freed by that commit become allocatable by the next one: a small commit releases them.
	if err := db.Update(func(tx *bolt.Tx) error {
		return writeIndexRun(tx, irIndex, ioPairs(r, prefixes, 5))
	}); err != nil {
		t.Fatal(err)
	}

	run := ioPairs(r, prefixes, 600)
	before := db.Stats().TxStats
	if err := db.Update(func(tx *bolt.Tx) error { return writeIndexRun(tx, irIndex, run) }); err != nil {
		t.Fatal(err)
	}
	after := db.Stats().TxStats
	delta := after.Sub(&before)
	t.Logf("one run of 600 keys over %d earlier runs and scattered free pages: %d writes (WriteAt calls), %d pages allocated, %d bytes written",
		history/2, delta.GetWrite(), delta.GetPageCount(), delta.GetPageAlloc())
	if delta.GetWrite() > 12 {
		t.Fatalf("the commit of one run performed %d writes, want at most 12", delta.GetWrite())
	}
}

// irCapOptions lowers the size at which a run stops being merged.
func irCapOptions(opt compactOptions, bytes int64) compactOptions {
	opt.MaxRunBytes = bytes
	return opt
}

type ioMergeCost struct {
	writes, pages, bytes float64 // per ingested key
}

// ioMerge ingests n runs of the same size and merges them to completion; it returns what the merges cost.
// The database also holds the same ballast of tiny runs of another index whatever n is, so that the bolt
// trees of the buckets and of the registry have the same depth in every measurement: what differs is the
// history of the index that merges.
func ioMerge(t *testing.T, n, perRun int, capBytes int64) ioMergeCost {
	t.Helper()
	r := rand.New(rand.NewSource(int64(n)))
	prefixes := ioPrefixes(r)
	db := ioOpen(t)
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucket([]byte(irIndex))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for range 1100 {
		pairs := ioPairs(r, prefixes, 2)
		if err := db.Update(func(tx *bolt.Tx) error { return writeIndexRun(tx, "scan_postings", pairs) }); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		// Fragment the free pages the way a history of merges does: drop every second ballast run.
		reg := tx.Bucket([]byte(runsRegistry))
		runs, err := listIndexRuns(reg, "scan_postings")
		if err != nil {
			return err
		}
		for i, e := range runs {
			if i%2 == 0 {
				if err := dropIndexRun(tx, reg, "scan_postings", e.id); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for range n {
		pairs := ioPairs(r, prefixes, perRun)
		if err := db.Update(func(tx *bolt.Tx) error { return writeIndexRun(tx, irIndex, pairs) }); err != nil {
			t.Fatal(err)
		}
	}
	before := db.Stats().TxStats
	for {
		did, err := compactIndexRuns(db, irIndex, irCapOptions(compactOptions{}, capBytes))
		if err != nil {
			t.Fatal(err)
		}
		if !did {
			break
		}
	}
	after := db.Stats().TxStats
	d := after.Sub(&before)
	keys := float64(n * perRun)
	return ioMergeCost{writes: float64(d.GetWrite()) / keys, pages: float64(d.GetPageCount()) / keys, bytes: float64(d.GetPageAlloc()) / keys}
}

// The bytes a key is rewritten by merges are bounded whatever the history: with a cap on the size of the runs
// that merge, 1024 runs cost per key what 64 runs cost, not log8(1024)/log8(64) times as much.
func TestIndexMergeWritesAreBoundedByHistory(t *testing.T) {
	const perRun = 80
	// The merge of 64 level-0 runs (the first level) makes a run that reaches the cap and is never merged again.
	capBytes := int64(64 * perRun * (ioKeyLen + ioValueLen))
	small := ioMerge(t, 64, perRun, capBytes)
	large := ioMerge(t, 1024, perRun, capBytes)
	t.Logf("per ingested key, 64 runs:   %.5f writes %.5f pages %.1f bytes", small.writes, small.pages, small.bytes)
	t.Logf("per ingested key, 1024 runs: %.5f writes %.5f pages %.1f bytes", large.writes, large.pages, large.bytes)
	check := func(what string, s, l float64) {
		if l > 1.3*s {
			t.Errorf("%s per key grew with the history: %.5f at 64 runs, %.5f at 1024 runs (limit 1.3x)", what, s, l)
		}
	}
	check("writes", small.writes, large.writes)
	check("pages", small.pages, large.pages)
	check("bytes", small.bytes, large.bytes)
	// Blocks: a merge writes one contiguous node per many keys, nowhere near one write per key.
	if large.writes > 0.05 || small.writes > 0.05 {
		t.Errorf("merges perform %.4f (64 runs) and %.4f (1024 runs) writes per key, want far below one (at most 0.05)", small.writes, large.writes)
	}
}
