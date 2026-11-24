// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"encoding/binary"
	"math/rand"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// gateCommitPairs are the pairs one commit of the single-host gate adds to each index: two acks of four records. The sizes are what the
// engine measures (TestGateWriteVolumePerAck...: per ack 424 bytes of keys and values in scan_time, 5,079 in scan_postings and 3,245 in
// scan_rows), so a commit is 8 time keys of 52 bytes, 50 postings keys of 202 and 40 rows of 162.
func gateCommitPairs(r *rand.Rand, prefixes [][]byte, seq int) map[string][]indexPair {
	out := map[string][]indexPair{}
	for range 8 {
		key := make([]byte, 24)
		binary.BigEndian.PutUint64(key, uint64(seq))
		r.Read(key[8:])
		val := make([]byte, 28)
		r.Read(val)
		out["scan_time"] = append(out["scan_time"], indexPair{Key: key, Value: val})
	}
	out["scan_postings"] = ioPairs(r, prefixes, 50)
	for range 40 {
		key := make([]byte, 17)
		key[0] = 'r'
		r.Read(key[1:])
		val := make([]byte, 145)
		r.Read(val)
		out[rowsIndex] = append(out[rowsIndex], indexPair{Key: key, Value: val})
	}
	return out
}

// mergeWindow is what the commits and the merges of a stretch of a history wrote, in 4 KiB pages of apply.db and in time.
type mergeWindow struct {
	commits               int
	commitPages           float64 // the pages the commits allocated, and one meta page each
	logicalBytes          float64 // the keys and values the commits wrote
	mergePages            float64
	commitTime, mergeTime time.Duration
	longestMerge          time.Duration // the longest compactIndexRuns call (all the chunk transactions of one merge)
	maxRuns               int           // the most ready runs of the three indexes at once
}

// levels is how many times the merges of the window rewrote what its commits wrote, as measured in pages.
func (w mergeWindow) levels() float64 { return w.mergePages * 4096 / w.logicalBytes }

// gateMergeHistory commits `commits` gate commits to a file opened like apply.db, merging after each commit what the merger would
// (the merger wakes every 200 ms, a commit comes about every 250), and returns the window of every `every` commits.
func gateMergeHistory(t *testing.T, commits, every int) []mergeWindow {
	t.Helper()
	r := rand.New(rand.NewSource(83))
	prefixes := ioPrefixes(r)
	db := ioOpen(t)
	var out []mergeWindow
	var w mergeWindow
	for c := 1; c <= commits; c++ {
		pairs := gateCommitPairs(r, prefixes, c)
		before := db.Stats()
		begin := time.Now()
		if err := db.Update(func(tx *bolt.Tx) error {
			for _, name := range []string{"scan_time", "scan_postings", rowsIndex} {
				if err := writeIndexRun(tx, name, pairs[name]); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		w.commitTime += time.Since(begin)
		mid := db.Stats()
		d := mid.Sub(&before)
		w.commitPages += float64(d.TxStats.GetPageAlloc())/4096 + 1
		begin = time.Now()
		for _, name := range []string{"scan_time", "scan_postings", rowsIndex} {
			for {
				one := time.Now()
				did, err := compactIndexRuns(db, name, compactOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if !did {
					break
				}
				w.longestMerge = max(w.longestMerge, time.Since(one))
			}
		}
		w.mergeTime += time.Since(begin)
		after := db.Stats()
		d = after.Sub(&mid)
		w.mergePages += float64(d.TxStats.GetPageAlloc()) / 4096
		w.commits++
		for _, ps := range pairs {
			for _, p := range ps {
				w.logicalBytes += float64(len(p.Key) + len(p.Value))
			}
		}
		runs := 0
		for _, name := range []string{"scan_time", "scan_postings", rowsIndex} {
			ready, _ := irRegistry(t, db, name)
			runs += len(ready)
		}
		w.maxRuns = max(w.maxRuns, runs)
		if c%every == 0 {
			out = append(out, w)
			w = mergeWindow{}
		}
	}
	return out
}

// TestGateMergesRewriteAKeyAtMostTwiceInTheFirstHours is the structural bound of the write volume of the index merges (D83). A commit of
// the gate writes one tiny run to each of three indexes (~17 KB), and a merge rewrites every key of its inputs, so what the merges write
// per commit is the number of levels a key climbs times what the commit wrote. With 8 runs to a level a key was rewritten once per
// level, log8 of the history: four to five times in the first hour (9.8 M of the 18.8 M pages apply.db wrote in a 900 s gate run, 18.6
// pages per ack). The levels hold 64 runs now (indexRunFanouts): a key is rewritten once until 4,096 commits (about 17 minutes at
// four commits a second), twice until 32,768 (an hour is 14,400), whatever the size of the commits.
//
// The test commits 8,192 commits (the first 35 minutes: 115 MB of keys and values over the three indexes) and reads the pages the
// merges wrote against the pages the commits wrote over the whole history: at most 2 levels, and never more than the ready runs the
// levels hold (3 x (63 + 63 + 7)).
func TestGateMergesRewriteAKeyAtMostTwiceInTheFirstHours(t *testing.T) {
	const commits, every = 8192, 1024
	windows := gateMergeHistory(t, commits, every)
	var total mergeWindow
	for i, w := range windows {
		total.commitPages += w.commitPages
		total.logicalBytes += w.logicalBytes
		total.mergePages += w.mergePages
		total.commitTime += w.commitTime
		total.mergeTime += w.mergeTime
		total.maxRuns = max(total.maxRuns, w.maxRuns)
		total.longestMerge = max(total.longestMerge, w.longestMerge)
		t.Logf("commits %5d-%5d: %.2f commit pages and %.2f merge pages per commit (%.2f levels), %v commit + %v merge per commit, longest merge %v, at most %d runs",
			i*every, (i+1)*every, w.commitPages/float64(w.commits), w.mergePages/float64(w.commits), w.levels(), w.commitTime/time.Duration(w.commits), w.mergeTime/time.Duration(w.commits), w.longestMerge, w.maxRuns)
	}
	t.Logf("history of %d commits: %.2f levels, longest merge %v", commits, total.levels(), total.longestMerge)
	if got := total.levels(); got > gateMergeLevelsBound {
		t.Errorf("the merges of %d gate commits wrote %.2f times the bytes of the keys and values the commits wrote, bound %.1f (a key is rewritten at most twice in the first 35 minutes)", commits, got, gateMergeLevelsBound)
	}
	if want := 3 * (63 + 63 + 7); total.maxRuns > want {
		t.Errorf("%d ready runs at once, the levels hold at most %d", total.maxRuns, want)
	}
}

// gateMergeLevelsBound is the bytes the merges write per byte of keys and values the commits write over the first 8,192 commits: two
// levels of merges (a key is rewritten once until 4,096 commits, twice after), 1.03 each in pages (a merge writes contiguous blocks
// of about the size of the keys and values it reads), 20 % headroom. With 8 runs to a level it is 4 levels of 1.4 (tiny merges write
// their buckets and registry entries too): 5.7 measured.
const gateMergeLevelsBound = 2.5
