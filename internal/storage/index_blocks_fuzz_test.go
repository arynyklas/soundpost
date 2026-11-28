// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The merged cursor, Get and Delete of an index made of block runs and a base bucket answer like a plain
// sorted map, through a random history of new runs (blocks of 48 bytes to 128 KiB), deletes of existing and of
// absent keys, writes to the base, and merges cut into chunks of 64 bytes to 1 MiB with caps that make some
// runs final.
func TestIndexRunsRandomizedAgainstMap(t *testing.T) {
	iters := 40
	if raceEnabled {
		iters = 10
	}
	for it := range iters {
		seed := int64(9100 + it)
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			r := rand.New(rand.NewSource(seed))
			old := indexRunBlockBytes
			indexRunBlockBytes = []int{48, 150, 700, 4096, indexBlockDefaultB}[r.Intn(5)]
			t.Cleanup(func() { indexRunBlockBytes = old })
			db := irOpen(t, 0)
			md := &irModel{kv: map[string][]byte{}}
			if err := db.Update(func(tx *bolt.Tx) error {
				b, err := tx.CreateBucket([]byte(irIndex))
				if err != nil {
					return err
				}
				for _, k := range irNewKeys(r, md, r.Intn(150)) {
					v := irRandBytes(r, r.Intn(31))
					md.kv[string(k)] = v
					if err := b.Put(k, v); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			for step := range 60 {
				switch r.Intn(9) {
				case 0, 1: // one to three runs in one transaction
					if err := db.Update(func(tx *bolt.Tx) error {
						for range 1 + r.Intn(3) {
							var pairs []indexPair
							for _, k := range irNewKeys(r, md, 1+r.Intn(120)) {
								v := irRandBytes(r, r.Intn(31))
								md.kv[string(k)] = v
								pairs = append(pairs, indexPair{Key: k, Value: v})
							}
							if err := writeIndexRun(tx, irIndex, pairs); err != nil {
								return err
							}
						}
						return nil
					}); err != nil {
						t.Fatalf("step %d: %v", step, err)
					}
				case 2: // deletes, checked in the transaction that makes them
					if err := db.Update(func(tx *bolt.Tx) error {
						s, err := openIndexSet(tx, irIndex)
						if err != nil {
							return err
						}
						keys := md.keys()
						for range r.Intn(40) {
							if len(keys) == 0 {
								break
							}
							k := keys[r.Intn(len(keys))]
							_, present := md.kv[k]
							found, err := s.Delete([]byte(k))
							if err != nil || found != present {
								t.Fatalf("step %d: Delete(%x) found=%v want %v err=%v", step, k, found, present, err)
							}
							delete(md.kv, k)
						}
						for _, k := range irNewKeys(r, md, 3) {
							if found, err := s.Delete(k); err != nil || found {
								t.Fatalf("step %d: Delete of the absent %x: %v %v", step, k, found, err)
							}
						}
						irVerify(t, s, md, r, 15)
						return nil
					}); err != nil {
						t.Fatalf("step %d: %v", step, err)
					}
				case 3, 4: // one merge
					opt := compactOptions{
						Fanout:        2 + r.Intn(4),
						MaxChunkBytes: []int{64, 300, 2048, 1 << 20}[r.Intn(4)],
						MaxRunBytes:   []int64{0, 400, 3000}[r.Intn(3)],
					}
					if _, err := compactIndexRuns(db, irIndex, opt); err != nil {
						t.Fatalf("step %d: %v", step, err)
					}
				case 5: // the rare path: a key into the base
					if err := db.Update(func(tx *bolt.Tx) error {
						s, err := openIndexSet(tx, irIndex)
						if err != nil {
							return err
						}
						for _, k := range irNewKeys(r, md, 1+r.Intn(5)) {
							v := irRandBytes(r, r.Intn(31))
							if err := s.Put(k, v); err != nil {
								return err
							}
							md.kv[string(k)] = v
						}
						return nil
					}); err != nil {
						t.Fatalf("step %d: %v", step, err)
					}
				default:
					irCheckDB(t, db, irIndex, md, r)
					ibCheckRuns(t, db, irIndex)
				}
			}
			irCheckDB(t, db, irIndex, md, r)
			for {
				did, err := compactIndexRuns(db, irIndex, compactOptions{Fanout: 3, MaxChunkBytes: 1 << 10})
				if err != nil {
					t.Fatal(err)
				}
				if !did {
					break
				}
			}
			irCheckDB(t, db, irIndex, md, r)
			ibCheckRuns(t, db, irIndex)
			if _, building := irRegistry(t, db, irIndex); len(building) != 0 {
				t.Fatal("building run left")
			}
		})
	}
}

// A merged cursor over hundreds of runs is exact (the heap holds every source) and a Seek lands where the
// map says.
func TestIndexCursorOverManyRuns(t *testing.T) {
	r := rand.New(rand.NewSource(41))
	old := indexRunBlockBytes
	indexRunBlockBytes = 300
	t.Cleanup(func() { indexRunBlockBytes = old })
	db := irOpen(t, 0)
	md := irRandModel(r, 4000)
	written, _ := irLayout(t, db, r, irIndex, md, 400, 5)
	if written < 300 {
		t.Fatalf("%d runs, the test needs hundreds", written)
	}
	irCheckDB(t, db, irIndex, md, r)
	ibCheckRuns(t, db, irIndex)
}

func ibRunMeta(t *testing.T, id uint64, level int, bytes int64) indexRunEntry {
	t.Helper()
	return indexRunEntry{id: id, meta: indexRunMeta{State: indexRunReady, Level: level, Count: 1, Bytes: bytes}}
}

func ibIDs(in []indexRunEntry) []uint64 {
	var out []uint64
	for _, e := range in {
		out = append(out, e.id)
	}
	return out
}

// A run that reached the cap is final: planIndexMerge neither takes it as an input nor counts it towards the
// fanout of its level.
func TestPlanIndexMergeIgnoresRunsAtTheCap(t *testing.T) {
	small := func(id uint64) indexRunEntry { return ibRunMeta(t, id, 0, 100) }
	big := func(id uint64) indexRunEntry { return ibRunMeta(t, id, 0, 5000) }
	cases := []struct {
		name   string
		runs   []indexRunEntry
		fanout int
		cap    int64
		want   []uint64
	}{
		{"below the cap", []indexRunEntry{small(1), small(2), small(3), small(4)}, 4, 1000, []uint64{1, 2, 3, 4}},
		{"at the cap", []indexRunEntry{small(1), small(2), small(3), small(4)}, 2, 100, nil},
		{"capped runs are skipped", []indexRunEntry{big(1), big(2), small(3), small(4)}, 2, 1000, []uint64{3, 4}},
		{"capped runs do not fill a fanout", []indexRunEntry{big(1), small(2), small(3)}, 3, 1000, nil},
		{"a lower level first", []indexRunEntry{ibRunMeta(t, 1, 1, 100), ibRunMeta(t, 2, 1, 100), small(3), small(4)}, 2, 1000, []uint64{3, 4}},
	}
	for _, c := range cases {
		_, in := planIndexMerge(c.runs, c.fanout, c.cap)
		if fmt.Sprint(ibIDs(in)) != fmt.Sprint(c.want) {
			t.Errorf("%s: inputs %v, want %v", c.name, ibIDs(in), c.want)
		}
	}
	building := append(append([]indexRunEntry(nil), big(1)), indexRunEntry{id: 2, meta: indexRunMeta{State: indexRunBuilding}})
	if b, in := planIndexMerge(building, 2, 1000); !b || len(in) != 0 {
		t.Errorf("a building run: building=%v inputs=%v", b, ibIDs(in))
	}
}

// Merging stops where runs reach the cap: 16 runs of 300 bytes, fanout 2, cap 1000 end as four runs of
// level 2 (1200 bytes each), and the index is unchanged.
func TestIndexMergeStopsAtTheCap(t *testing.T) {
	r := rand.New(rand.NewSource(43))
	db := irOpen(t, 0)
	md := &irModel{kv: map[string][]byte{}}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucket([]byte(irIndex))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	keys := r.Perm(160)
	for run := range 16 {
		var pairs []indexPair
		for _, i := range keys[run*10 : run*10+10] {
			k, v := []byte(fmt.Sprintf("key-%016d", i)), []byte(fmt.Sprintf("v%09d", i))
			md.kv[string(k)] = v
			pairs = append(pairs, indexPair{Key: k, Value: v})
		}
		if err := db.Update(func(tx *bolt.Tx) error { return writeIndexRun(tx, irIndex, pairs) }); err != nil {
			t.Fatal(err)
		}
	}
	merges := 0
	for {
		did, err := compactIndexRuns(db, irIndex, compactOptions{Fanout: 2, MaxRunBytes: 1000})
		if err != nil {
			t.Fatal(err)
		}
		if !did {
			break
		}
		merges++
	}
	ready, building := irRegistry(t, db, irIndex)
	if len(building) != 0 || len(ready) != 4 || merges != 8+4 {
		t.Fatalf("%d merges left %d ready and %d building runs, want 12 merges and 4 ready runs", merges, len(ready), len(building))
	}
	for _, e := range ready {
		if e.meta.Level != 2 || e.meta.Bytes != 1200 || e.meta.Count != 40 {
			t.Fatalf("run %d: level %d, %d bytes, %d keys, want level 2, 1200 bytes, 40 keys", e.id, e.meta.Level, e.meta.Bytes, e.meta.Count)
		}
	}
	irCheckDB(t, db, irIndex, md, r)
	if _, err := compactIndexRuns(db, irIndex, compactOptions{MaxRunBytes: -1}); irCode(err) != model.Invalid {
		t.Fatalf("a negative cap: %v", err)
	}
}
