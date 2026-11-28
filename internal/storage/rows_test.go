// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"slices"
	"sort"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// rowsModel is what the five buckets the row store replaces would hold: one map per table.
type rowsModel [len(rowTables)]map[string][]byte

func newRowsModel() *rowsModel {
	var m rowsModel
	for i := range m {
		m[i] = map[string][]byte{}
	}
	return &m
}

func (m *rowsModel) sortedKeys(t rowTable) []string {
	out := make([]string, 0, len(m[t.idx]))
	for k := range m[t.idx] {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// rowsTestDB opens a database with the five legacy buckets.
func rowsTestDB(t *testing.T) *bolt.DB {
	t.Helper()
	db := irOpen(t, 0)
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, tbl := range rowTables {
			if _, err := tx.CreateBucket([]byte(tbl.bucket)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return db
}

func smallRowBlocks(t *testing.T, n int) {
	t.Helper()
	old := rowsRunBlockBytes
	rowsRunBlockBytes = n
	t.Cleanup(func() { rowsRunBlockBytes = old })
}

func rowsRandKey(r *rand.Rand) []byte {
	k := make([]byte, 12+r.Intn(30))
	r.Read(k)
	if r.Intn(3) == 0 {
		k = append([]byte("org:project:source:"), k...) // keys that share a front, as the keys of the batches do
	}
	return k
}

func rowsRandValue(r *rand.Rand) []byte {
	v := make([]byte, 1+r.Intn(300))
	for i := range v {
		v[i] = "abcdefgh"[r.Intn(8)]
	}
	return v
}

// verifyRows compares the store a fresh transaction sees with the model: every key by Get, every table by cursor
// (in key order, each key once), and a key the model does not hold is absent.
func verifyRows(t *testing.T, db *bolt.DB, m *rowsModel, r *rand.Rand) {
	t.Helper()
	if err := db.View(func(tx *bolt.Tx) error {
		rs, err := rowsOf(tx)
		if err != nil {
			return err
		}
		for _, tbl := range rowTables {
			for k, v := range m[tbl.idx] {
				if got := rs.Get(tbl, []byte(k)); !bytes.Equal(got, v) || got == nil {
					return fmt.Errorf("table %s: Get(%x) = %x, want %x", tbl.bucket, k, got, v)
				}
			}
			for range 20 {
				k := rowsRandKey(r)
				if _, held := m[tbl.idx][string(k)]; held {
					continue
				}
				if got := rs.Get(tbl, k); got != nil {
					return fmt.Errorf("table %s: Get of a key nobody stored = %x", tbl.bucket, got)
				}
			}
			var keys []string
			if err := rs.ForEach(tbl, func(k, v []byte) error {
				want, ok := m[tbl.idx][string(k)]
				if !ok || !bytes.Equal(v, want) {
					return fmt.Errorf("table %s: the cursor yields %x -> %x, the model holds %x (%v)", tbl.bucket, k, v, want, ok)
				}
				keys = append(keys, string(k))
				return nil
			}); err != nil {
				return err
			}
			if !sort.StringsAreSorted(keys) || len(keys) != len(m[tbl.idx]) {
				return fmt.Errorf("table %s: the cursor yields %d keys (sorted %v), the model holds %d", tbl.bucket, len(keys), sort.StringsAreSorted(keys), len(m[tbl.idx]))
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The row store is the five buckets it replaces: whatever sequence of commits that insert, replace and delete
// rows, with merges between them, a reader sees what one bucket per table would hold. The legacy buckets
// carry rows from before the layout, and the blocks are small so that every table spans many.
func TestRowStoreIsTheUnionOfItsTablesWhateverTheHistory(t *testing.T) {
	smallRowBlocks(t, 400)
	for seed := int64(1); seed <= 4; seed++ {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			r := rand.New(rand.NewSource(seed))
			db := rowsTestDB(t)
			m := newRowsModel()
			// Rows of the single-bucket layout.
			if err := db.Update(func(tx *bolt.Tx) error {
				for _, tbl := range rowTables {
					for range 60 {
						k, v := rowsRandKey(r), rowsRandValue(r)
						if err := tx.Bucket([]byte(tbl.bucket)).Put(k, v); err != nil {
							return err
						}
						m[tbl.idx][string(k)] = v
					}
				}
				_, err := tx.CreateBucket([]byte(runsRegistry))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			verifyRows(t, db, m, r)
			for round := range 40 {
				switch round % 4 {
				case 0, 1: // a commit of appends: inserts, seen at once by the transaction that makes them
					err := db.Update(func(tx *bolt.Tx) error {
						return withIndexRun(tx, func() error {
							rs, err := rowsOf(tx)
							if err != nil {
								return err
							}
							for i := range 10 + r.Intn(30) {
								tbl := rowTables[r.Intn(len(rowTables))]
								k, v := rowsRandKey(r), rowsRandValue(r)
								if _, held := m[tbl.idx][string(k)]; held {
									continue
								}
								if rs.Get(tbl, k) != nil {
									return fmt.Errorf("a key nobody stored is held")
								}
								if err := rs.Insert(tbl, k, v); err != nil {
									return err
								}
								m[tbl.idx][string(k)] = v
								if !bytes.Equal(rs.Get(tbl, k), v) {
									return fmt.Errorf("the transaction does not see the row it inserted")
								}
								if i == 5 { // a cursor in the middle of a commit sees the collected rows
									n := 0
									if err := rs.ForEach(tbl, func(_, _ []byte) error { n++; return nil }); err != nil {
										return err
									}
									if n != len(m[tbl.idx]) {
										return fmt.Errorf("mid-commit cursor yields %d rows, want %d", n, len(m[tbl.idx]))
									}
								}
							}
							return nil
						})
					})
					if err != nil {
						t.Fatal(err)
					}
				case 2: // erasure: delete rows (some of them absent), replace others, create some
					err := db.Update(func(tx *bolt.Tx) error {
						rs, err := rowsOf(tx)
						if err != nil {
							return err
						}
						for _, tbl := range rowTables {
							keys := m.sortedKeys(tbl)
							for range 6 {
								if len(keys) == 0 {
									break
								}
								k := keys[r.Intn(len(keys))]
								found, err := rs.Delete(tbl, []byte(k))
								_, held := m[tbl.idx][k]
								if err != nil || found != held {
									return fmt.Errorf("Delete(%x) = %v, %v; held %v", k, found, err, held)
								}
								delete(m[tbl.idx], k)
							}
							if found, err := rs.Delete(tbl, rowsRandKey(r)); err != nil || found {
								return fmt.Errorf("Delete of a key nobody stored = %v, %v", found, err)
							}
							var kvs []rowKV
							seen := map[string]bool{}
							for range 8 {
								var k []byte
								if keys := m.sortedKeys(tbl); len(keys) > 0 && r.Intn(4) != 0 {
									k = []byte(keys[r.Intn(len(keys))])
								} else {
									k = rowsRandKey(r)
								}
								if seen[string(k)] {
									continue
								}
								seen[string(k)] = true
								v := rowsRandValue(r)
								kvs = append(kvs, rowKV{Key: k, Value: v})
								m[tbl.idx][string(k)] = v
							}
							if err := rs.SetMany(tbl, kvs); err != nil {
								return err
							}
						}
						return nil
					})
					if err != nil {
						t.Fatal(err)
					}
				case 3:
					for {
						did, err := compactIndexRuns(db, rowsIndex, compactOptions{Fanout: 3, MaxChunkBytes: 1500})
						if err != nil {
							t.Fatal(err)
						}
						if !did {
							break
						}
					}
					checkRowBlooms(t, db)
				}
				verifyRows(t, db, m, r)
			}
		})
	}
}

// A merge builds its output over several transactions: an erasure, a replacement or a new commit that runs between
// two of them must be in the output when it is flipped to ready (a deleted row stays deleted).
func TestRowStoreChangesDuringAMergeReachItsOutput(t *testing.T) {
	smallRowBlocks(t, 300)
	r := rand.New(rand.NewSource(11))
	db := rowsTestDB(t)
	m := newRowsModel()
	if err := db.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucket([]byte(runsRegistry)); return err }); err != nil {
		t.Fatal(err)
	}
	commit := func(n int) {
		err := db.Update(func(tx *bolt.Tx) error {
			return withIndexRun(tx, func() error {
				rs, err := rowsOf(tx)
				if err != nil {
					return err
				}
				for range n {
					tbl := rowTables[r.Intn(len(rowTables))]
					k, v := rowsRandKey(r), rowsRandValue(r)
					m[tbl.idx][string(k)] = v
					if err := rs.Insert(tbl, k, v); err != nil {
						return err
					}
				}
				return nil
			})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for range 4 {
		commit(60)
	}
	between := 0
	irSetHook(t, func() {
		between++
		err := db.Update(func(tx *bolt.Tx) error {
			rs, err := rowsOf(tx)
			if err != nil {
				return err
			}
			for _, tbl := range rowTables {
				keys := m.sortedKeys(tbl)
				for range 5 {
					k := keys[r.Intn(len(keys))]
					if _, held := m[tbl.idx][k]; !held {
						continue
					}
					if r.Intn(2) == 0 {
						if found, err := rs.Delete(tbl, []byte(k)); err != nil || !found {
							return fmt.Errorf("Delete = %v, %v", found, err)
						}
						delete(m[tbl.idx], k)
					} else {
						v := rowsRandValue(r)
						if err := rs.Set(tbl, []byte(k), v); err != nil {
							return err
						}
						m[tbl.idx][k] = v
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Error(err)
		}
		commit(10)
	})
	did, err := compactIndexRuns(db, rowsIndex, compactOptions{Fanout: 4, MaxChunkBytes: 700})
	if err != nil || !did {
		t.Fatalf("merge = %v, %v", did, err)
	}
	if between == 0 {
		t.Fatal("the merge was one transaction: nothing ran between its chunks")
	}
	checkRowBlooms(t, db)
	verifyRows(t, db, m, r)
}

// checkRowBlooms: every ready run of the row store has a bloom filter, and no other filter is left.
func checkRowBlooms(t *testing.T, db *bolt.DB) {
	t.Helper()
	if err := db.View(func(tx *bolt.Tx) error {
		reg := tx.Bucket([]byte(runsRegistry))
		runs, err := listIndexRuns(reg, rowsIndex)
		if err != nil {
			return err
		}
		filters := 0
		prefix := []byte(rowsIndex + ".bloom/")
		_ = reg.ForEach(func(k, _ []byte) error {
			if bytes.HasPrefix(k, prefix) {
				filters++
			}
			return nil
		})
		for _, run := range runs {
			if run.meta.State == indexRunReady && reg.Get(indexRunBloomKey(rowsIndex, run.id)) == nil {
				return fmt.Errorf("run %d has no bloom filter", run.id)
			}
		}
		if filters != len(runs) {
			return fmt.Errorf("%d bloom filters for %d runs", filters, len(runs))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A bloom filter has no false negatives and, at 12 bits a key, few false positives.
func TestRowBloomHoldsEveryKeyAndRejectsMostOthers(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	const n = 5000
	b := newBloomBuilder(n)
	keys := make([][]byte, n)
	for i := range keys {
		keys[i] = rowsRandKey(r)
		keys[i][0] = 'b'
		b.add(keys[i])
	}
	for _, k := range keys {
		h1, h2 := bloomHash(k)
		if !bloomMayHold(b.bytes(), h1, h2) {
			t.Fatalf("the filter lost key %x", k)
		}
	}
	positives := 0
	const probes = 20000
	for range probes {
		h1, h2 := bloomHash(rowsRandKey(r))
		if bloomMayHold(b.bytes(), h1, h2) {
			positives++
		}
	}
	if rate := float64(positives) / probes; rate > 0.03 {
		t.Fatalf("false positive rate %.3f at %d bits a key", rate, bloomBitsPerKey)
	}
	// A filter that does not parse holds everything: the run is asked.
	h1, h2 := bloomHash(keys[0])
	for _, bad := range [][]byte{nil, {1}, b.bytes()[:bloomHeader+bloomBlockBytes-1], append([]byte{9}, b.bytes()[1:]...)} {
		if !bloomMayHold(bad, h1, h2) {
			t.Fatalf("a damaged filter %d bytes long rejected a key", len(bad))
		}
	}
}

// edit rewrites each block it changes once and leaves the run a valid run: keys found, refiled under a new last
// key, blocks that lose every pair gone, and a key the run does not hold reported as not found.
func TestBlockRunEditChangesPairsInPlace(t *testing.T) {
	smallRowBlocks(t, 300)
	for seed := int64(1); seed <= 6; seed++ {
		r := rand.New(rand.NewSource(seed))
		db := irOpen(t, 0)
		kv := map[string][]byte{}
		var pairs []indexPair
		for len(kv) < 400 {
			k := append([]byte{'b'}, rowsRandKey(r)...)
			if _, ok := kv[string(k)]; ok {
				continue
			}
			v := rowsRandValue(r)
			kv[string(k)] = v
			pairs = append(pairs, indexPair{Key: k, Value: v})
		}
		if err := db.Update(func(tx *bolt.Tx) error { return writeIndexRun(tx, rowsIndex, slices.Clone(pairs)) }); err != nil {
			t.Fatal(err)
		}
		for round := range 25 {
			err := db.Update(func(tx *bolt.Tx) error {
				run := blockRun{tx.Bucket(indexRunBucketName(rowsIndex, 1))}
				var keys []string
				for k := range kv {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				picked := map[string]blockEdit{}
				for range 1 + r.Intn(40) {
					var k string
					switch {
					case len(keys) > 0 && r.Intn(5) != 0:
						k = keys[r.Intn(len(keys))]
					case r.Intn(2) == 0:
						k = string(append([]byte{'b'}, rowsRandKey(r)...)) // not held (or by chance held: the model decides)
					default:
						k = "z" + string(rowsRandKey(r)) // above every key of the run
					}
					e := blockEdit{Key: []byte(k)}
					if r.Intn(2) == 0 || round%5 == 4 {
						e.Delete = true
					} else {
						e.Value = rowsRandValue(r)
					}
					picked[k] = e
				}
				edits := make([]blockEdit, 0, len(picked))
				for _, e := range picked {
					edits = append(edits, e)
				}
				sort.Slice(edits, func(i, j int) bool { return bytes.Compare(edits[i].Key, edits[j].Key) < 0 })
				found, err := run.edit(edits)
				if err != nil {
					return err
				}
				for i, e := range edits {
					_, held := kv[string(e.Key)]
					if found[i] != held {
						return fmt.Errorf("edit of %x: found %v, held %v", e.Key, found[i], held)
					}
					switch {
					case !held:
					case e.Delete:
						delete(kv, string(e.Key))
					default:
						kv[string(e.Key)] = e.Value
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := db.View(func(tx *bolt.Tx) error {
				b := tx.Bucket(indexRunBucketName(rowsIndex, 1))
				run := blockRun{b}
				c := run.Cursor().(*blockCursor)
				n := 0
				var last []byte
				for k, v := c.First(); k != nil; k, v = c.Next() {
					if last != nil && bytes.Compare(last, k) >= 0 {
						return fmt.Errorf("the run is not in key order after round %d", round)
					}
					last = bytes.Clone(k)
					if !bytes.Equal(kv[string(k)], v) {
						return fmt.Errorf("run holds %x -> %x, model %x", k, v, kv[string(k)])
					}
					n++
				}
				if err := c.Err(); err != nil || n != len(kv) {
					return fmt.Errorf("run holds %d pairs (%v), model %d", n, err, len(kv))
				}
				for k, v := range kv {
					if !bytes.Equal(run.Get([]byte(k)), v) {
						return fmt.Errorf("Get(%x) disagrees with the model", k)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if len(kv) == 0 {
				break
			}
		}
	}
}

// A damaged block is corruption, never an empty table: a cursor over the table reports it.
func TestRowStoreReportsADamagedBlock(t *testing.T) {
	smallRowBlocks(t, 300)
	r := rand.New(rand.NewSource(9))
	db := rowsTestDB(t)
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucket([]byte(runsRegistry)); err != nil {
			return err
		}
		return withIndexRun(tx, func() error {
			rs, err := rowsOf(tx)
			if err != nil {
				return err
			}
			for range 50 {
				if err := rs.Insert(tblReceipts, rowsRandKey(r), rowsRandValue(r)); err != nil {
					return err
				}
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexRunBucketName(rowsIndex, 1))
		k, v := b.Cursor().First()
		damaged := bytes.Clone(v)
		damaged[0] ^= 0xff // the magic
		return b.Put(bytes.Clone(k), damaged)
	}); err != nil {
		t.Fatal(err)
	}
	err := db.View(func(tx *bolt.Tx) error {
		return tableForEach(tx, tblReceipts, func(_, _ []byte) error { return nil })
	})
	if irCode(err) != model.Corrupt {
		t.Fatalf("a table over a damaged block ended with %v, want corrupt", err)
	}
}

// A file of the runs layout that the row store does not know (version 2: its rows are in the buckets) opens,
// moves to version 3, serves every row from the buckets, and keeps new rows in runs without touching the old ones.
func TestRunsLayoutFileOfTheQueryIndexesOnlyMovesToTheRowStore(t *testing.T) {
	withoutPayloadToggle(t)
	store, service, cred, desc := fixture(t)
	fx := layoutFixture{store, service, cred, desc}
	dir := t.TempDir()
	e, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	first := appendLayoutBatches(t, e, fx, 10)
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	editDB(t, dir, func(tx *bolt.Tx) error {
		moveRowRunsToLegacy(t, tx)
		return tx.Bucket([]byte("meta")).Put([]byte("scan_index_version"), []byte{scanIndexRuns})
	})
	e, err = openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	if marker, registry := scanLayoutMarker(t, e); marker != scanIndexRows || !registry || !e.runsLayout.Load() {
		t.Fatalf("a version 2 file became version %d, registry %v, runsLayout %v", marker, registry, e.runsLayout.Load())
	}
	for _, name := range []string{"batches", "receipts", "metrics", "scan_pages", "scan_commits"} {
		if base, runs := layoutEntries(t, e, name); base == 0 || runs != 0 {
			t.Fatalf("%s: %d entries in the bucket and %d in runs, want the rows of the file in the bucket", name, base, runs)
		}
	}
	if got := scanAllRows(t, e, fx, first); got != 10 {
		t.Fatalf("a query returns %d rows of the old file, want 10", got)
	}
	more := appendLayoutBatches(t, e, fx, 6)
	for _, name := range []string{"batches", "receipts", "scan_pages", "scan_commits"} {
		if base, runs := layoutEntries(t, e, name); base == 0 || runs == 0 {
			t.Fatalf("%s: %d entries in the bucket and %d in runs after new appends, want both", name, base, runs)
		}
	}
	all := append(append([]model.Cursor{}, first...), more...)
	if got := scanAllRows(t, e, fx, all); got != 16 {
		t.Fatalf("a query returns %d rows, want 16", got)
	}
	if err = e.db.View(validateIndexIntegrity); err != nil {
		t.Fatalf("integrity: %v", err)
	}
	// The rows that live in the buckets are erased, flushed and read like the others.
	if err = e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := scanAllRows(t, e, fx, all); got != 16 {
		t.Fatalf("after the segments were published a query returns %d rows, want 16", got)
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	e, err = openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if got := scanAllRows(t, e, fx, all); got != 16 {
		t.Fatalf("after the reopen a query returns %d rows, want 16", got)
	}
}

// moveRowRunsToLegacy turns the file of tx into the image of a build that had the query-index runs but no row
// store: every row of the row runs back into its bucket, the row runs, their filters and their registry entries gone.
func moveRowRunsToLegacy(t *testing.T, tx *bolt.Tx) {
	t.Helper()
	var runs []*bolt.Bucket
	var names [][]byte
	_ = tx.ForEach(func(n []byte, b *bolt.Bucket) error {
		if bytes.HasPrefix(n, []byte(rowsIndex+".r")) {
			runs = append(runs, b)
			names = append(names, bytes.Clone(n))
		}
		return nil
	})
	for _, b := range runs {
		for _, tbl := range rowTables {
			err := tagRunBucket{b, tbl.tag}.ForEach(func(k, v []byte) error { return tx.Bucket([]byte(tbl.bucket)).Put(bytes.Clone(k), bytes.Clone(v)) })
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, n := range names {
		if err := tx.DeleteBucket(n); err != nil {
			t.Fatal(err)
		}
	}
	if reg := tx.Bucket([]byte(runsRegistry)); reg != nil {
		var drop [][]byte
		_ = reg.ForEach(func(k, _ []byte) error {
			if bytes.HasPrefix(k, []byte(rowsIndex)) {
				drop = append(drop, bytes.Clone(k))
			}
			return nil
		})
		for _, k := range drop {
			if err := reg.Delete(k); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// A read transaction loads the row store for every acknowledged append (receipt lookup, validation, the read of a
// batch), and opening the bucket of every run was the largest cost of that (L2w20Admission38: 8 % of the cpu of the
// single-host gate). The runs of a read-only transaction are opened when a Get that their bloom filters do not
// exclude asks them; a ready run without its bucket is still found: Err and tableGet report it, a writing
// transaction fails at the load.
func TestRowStoreOpensOnlyTheRunsAReadAsks(t *testing.T) {
	smallRowBlocks(t, 400)
	r := rand.New(rand.NewSource(38))
	db := rowsTestDB(t)
	if err := db.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucket([]byte(runsRegistry)); return err }); err != nil {
		t.Fatal(err)
	}
	const commits = 12
	var firstKey, lastKey []byte
	for c := range commits {
		err := db.Update(func(tx *bolt.Tx) error {
			return withIndexRun(tx, func() error {
				rs, err := rowsOf(tx)
				if err != nil {
					return err
				}
				for range 20 {
					k := rowsRandKey(r)
					if c == 0 && firstKey == nil {
						firstKey = k
					}
					if c == commits-1 {
						lastKey = k
					}
					if err := rs.Insert(tblReceipts, k, rowsRandValue(r)); err != nil {
						return err
					}
				}
				return nil
			})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	opened := func(rs *rowStore) (n int) {
		for i := range rs.runs {
			if rs.runs[i].opened {
				n++
			}
		}
		return n
	}
	if err := db.View(func(tx *bolt.Tx) error {
		rs, err := loadRowStore(tx)
		if err != nil {
			return err
		}
		if len(rs.runs) != commits {
			return fmt.Errorf("%d runs, want one per commit (%d)", len(rs.runs), commits)
		}
		if n := opened(rs); n != 0 {
			return fmt.Errorf("loading the store in a read transaction opened %d of %d run buckets", n, len(rs.runs))
		}
		for range 50 {
			if got := rs.Get(tblReceipts, rowsRandKey(r)); got != nil {
				return fmt.Errorf("Get of a key nobody stored = %x", got)
			}
		}
		if n := opened(rs); n > len(rs.runs)/2 {
			return fmt.Errorf("50 Gets of absent keys opened %d of %d run buckets: the bloom filters are not asked first", n, len(rs.runs))
		}
		if rs.Get(tblReceipts, lastKey) == nil || rs.Get(tblReceipts, firstKey) == nil {
			return fmt.Errorf("a stored row is not found through the lazily opened runs")
		}
		return rs.Err()
	}); err != nil {
		t.Fatal(err)
	}
	// The oldest run loses its bucket (damage): a reader that asks for one of its rows is told, and a writer fails at the load.
	if err := db.Update(func(tx *bolt.Tx) error {
		reg := tx.Bucket([]byte(runsRegistry))
		entries, err := listIndexRuns(reg, rowsIndex)
		if err != nil {
			return err
		}
		return tx.DeleteBucket(indexRunBucketName(rowsIndex, entries[0].id))
	}); err != nil {
		t.Fatal(err)
	}
	err := db.View(func(tx *bolt.Tx) error {
		if _, err := tableGet(tx, tblReceipts, firstKey); irCode(err) != model.Corrupt {
			return fmt.Errorf("tableGet of a row of the damaged run = %v, want model.Corrupt", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error { _, err := loadRowStore(tx); return err }); irCode(err) != model.Corrupt {
		t.Fatalf("a writing transaction over a ready run without its bucket = %v, want model.Corrupt", err)
	}
}

// Loading the row store is done by every read transaction of an acknowledged append (a receipt lookup, the validation, the read of a
// batch: about ten a request), so what it allocates is allocated ten times a request, and the garbage collector is a tenth of the cpu
// of the single-host gate (L2w20Admission39). It read the registry once for the entries (a slice grown by doubling) and once a
// run for its bloom filter (a cursor each, a slice grown by doubling again): the allocations were a function of the number of runs,
// which grows with the history. The registry is read in one pass, and what is allocated does not depend on how many runs the store holds.
func TestRowStoreLoadAllocationsDoNotGrowWithTheRuns(t *testing.T) {
	smallRowBlocks(t, 400)
	allocs := func(commits int) (perLoad float64, runs int) {
		t.Helper()
		r := rand.New(rand.NewSource(39))
		db := rowsTestDB(t)
		if err := db.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucket([]byte(runsRegistry)); return err }); err != nil {
			t.Fatal(err)
		}
		for range commits {
			err := db.Update(func(tx *bolt.Tx) error {
				return withIndexRun(tx, func() error {
					rs, err := rowsOf(tx)
					if err != nil {
						return err
					}
					for range 10 {
						if err := rs.Insert(tblReceipts, rowsRandKey(r), rowsRandValue(r)); err != nil {
							return err
						}
					}
					return nil
				})
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := db.View(func(tx *bolt.Tx) error {
			rs, err := loadRowStore(tx)
			if err != nil {
				return err
			}
			runs = len(rs.runs)
			perLoad = testing.AllocsPerRun(50, func() {
				if _, err := loadRowStore(tx); err != nil {
					t.Error(err)
				}
			})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return perLoad, runs
	}
	few, fewRuns := allocs(4)
	many, manyRuns := allocs(48)
	t.Logf("loading the row store: %.0f allocations with %d runs, %.0f with %d", few, fewRuns, many, manyRuns)
	if fewRuns != 4 || manyRuns != 48 {
		t.Fatalf("the fixture holds %d and %d runs, want 4 and 48", fewRuns, manyRuns)
	}
	if many > few+4 {
		t.Errorf("a load allocates %.0f times with %d runs and %.0f with %d: it must not grow with the runs", many, manyRuns, few, fewRuns)
	}
	if many > 16 {
		t.Errorf("a load of %d runs allocates %.0f times, want at most 16", manyRuns, many)
	}
}

// The registry is read in one pass that pairs each ready run with its bloom filter; a run without one (a file an older release
// wrote), a filter without a run (left by a crashed merge) and a run that is still building are what they were when every run was
// asked for its filter on its own.
func TestRowStoreLoadPairsRunsAndFilters(t *testing.T) {
	smallRowBlocks(t, 400)
	r := rand.New(rand.NewSource(40))
	db := rowsTestDB(t)
	if err := db.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucket([]byte(runsRegistry)); return err }); err != nil {
		t.Fatal(err)
	}
	for range 9 {
		err := db.Update(func(tx *bolt.Tx) error {
			return withIndexRun(tx, func() error {
				rs, err := rowsOf(tx)
				if err != nil {
					return err
				}
				for range 5 {
					if err := rs.Insert(tblReceipts, rowsRandKey(r), rowsRandValue(r)); err != nil {
						return err
					}
				}
				return nil
			})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// Runs 2 and 5 lose their filters, a filter of a run that is not registered appears (id 100), run 7 becomes a building run.
	if err := db.Update(func(tx *bolt.Tx) error {
		reg := tx.Bucket([]byte(runsRegistry))
		for _, id := range []uint64{2, 5} {
			if err := reg.Delete(indexRunBloomKey(rowsIndex, id)); err != nil {
				return err
			}
		}
		if err := reg.Put(indexRunBloomKey(rowsIndex, 100), []byte{1, 2, 3}); err != nil {
			return err
		}
		return reg.Put(indexRunRegKey(rowsIndex, 7), indexRunMetaJSON(indexRunMeta{State: indexRunBuilding, Level: 1}))
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.View(func(tx *bolt.Tx) error {
		reg := tx.Bucket([]byte(runsRegistry))
		entries, err := listIndexRuns(reg, rowsIndex)
		if err != nil {
			return err
		}
		var want []rowRun
		for i := len(entries) - 1; i >= 0; i-- { // newest first, the filter looked up on its own
			if e := entries[i]; e.meta.State == indexRunReady {
				want = append(want, rowRun{id: e.id, bloom: reg.Get(indexRunBloomKey(rowsIndex, e.id))})
			}
		}
		rs, err := loadRowStore(tx)
		if err != nil {
			return err
		}
		if len(rs.runs) != len(want) || len(want) != 8 {
			return fmt.Errorf("%d ready runs loaded, want %d (8: nine commits and a building run)", len(rs.runs), len(want))
		}
		for i := range want {
			if rs.runs[i].id != want[i].id || !bytes.Equal(rs.runs[i].bloom, want[i].bloom) || (rs.runs[i].bloom == nil) != (want[i].bloom == nil) || rs.runs[i].opened {
				return fmt.Errorf("run %d of the store is %d with a filter of %d bytes, want %d with %d bytes", i, rs.runs[i].id, len(rs.runs[i].bloom), want[i].id, len(want[i].bloom))
			}
		}
		if rs.runs[0].id < rs.runs[len(rs.runs)-1].id {
			return fmt.Errorf("the runs are not newest first")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A read-only transaction opens the legacy bucket of a table when a lookup reaches it (bolt opens a bucket afresh on every ask of a
// read-only transaction, so six openings in every load were the larger part of what a load allocated); a writing transaction opens
// them all at the load. A file that lacks one is model.Corrupt where it is used (tableGet, Err) and at the load of a writer.
func TestRowStoreOpensLegacyBucketsWhenAsked(t *testing.T) {
	smallRowBlocks(t, 400)
	db := rowsTestDB(t)
	if err := db.View(func(tx *bolt.Tx) error {
		rs, err := loadRowStore(tx)
		if err != nil {
			return err
		}
		for _, tbl := range rowTables {
			if rs.legacy[tbl.idx] != nil {
				return fmt.Errorf("loading the store in a read transaction opened the legacy bucket of %s", tbl.bucket)
			}
		}
		if rs.Get(tblReceipts, []byte("absent")) != nil || rs.Err() != nil {
			return fmt.Errorf("Get of an absent key: %v", rs.Err())
		}
		for _, tbl := range rowTables {
			if opened := rs.legacy[tbl.idx] != nil; opened != (tbl.idx == tblReceipts.idx) {
				return fmt.Errorf("after one Get of %s the legacy bucket of %s is opened: %v", tblReceipts.bucket, tbl.bucket, opened)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		rs, err := loadRowStore(tx)
		if err != nil {
			return err
		}
		for _, tbl := range rowTables {
			if rs.legacy[tbl.idx] == nil {
				return fmt.Errorf("a writing transaction did not open the legacy bucket of %s at the load", tbl.bucket)
			}
		}
		return tx.DeleteBucket([]byte(tblMetrics.bucket))
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.View(func(tx *bolt.Tx) error {
		if _, err := tableGet(tx, tblReceipts, []byte("absent")); err != nil {
			return fmt.Errorf("a table whose bucket is there answered %v", err)
		}
		if _, err := tableGet(tx, tblMetrics, []byte("absent")); irCode(err) != model.Corrupt {
			return fmt.Errorf("tableGet of a table without its legacy bucket = %v, want model.Corrupt", err)
		}
		return tableForEach(tx, tblMetrics, func(k, v []byte) error { return nil })
	}); irCode(err) != model.Corrupt {
		t.Fatalf("a scan of a table without its legacy bucket = %v, want model.Corrupt", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error { _, err := loadRowStore(tx); return err }); irCode(err) != model.Corrupt {
		t.Fatalf("a writing transaction over a file without a legacy bucket = %v, want model.Corrupt", err)
	}
}
