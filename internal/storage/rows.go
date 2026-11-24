// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"encoding/binary"
	"slices"
	"sync/atomic"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The row store: the random-keyed buckets of the data engine in the block-runs layout (decision D88).
//
// An acknowledged append writes one row into each of `batches` (the stored records), `receipts`, `metrics`
// (one per sample), `scan_pages` (the page of its rows) and `scan_commits`, and the keys of every one are random
// (organisation, project, source, producer, batch id; a hash of the series; a page id), so in a B-tree each
// row dirties its own leaf, a branch path above it and sometimes a split: the writer of apply.db was held 97 % of the
// time by these (L2w20Admission14: five buckets were about 13 of the 22 page nodes an acknowledged request
// wrote, with a dozen acknowledged requests to a commit). The query indexes already moved to runs (index_runs.go):
// one bolt commit writes the rows of all the appends it carries as ONE new run, sorted, in blocks, and the
// background merges of compactIndexRuns fold runs into larger runs. The five buckets share one logical index,
// `scan_rows`, so that the commit adds one run and not five: a row of table t with key k is the pair
// (t.tag + k, value) of the index, tag 'b' batches, 'c' commits, 'm' metrics, 'p' pages, 'r' receipts, so each
// table is a contiguous key range of every run.
//
// The legacy buckets stay, as the oldest source of every table. A file that was contracted before this layout
// (scan_index_version 2) or adopted from the single-bucket layout keeps every row it has in them and reads
// them through the same merged view; a row that is replaced or inserted outside the appends of a commit (an
// erasure re-indexing the rows it keeps, the publication of segments) is written to its legacy bucket
// or, when a run holds it, in place in the block of that run. Nothing is migrated.
//
// Reads. Get asks the rows the commit has collected, then every run newest first (a run answers only when its bloom filter,
// rows_bloom.go, may hold the key), then the legacy bucket. A cursor over a table is the merged cursor of its
// ranges of the runs and of the legacy bucket (the key is the key of the table, without the tag).
//
// Writes. Insert is for a row the store does not hold: inside withIndexRun (every apply of the engine) it only
// collects the row, and the accumulator of the commit writes the run (flushIndexRun) before the commit; outside
// it writes the legacy bucket. Set, SetMany and Delete change rows that exist: they write the collected rows first, then
// rewrite the blocks that hold the rows (blockRun.edit, a block once) so that an erased row is gone from the
// file as soon as bolt frees its pages (the scrub of scrub.go then zeroes them), and a replaced row never
// has an older copy that a merge would have to drop.
const rowsIndex = "scan_rows"

// rowTable is one of the buckets that live in the row store: its tag in the keys of the runs, its legacy bucket.
type rowTable struct {
	idx    int
	tag    byte
	bucket string
}

var (
	tblBatches  = rowTable{0, 'b', "batches"}
	tblReceipts = rowTable{1, 'r', "receipts"}
	tblMetrics  = rowTable{2, 'm', "metrics"}
	tblPages    = rowTable{3, 'p', "scan_pages"}
	tblCommits  = rowTable{4, 'c', "scan_commits"}
	// tblConsumed holds the consumed reservation of every acknowledged batch (keyed by reservation id, a random id: the last
	// bucket whose size grew with the history, D89 stage 2).
	tblConsumed = rowTable{5, 'k', "consumed"}
)

var rowTables = [...]rowTable{tblBatches, tblReceipts, tblMetrics, tblPages, tblCommits, tblConsumed}

// rowRun is a ready run of the row store with its bloom filter (nil when the registry holds none: the run is asked).
// In a read-only transaction the bucket of the run is opened on first use (runAt): a Get whose bloom filters
// say "not here" for a run never opens it, and opening a run (a seek in the root bucket and a bucket header) was
// the largest cost of loading the store, which every read transaction of an acknowledged append does
// (L2w20Admission38).
type rowRun struct {
	id     uint64
	run    blockRun
	opened bool
	bloom  []byte
}

// rowStore is the row store inside one transaction: the ready runs, newest first, the legacy buckets and, in a
// transaction that applies appends, the rows it has collected for the run of its commit.
type rowStore struct {
	tx       *bolt.Tx
	runs     []rowRun
	err      error      // a ready run whose bucket is missing, found by a lazy open: Err, tableGet
	building []blockRun // invisible output runs of a merge in flight: only a deletion or a replacement reaches them
	legacy   [len(rowTables)]*bolt.Bucket
	acc      *indexAccumulator
}

// loadRowStore opens the store in tx: the layout of the file decides whether there are runs. A writing transaction opens the legacy
// bucket of every table at the load (a file that lacks one is model.Corrupt); a read-only transaction opens the bucket of a table when
// a lookup reaches it (legacyOf), because bolt opens a bucket afresh every time a read-only transaction asks for it (a cursor, a seek in
// the root and the bucket's header), which was six openings in every load, ten loads a request (L2w20Admission39).
func loadRowStore(tx *bolt.Tx) (*rowStore, error) {
	rs := &rowStore{tx: tx}
	if tx.Writable() {
		for _, t := range rowTables {
			if _, err := rs.legacyOf(t); err != nil {
				return nil, err
			}
		}
	}
	return rs, rs.loadRuns()
}

// legacyOf is the legacy bucket of table t, opened once per store; a file without it is model.Corrupt.
func (rs *rowStore) legacyOf(t rowTable) (*bolt.Bucket, error) {
	if b := rs.legacy[t.idx]; b != nil {
		return b, nil
	}
	b := rs.tx.Bucket([]byte(t.bucket))
	if b == nil {
		return nil, model.Fail(model.Corrupt)
	}
	rs.legacy[t.idx] = b
	return b, nil
}

// rowRunsHint is how many ready runs the last load of the row store found: the next load allocates its slice that large, so that a load
// does not grow it by doubling.
var rowRunsHint atomic.Int32

// loadRuns reads the registry of the row runs into rs, in one pass: the entries of the runs are the keys "scan_rows/<id>" and the
// bloom filters the keys "scan_rows.bloom/<id>", each range in ascending id order, so that a second cursor pairs every ready run
// with its filter (a run that has none, an older file's, gets nil: it is asked) and skips a filter that no entry names. Reading the
// entries into a slice and asking for each filter on its own (a cursor and a seek a run) allocated a number of times that grew with the
// runs, in every read transaction of every acknowledged append (L2w20Admission39).
func (rs *rowStore) loadRuns() error {
	rs.runs, rs.building = nil, nil
	reg := rs.tx.Bucket([]byte(runsRegistry))
	if reg == nil {
		return nil
	}
	var prefixBuf, bloomBuf [24]byte
	prefix := append(append(prefixBuf[:0], rowsIndex...), '/')
	bloomPrefix := append(append(bloomBuf[:0], rowsIndex...), ".bloom/"...)
	writable := rs.tx.Writable()
	runs := make([]rowRun, 0, rowRunsHint.Load())
	var building []blockRun
	entries, filters := reg.Cursor(), reg.Cursor()
	fk, fv := filters.Seek(bloomPrefix)
	for k, v := entries.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = entries.Next() {
		if len(k) != len(prefix)+8 {
			return model.Fail(model.Corrupt)
		}
		meta, err := parseIndexRunMeta(v)
		if err != nil {
			return err
		}
		id := binary.BigEndian.Uint64(k[len(prefix):])
		switch meta.State {
		case indexRunReady:
			r := rowRun{id: id}
			for fk != nil && bytes.HasPrefix(fk, bloomPrefix) && (len(fk) != len(bloomPrefix)+8 || binary.BigEndian.Uint64(fk[len(bloomPrefix):]) < id) {
				fk, fv = filters.Next()
			}
			if fk != nil && len(fk) == len(bloomPrefix)+8 && bytes.HasPrefix(fk, bloomPrefix) && binary.BigEndian.Uint64(fk[len(bloomPrefix):]) == id {
				r.bloom = fv
			}
			if writable {
				// A writing transaction asks the runs it rewrites and fails as a whole on a missing one.
				if _, err := rs.openRun(&r); err != nil {
					return err
				}
			}
			runs = append(runs, r)
		case indexRunBuilding:
			if writable {
				if b := rs.tx.Bucket(indexRunBucketName(rowsIndex, id)); b != nil {
					building = append(building, blockRun{b})
				}
			}
		}
	}
	slices.Reverse(runs) // newest first
	slices.Reverse(building)
	rs.runs, rs.building = runs, building
	if n := int32(len(runs)); rowRunsHint.Load() != n {
		rowRunsHint.Store(n)
	}
	return nil
}

// openRun opens the bucket of r once; a ready run without one is model.Corrupt.
func (rs *rowStore) openRun(r *rowRun) (blockRun, error) {
	if !r.opened {
		b := rs.tx.Bucket(indexRunBucketName(rowsIndex, r.id))
		if b == nil {
			return blockRun{}, model.Fail(model.Corrupt)
		}
		r.run, r.opened = blockRun{b}, true
	}
	return r.run, nil
}

// runAt is the run i of the store, opened when it is first asked.
func (rs *rowStore) runAt(i int) (blockRun, error) { return rs.openRun(&rs.runs[i]) }

// Err is model.Corrupt once a read found a ready run of the registry without its bucket (the Get that met it
// answered "not here"; a reader that must not take that for an answer asks Err after its lookups).
func (rs *rowStore) Err() error { return rs.err }

// rowsOf is the row store of tx. Inside withIndexRun it is one store for the whole transaction, with the rows the
// appends of the commit collected; anywhere else a fresh one.
func rowsOf(tx *bolt.Tx) (*rowStore, error) {
	acc := accumulatorOf(tx)
	if acc != nil && acc.rows != nil {
		return acc.rows, nil
	}
	rs, err := loadRowStore(tx)
	if err != nil {
		return nil, err
	}
	if acc != nil {
		rs.acc, acc.rows = acc, rs
	}
	return rs, nil
}

// tableGet is the value of key in table t of tx (nil when none).
func tableGet(tx *bolt.Tx, t rowTable, key []byte) ([]byte, error) {
	rs, err := rowsOf(tx)
	if err != nil {
		return nil, err
	}
	v := rs.Get(t, key)
	return v, rs.err
}

// tableForEach calls fn for every row of table t in key order.
func tableForEach(tx *bolt.Tx, t rowTable, fn func(k, v []byte) error) error {
	rs, err := rowsOf(tx)
	if err != nil {
		return err
	}
	return rs.ForEach(t, fn)
}

func taggedKey(t rowTable, key []byte) []byte {
	out := make([]byte, 1+len(key))
	out[0] = t.tag
	copy(out[1:], key)
	return out
}

// Get returns the value of key in table t (valid for the life of the transaction), nil when the store has none.
func (rs *rowStore) Get(t rowTable, key []byte) []byte {
	if len(rs.runs) == 0 && (rs.acc == nil || len(rs.acc.rowIdx) == 0) {
		return rs.legacyGet(t, key)
	}
	tagged := taggedKey(t, key)
	if rs.acc != nil {
		if i, ok := rs.acc.rowIdx[string(tagged)]; ok {
			return rs.acc.pairs[rowsIndex][i].Value
		}
	}
	h1, h2 := bloomHash(tagged)
	for i := range rs.runs {
		r := &rs.runs[i]
		if r.bloom != nil && !bloomMayHold(r.bloom, h1, h2) {
			continue
		}
		run, err := rs.openRun(r)
		if err != nil {
			rs.err = err
			return nil
		}
		if v := run.Get(tagged); v != nil {
			return v
		}
	}
	return rs.legacyGet(t, key)
}

// legacyGet is the value of key in the legacy bucket of t; a file without the bucket is reported by Err.
func (rs *rowStore) legacyGet(t rowTable, key []byte) []byte {
	b, err := rs.legacyOf(t)
	if err != nil {
		rs.err = err
		return nil
	}
	return b.Get(key)
}

// Insert stores a row the store does not hold (see the type's comment). The value is kept by reference until
// the commit, as bolt keeps the value of a Put.
func (rs *rowStore) Insert(t rowTable, key, value []byte) error {
	if rs.acc == nil {
		b, err := rs.legacyOf(t)
		if err != nil {
			return err
		}
		return b.Put(key, value)
	}
	if value == nil {
		value = []byte{}
	}
	tagged := taggedKey(t, key)
	if len(tagged) > bolt.MaxKeySize {
		return model.Fail(model.Invalid)
	}
	pairs := rs.acc.pairs[rowsIndex]
	if i, ok := rs.acc.rowIdx[string(tagged)]; ok {
		pairs[i].Value = value
		return nil
	}
	rs.acc.rowIdx[string(tagged)] = len(pairs)
	rs.acc.pairs[rowsIndex] = append(pairs, indexPair{Key: tagged, Value: value})
	return nil
}

// settle writes the rows the commit collected as a run, so that a read that must see them in the runs (a
// cursor, a rewrite of a block) does.
func (rs *rowStore) settle() error {
	if rs.acc == nil || len(rs.acc.pairs[rowsIndex]) == 0 {
		return nil
	}
	if err := rs.acc.flush(rs.tx); err != nil {
		return err
	}
	if err := rs.loadRuns(); err != nil {
		return err
	}
	rs.acc.rows = rs
	return nil
}

// rowKV is a row to set.
type rowKV struct{ Key, Value []byte }

// Set replaces the row under key of table t, or creates it.
func (rs *rowStore) Set(t rowTable, key, value []byte) error {
	return rs.SetMany(t, []rowKV{{key, value}})
}

// SetMany replaces rows of table t, or creates the ones the store does not hold (in the legacy bucket). The keys
// must be distinct. A row held by a run is replaced inside its block; every block is rewritten once.
func (rs *rowStore) SetMany(t rowTable, kvs []rowKV) error {
	if err := rs.settle(); err != nil {
		return err
	}
	if len(kvs) == 0 {
		return nil
	}
	order := make([]int, len(kvs))
	edits := make([]blockEdit, len(kvs))
	for i := range kvs {
		order[i] = i
		edits[i] = blockEdit{Key: taggedKey(t, kvs[i].Key), Value: kvs[i].Value}
	}
	slices.SortFunc(order, func(a, b int) int { return bytes.Compare(edits[a].Key, edits[b].Key) })
	sorted := make([]blockEdit, len(kvs))
	hashes := make([][2]uint64, len(kvs))
	for n, i := range order {
		sorted[n] = edits[i]
		hashes[n][0], hashes[n][1] = bloomHash(sorted[n].Key)
		if n > 0 && bytes.Equal(sorted[n-1].Key, sorted[n].Key) {
			return model.Fail(model.Invalid)
		}
	}
	held := make([]bool, len(kvs)) // by sorted position
	apply := func(r blockRun, bloom []byte) error {
		var cand []blockEdit
		var at []int
		for n := range sorted {
			if bloom == nil || bloomMayHold(bloom, hashes[n][0], hashes[n][1]) {
				cand, at = append(cand, sorted[n]), append(at, n)
			}
		}
		if len(cand) == 0 {
			return nil
		}
		found, err := r.edit(cand)
		for j, f := range found {
			held[at[j]] = held[at[j]] || f
		}
		return err
	}
	for i := range rs.runs {
		run, err := rs.runAt(i)
		if err != nil {
			return err
		}
		if err := apply(run, rs.runs[i].bloom); err != nil {
			return err
		}
	}
	for _, b := range rs.building {
		if err := apply(b, nil); err != nil {
			return err
		}
	}
	legacy, err := rs.legacyOf(t)
	if err != nil {
		return err
	}
	for n, i := range order {
		if held[n] && legacy.Get(kvs[i].Key) == nil {
			continue
		}
		if err := legacy.Put(kvs[i].Key, kvs[i].Value); err != nil {
			return err
		}
	}
	return nil
}

// Delete removes the row under key of table t from every place that holds it and reports whether one did.
func (rs *rowStore) Delete(t rowTable, key []byte) (found bool, err error) {
	if err = rs.settle(); err != nil {
		return false, err
	}
	tagged := taggedKey(t, key)
	h1, h2 := bloomHash(tagged)
	for i := range rs.runs {
		r := &rs.runs[i]
		if r.bloom != nil && !bloomMayHold(r.bloom, h1, h2) {
			continue
		}
		run, err := rs.openRun(r)
		if err != nil {
			return found, err
		}
		f, err := run.Delete(tagged)
		if err != nil {
			return found, err
		}
		found = found || f
	}
	for _, b := range rs.building {
		if _, err := b.Delete(tagged); err != nil {
			return found, err
		}
	}
	legacy, err := rs.legacyOf(t)
	if err != nil {
		return found, err
	}
	if legacy.Get(key) != nil {
		if err := legacy.Delete(key); err != nil {
			return found, err
		}
		found = true
	}
	return found, nil
}

// tableSource is the range of table t of a run as a source of the merged cursor: the keys it yields are the
// keys of the table (without the tag).
type tableSource struct {
	run blockRun
	tag byte
}

func (s tableSource) Get(key []byte) []byte {
	return s.run.Get(append([]byte{s.tag}, key...))
}

func (s tableSource) Delete(key []byte) (bool, error) {
	return s.run.Delete(append([]byte{s.tag}, key...))
}

func (s tableSource) Cursor() indexSourceCursor { return &tableCursor{in: s.run.Cursor(), tag: s.tag} }

// tableCursor iterates the keys of one tag of a run.
type tableCursor struct {
	in   indexSourceCursor
	tag  byte
	seek []byte
}

func (c *tableCursor) clip(k, v []byte) (key, value []byte) {
	if k == nil || len(k) == 0 || k[0] != c.tag {
		return nil, nil
	}
	return k[1:], v
}

func (c *tableCursor) First() (k, v []byte) { return c.clip(c.in.Seek([]byte{c.tag})) }

func (c *tableCursor) Seek(seek []byte) (k, v []byte) {
	c.seek = append(append(c.seek[:0], c.tag), seek...)
	return c.clip(c.in.Seek(c.seek))
}

func (c *tableCursor) Next() (k, v []byte) { return c.clip(c.in.Next()) }

// Err is model.Corrupt after the run met a damaged block (the cursor then ended; the damage must not read as
// the end of the table).
func (c *tableCursor) Err() error {
	if e, ok := c.in.(interface{ Err() error }); ok {
		return e.Err()
	}
	return nil
}

// Cursor returns the merged cursor of table t: the ranges of the runs, newest first, then the legacy bucket.
// Like a bolt cursor it does not survive writes to the rows of the store.
func (rs *rowStore) Cursor(t rowTable) (*indexCursor, error) {
	if err := rs.settle(); err != nil {
		return nil, err
	}
	srcs := make([]indexSource, 0, len(rs.runs)+1)
	for i := range rs.runs {
		run, err := rs.runAt(i)
		if err != nil {
			return nil, err
		}
		srcs = append(srcs, tableSource{run: run, tag: t.tag})
	}
	legacy, err := rs.legacyOf(t)
	if err != nil {
		return nil, err
	}
	srcs = append(srcs, baseSource{legacy})
	return newIndexCursor(srcs), nil
}

// ForEach calls fn for every row of table t in key order until it returns an error; a damaged block is
// model.Corrupt. The key and the value are valid until fn returns.
func (rs *rowStore) ForEach(t rowTable, fn func(k, v []byte) error) error {
	c, err := rs.Cursor(t)
	if err != nil {
		return err
	}
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if err := fn(k, v); err != nil {
			return err
		}
	}
	return c.Err()
}
