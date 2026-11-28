// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"container/heap"
	"encoding/binary"
	"encoding/json"
	"errors"
	"slices"
	"strconv"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// A log-structured index on bolt (decision D81, the per-append write set).
//
// A logical ordered index (name "scan_time" or "scan_postings") is its base bucket `name` (legacy data and
// whatever Put wrote) plus run buckets. One bolt commit writes the index keys of the appends it carries as
// ONE new small run bucket instead of one random insert per key into the big sorted bucket;
// compactIndexRuns merges runs into larger runs in the background. Readers see the union of the base bucket
// and all ready runs through one merged cursor (indexSource is what the cursor needs of each bucket).
//
// A run bucket holds blocks, not one bolt entry per key (index_blocks.go has the format): a block is up to
// indexRunBlockBytes of sorted, prefix-compressed pairs, and bolt stores a value of that size as one
// contiguous overflow node. The data engine is bound by the number of scattered dirty 4 KiB pages one
// acknowledged request writes (the disk does about as many random 4 KiB writes per second whatever their
// number in parallel, and a 64 KiB contiguous write costs a few times one 4 KiB write), so a run of 600 keys
// is a handful of sequential writes where one bolt entry per key was a leaf page per twenty keys, each
// allocated from a scattered free page.
//
// Run bucket name: name + ".r" + 16 lowercase hex digits of the run id; ids strictly increase per name.
// Registry bucket runsRegistry: key = name + "/" + 8-byte big-endian run id, value =
// {"state":"ready"|"building","level":N,"count":N,"bytes":N}. Only ready runs are visible to readers.
// count and bytes are the statistics of the run when it was written (bytes: the keys and values, not their
// encoding); deletes do not update them.
//
// A key lives in exactly one source (base or one run). Sources are ordered newest first (highest run id
// first, the base last) so that a corrupt state that holds a key twice still has one defined winner.
//
// Write amplification. A merge rewrites every key of its inputs, so a key is rewritten once per level it
// climbs. The levels hold indexRunFanouts runs (64, 64, then 8): a key is rewritten once until 4,096 commits,
// twice until 32,768 (2.3 hours at four commits a second), instead of once per factor 8 of the history (four to five times in the first hour of the
// single-host gate, 52 % of the pages apply.db wrote, L2w20Admission28). A run whose bytes reach
// compactOptions.MaxRunBytes (64 MiB by default) is never merged again (planIndexMerge ignores it): a key is
// rewritten by merges at most once per level below that size, whatever the history, and the number of runs
// grows only by history / MaxRunBytes. The merged cursor stays O(log runs) per Next (a heap), a Seek or a Get
// costs one bolt seek per run: the few hundred runs the levels hold (3 x 133) are cheap.

const (
	indexRunReady    = "ready"
	indexRunBuilding = "building"
)

// indexPair is one key of an index and its value.
type indexPair struct{ Key, Value []byte }

// indexRunMeta is the registry value of a run.
type indexRunMeta struct {
	State string `json:"state"`
	Level int    `json:"level"`
	Count int64  `json:"count"`
	Bytes int64  `json:"bytes"`
}

// indexRunEntry is a registry entry of one index: the run id and its meta.
type indexRunEntry struct {
	id   uint64
	meta indexRunMeta
}

func indexRunBucketName(name string, id uint64) []byte {
	const hexDigits = "0123456789abcdef"
	b := make([]byte, 0, len(name)+2+16)
	b = append(b, name...)
	b = append(b, '.', 'r')
	for shift := 60; shift >= 0; shift -= 4 {
		b = append(b, hexDigits[(id>>uint(shift))&0xf])
	}
	return b
}

func indexRunRegPrefix(name string) []byte {
	b := make([]byte, 0, len(name)+1+8)
	b = append(b, name...)
	return append(b, '/')
}

func indexRunRegKey(name string, id uint64) []byte {
	return binary.BigEndian.AppendUint64(indexRunRegPrefix(name), id)
}

// indexRunBloomKey is the registry key of the bloom filter of a run of an index that keeps one (rows_bloom.go):
// name + ".bloom/" + the 8-byte run id. It sorts before every run key of name (index "scan_rows" holds the run
// keys "scan_rows/<id>"), and listIndexRuns, which reads the prefix name + "/", does not see it.
func indexRunBloomKey(name string, id uint64) []byte {
	b := make([]byte, 0, len(name)+len(".bloom/")+8)
	b = append(b, name...)
	b = append(b, ".bloom/"...)
	return binary.BigEndian.AppendUint64(b, id)
}

// indexKeepsBlooms is whether the runs of the index name carry a bloom filter of their keys: the row store,
// whose point reads (a receipt, a metric sample, a page) must not ask every run.
func indexKeepsBlooms(name string) bool { return name == rowsIndex }

// indexRunMetaJSON encodes m as the JSON the registry holds (the canonical form parseIndexRunMeta reads fast).
func indexRunMetaJSON(m indexRunMeta) []byte {
	b := make([]byte, 0, 80)
	b = append(b, `{"state":"`...)
	b = append(b, m.State...)
	b = append(b, `","level":`...)
	b = strconv.AppendInt(b, int64(m.Level), 10)
	b = append(b, `,"count":`...)
	b = strconv.AppendInt(b, m.Count, 10)
	b = append(b, `,"bytes":`...)
	b = strconv.AppendInt(b, m.Bytes, 10)
	return append(b, '}')
}

func cutBytesPrefix(b []byte, prefix string) ([]byte, bool) {
	if len(b) < len(prefix) || string(b[:len(prefix)]) != prefix {
		return b, false
	}
	return b[len(prefix):], true
}

// scanIndexUint reads the leading decimal digits of b (1..18 of them).
func scanIndexUint(b []byte) (n int64, rest []byte, ok bool) {
	i := 0
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		if i == 18 {
			return 0, b, false
		}
		n = n*10 + int64(b[i]-'0')
		i++
	}
	return n, b[i:], i > 0
}

func parseIndexRunMetaFast(v []byte) (m indexRunMeta, ok bool) {
	rest, ok := cutBytesPrefix(v, `{"state":"ready","level":`)
	m.State = indexRunReady
	if !ok {
		if rest, ok = cutBytesPrefix(v, `{"state":"building","level":`); !ok {
			return m, false
		}
		m.State = indexRunBuilding
	}
	var n int64
	if n, rest, ok = scanIndexUint(rest); !ok {
		return m, false
	}
	m.Level = int(n)
	if rest, ok = cutBytesPrefix(rest, `,"count":`); !ok {
		return m, false
	}
	if m.Count, rest, ok = scanIndexUint(rest); !ok {
		return m, false
	}
	if rest, ok = cutBytesPrefix(rest, `,"bytes":`); !ok {
		return m, false
	}
	if m.Bytes, rest, ok = scanIndexUint(rest); !ok {
		return m, false
	}
	return m, len(rest) == 1 && rest[0] == '}'
}

// parseIndexRunMeta decodes a registry value; anything that is not a well-formed run meta is corruption.
func parseIndexRunMeta(v []byte) (indexRunMeta, error) {
	if m, ok := parseIndexRunMetaFast(v); ok {
		return m, nil
	}
	var m indexRunMeta
	if err := json.Unmarshal(v, &m); err != nil {
		return m, model.Fail(model.Corrupt)
	}
	if (m.State != indexRunReady && m.State != indexRunBuilding) || m.Level < 0 || m.Count < 0 || m.Bytes < 0 {
		return m, model.Fail(model.Corrupt)
	}
	return m, nil
}

// listIndexRuns returns the registry entries of the index name (ready and building) in ascending id order.
func listIndexRuns(reg *bolt.Bucket, name string) ([]indexRunEntry, error) {
	prefix := indexRunRegPrefix(name)
	var out []indexRunEntry
	c := reg.Cursor()
	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		if len(k) != len(prefix)+8 {
			return nil, model.Fail(model.Corrupt)
		}
		meta, err := parseIndexRunMeta(v)
		if err != nil {
			return nil, err
		}
		out = append(out, indexRunEntry{id: binary.BigEndian.Uint64(k[len(prefix):]), meta: meta})
	}
	return out, nil
}

// nextIndexRunID is one more than the highest run id registered for name (building runs included), 1 for none.
func nextIndexRunID(reg *bolt.Bucket, name string) uint64 {
	prefix := indexRunRegPrefix(name)
	end := append([]byte(name), '0') // '0' follows '/': above every key of name + "/" + id
	c := reg.Cursor()
	k, _ := c.Seek(end)
	if k == nil {
		k, _ = c.Last()
	} else {
		k, _ = c.Prev()
	}
	for ; k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Prev() {
		if len(k) == len(prefix)+8 {
			return binary.BigEndian.Uint64(k[len(prefix):]) + 1
		}
	}
	return 1
}

// dropIndexRun deletes the registry entry (and the bloom filter of the run, when the index has them) and the
// bucket of a run; all are idempotent.
func dropIndexRun(tx *bolt.Tx, reg *bolt.Bucket, name string, id uint64) error {
	if err := reg.Delete(indexRunRegKey(name, id)); err != nil {
		return err
	}
	if err := reg.Delete(indexRunBloomKey(name, id)); err != nil {
		return err
	}
	if b := tx.Bucket(indexRunBucketName(name, id)); b != nil {
		// The blocks of the run that live in the payload log are no longer named: their records hold keys and values that an
		// erasure may reach, so they are owed a zeroing (paylog.go).
		if tx.Bucket([]byte(payloadScrubBucket)) != nil { // the file has the payload layout
			c := b.Cursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				if err := owePayloadScrub(tx, v); err != nil {
					return err
				}
			}
		}
	}
	if err := tx.DeleteBucket(indexRunBucketName(name, id)); err != nil && !errors.Is(err, bolt.ErrBucketNotFound) {
		return err
	}
	return nil
}

// removeBuildingRuns drops every "building" run of the index name (registry entry and bucket) and returns the
// count. The engine calls it at open, compactIndexRuns before it starts: a building run is the leftover of a
// compaction that did not finish.
func removeBuildingRuns(tx *bolt.Tx, name string) (int, error) {
	reg := tx.Bucket([]byte(runsRegistry))
	if reg == nil {
		return 0, nil
	}
	runs, err := listIndexRuns(reg, name)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range runs {
		if r.meta.State != indexRunBuilding {
			continue
		}
		if err := dropIndexRun(tx, reg, name, r.id); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func compareIndexPairs(a, b indexPair) int { return bytes.Compare(a.Key, b.Key) }

// writeIndexRun writes pairs as a new ready run of level 0 of the index name: sorted by key (duplicate keys are
// model.Corrupt) and encoded as blocks of about indexRunBlockBytes in a fresh bucket, so that its pages are
// contiguous. pairs is sorted in place and may be reused (keys and values included) once it returns: the
// blocks are copies, bolt keeps them by reference until the commit. Every failure is detected before the
// transaction is modified except bolt's own errors. len(pairs) == 0 does nothing.
func writeIndexRun(tx *bolt.Tx, name string, pairs []indexPair) error {
	if len(pairs) == 0 {
		return nil
	}
	if !tx.Writable() {
		return bolt.ErrTxNotWritable
	}
	if !slices.IsSortedFunc(pairs, compareIndexPairs) {
		slices.SortFunc(pairs, compareIndexPairs)
	}
	var size, room int64
	for i := range pairs {
		p := &pairs[i]
		if len(p.Key) == 0 || len(p.Key) > bolt.MaxKeySize || int64(len(p.Value)) > bolt.MaxValueSize {
			return model.Fail(model.Invalid)
		}
		if i > 0 && bytes.Equal(pairs[i-1].Key, p.Key) {
			return model.Fail(model.Corrupt)
		}
		size += int64(len(p.Key) + len(p.Value))
		room += int64(len(p.Key)+len(p.Value)) + 16
	}
	reg, err := tx.CreateBucketIfNotExists([]byte(runsRegistry))
	if err != nil {
		return err
	}
	id := nextIndexRunID(reg, name)
	b, err := tx.CreateBucket(indexRunBucketName(name, id))
	if err != nil {
		return err
	}
	block := runBlockBytes(name)
	ap := newBlockAppender(b, block, int(min(room, int64(block+4096))))
	var bloom *bloomBuilder
	if indexKeepsBlooms(name) {
		bloom = newBloomBuilder(int64(len(pairs)))
	}
	for i := range pairs {
		if _, err := ap.add(pairs[i].Key, pairs[i].Value); err != nil {
			return err
		}
		if bloom != nil {
			bloom.add(pairs[i].Key)
		}
	}
	if err := ap.flush(); err != nil {
		return err
	}
	if bloom != nil {
		if err := reg.Put(indexRunBloomKey(name, id), bloom.bytes()); err != nil {
			return err
		}
	}
	meta := indexRunMeta{State: indexRunReady, Count: int64(len(pairs)), Bytes: size}
	return reg.Put(indexRunRegKey(name, id), indexRunMetaJSON(meta))
}

// indexSet is the logical index name inside one transaction: the base bucket and the ready runs.
type indexSet struct {
	tx   *bolt.Tx
	name string
	base *bolt.Bucket
	runs []indexSource // ready runs, newest first
	all  []indexSource // runs, then the base: the sources in priority order (sources)
	// building are the invisible output runs of a compaction in flight; only Delete touches them, so that a
	// key deleted after it was copied does not come back when the run is flipped to ready.
	building []indexSource
}

// openIndexSet opens the index name in tx. The base bucket must exist (model.Corrupt otherwise); a missing
// registry means no runs.
func openIndexSet(tx *bolt.Tx, name string) (*indexSet, error) {
	base := tx.Bucket([]byte(name))
	if base == nil {
		return nil, model.Fail(model.Corrupt)
	}
	s := &indexSet{tx: tx, name: name, base: base}
	reg := tx.Bucket([]byte(runsRegistry))
	if reg == nil {
		return s, nil
	}
	entries, err := listIndexRuns(reg, name)
	if err != nil {
		return nil, err
	}
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		switch e.meta.State {
		case indexRunReady:
			b := tx.Bucket(indexRunBucketName(name, e.id))
			if b == nil {
				return nil, model.Fail(model.Corrupt)
			}
			s.runs = append(s.runs, blockRun{b})
		case indexRunBuilding:
			if !tx.Writable() {
				continue
			}
			if b := tx.Bucket(indexRunBucketName(name, e.id)); b != nil {
				s.building = append(s.building, blockRun{b})
			}
		}
	}
	return s, nil
}

// RunCount is the number of ready runs of the index.
func (s *indexSet) RunCount() int { return len(s.runs) }

// sources are the visible buckets in priority order: runs newest first, the base last.
func (s *indexSet) sources() []indexSource {
	if s.all == nil {
		s.all = append(append(make([]indexSource, 0, len(s.runs)+1), s.runs...), baseSource{s.base})
	}
	return s.all
}

// Get returns the value of key (valid for the life of the transaction) or nil when no source holds it.
func (s *indexSet) Get(key []byte) []byte {
	for _, r := range s.runs {
		if v := r.Get(key); v != nil {
			return v
		}
	}
	return s.base.Get(key)
}

// Delete removes key from whichever source holds it and reports whether one did. A corrupt state that holds
// the key in two sources deletes both.
func (s *indexSet) Delete(key []byte) (found bool, err error) {
	for _, src := range s.sources() {
		f, err := src.Delete(key)
		if err != nil {
			return found, err
		}
		found = found || f
	}
	for _, b := range s.building {
		if _, err := b.Delete(key); err != nil {
			return found, err
		}
	}
	return found, nil
}

// Put stores key in the base bucket. It is the rare path (the engine writes index keys with writeIndexRun):
// a key that any source already holds is model.Corrupt.
func (s *indexSet) Put(key, value []byte) error {
	if s.Get(key) != nil {
		return model.Fail(model.Corrupt)
	}
	if value == nil {
		value = []byte{}
	}
	return s.base.Put(key, value)
}

// ForEach calls fn for every key in ascending order until it returns an error; a damaged block is
// model.Corrupt (after fn saw the one entry that stands for it). The key and the value are valid until fn returns.
func (s *indexSet) ForEach(fn func(k, v []byte) error) error {
	c := s.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if err := fn(k, v); err != nil {
			return err
		}
	}
	return c.Err()
}

// Cursor returns a merged ordered cursor over the base bucket and the ready runs. Like a bolt cursor it does
// not survive writes to the buckets it reads.
func (s *indexSet) Cursor() *indexCursor { return newIndexCursor(s.sources()) }

// CursorCached is Cursor for a scan: the blocks of the runs it reads come from the cache of the payload log
// when it holds them (block_cache.go).
func (s *indexSet) CursorCached() *indexCursor {
	sources := s.sources()
	c := &indexCursor{srcs: make([]cursorSource, len(sources)), h: make(cursorHeap, 0, len(sources))}
	for i, src := range sources {
		if run, ok := src.(blockRun); ok {
			c.srcs[i] = cursorSource{cur: run.cachedCursor(), pri: i}
		} else {
			c.srcs[i] = cursorSource{cur: src.Cursor(), pri: i}
		}
	}
	return c
}

// cursorSource is one bucket of a merged cursor: its cursor, the entry it stands on, its priority (a lower
// value wins when two sources hold the same key).
type cursorSource struct {
	cur  indexSourceCursor
	k, v []byte
	pri  int
}

// cursorHeap is the min-heap of the sources that still have an entry, ordered by key then priority.
type cursorHeap []*cursorSource

func (h cursorHeap) Len() int { return len(h) }
func (h cursorHeap) Less(i, j int) bool {
	if c := bytes.Compare(h[i].k, h[j].k); c != 0 {
		return c < 0
	}
	return h[i].pri < h[j].pri
}
func (h cursorHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *cursorHeap) Push(x any)   { *h = append(*h, x.(*cursorSource)) }
func (h *cursorHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return x
}

// indexCursor iterates the union of several sources in ascending key order, each key once. The key and the
// value it returns are valid until the next call on the cursor (a block holds them as differences to the
// previous pair, so they are rebuilt in buffers).
type indexCursor struct {
	srcs []cursorSource
	h    cursorHeap
	out  []byte
	outV []byte
}

// newIndexCursor merges sources; earlier sources win when they hold a key that a later source holds too.
func newIndexCursor(sources []indexSource) *indexCursor {
	c := &indexCursor{srcs: make([]cursorSource, len(sources)), h: make(cursorHeap, 0, len(sources))}
	for i, s := range sources {
		c.srcs[i] = cursorSource{cur: s.Cursor(), pri: i}
	}
	return c
}

// Err is model.Corrupt when a source met a damaged block: the cursor then yielded one entry for it (an
// empty value, which no index value is) and went on without the rest of that source.
func (c *indexCursor) Err() error {
	for i := range c.srcs {
		if e, ok := c.srcs[i].cur.(interface{ Err() error }); ok {
			if err := e.Err(); err != nil {
				return err
			}
		}
	}
	return nil
}

// take returns the smallest entry of the heap and steps past it (and past equal keys of lower-priority
// sources). The key is copied into the cursor's buffer: the source that holds it moves on.
func (c *indexCursor) take() (k, v []byte) {
	if len(c.h) == 0 {
		return nil, nil
	}
	top := c.h[0]
	c.out = append(c.out[:0], top.k...)
	c.outV = append(c.outV[:0], top.v...)
	c.advanceTop()
	for len(c.h) > 0 && bytes.Equal(c.h[0].k, c.out) {
		c.advanceTop()
	}
	return c.out, c.outV
}

func (c *indexCursor) advanceTop() {
	top := c.h[0]
	top.k, top.v = top.cur.Next()
	if top.k == nil {
		heap.Remove(&c.h, 0)
		return
	}
	heap.Fix(&c.h, 0)
}

// more reports whether the cursor has an entry left to return.
func (c *indexCursor) more() bool { return len(c.h) > 0 }

// First moves to the first key; nil, nil when the index is empty.
func (c *indexCursor) First() (k, v []byte) {
	c.h = c.h[:0]
	for i := range c.srcs {
		s := &c.srcs[i]
		if s.k, s.v = s.cur.First(); s.k != nil {
			c.h = append(c.h, s)
		}
	}
	heap.Init(&c.h)
	return c.take()
}

// Seek moves to the first key >= seek, like bolt.Cursor.Seek; nil, nil when there is none.
func (c *indexCursor) Seek(seek []byte) (k, v []byte) {
	c.h = c.h[:0]
	for i := range c.srcs {
		s := &c.srcs[i]
		if s.k, s.v = s.cur.Seek(seek); s.k != nil {
			c.h = append(c.h, s)
		}
	}
	heap.Init(&c.h)
	return c.take()
}

// Next moves to the next key; nil, nil at the end (and before First or Seek).
func (c *indexCursor) Next() (k, v []byte) { return c.take() }
