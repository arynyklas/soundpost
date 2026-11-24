// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"encoding/binary"
	"math"
	"sync"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The block format of a run bucket (index_runs.go says why a run is made of blocks).
//
// A run bucket holds one bolt entry per block. The bolt key of a block is the LAST index key it holds, so that
// a bolt cursor Seek(k) lands on the block that holds the first index key >= k (or on none: nothing is >= k);
// the bolt value is the block:
//
//	byte  indexBlockMagic (format version)
//	u32   n, the number of pairs (n >= 1)
//	records, in key order, back to back (see below)
//	u32   restarts[r], the offset from the start of the block of every 16th record (r = ceil(n/16))
//	u32   r
//
// Index keys share long runs of bytes with their sorted neighbour (the namespace and the term in front, the
// commit group and index behind a time and an id that differ) and so do their values (the page id), so a
// record stores a pair as a difference to the previous pair, which is the whole point of the format: the
// disk-bound database writes a third of the bytes of the plain pairs. A record is
//
//	uvarint p   bytes shared with the front of the previous key
//	uvarint l1  literal bytes that follow them
//	uvarint m   bytes then copied from the previous key at the same offsets (a run of equal bytes)
//	uvarint l2  literal bytes that end the key
//	uvarint vp  bytes shared with the front of the previous value
//	uvarint vl  literal bytes that end the value
//	l1 literal key bytes, l2 literal key bytes, vl literal value bytes
//
// key = previous[:p] + lit1 + previous[p+l1 : p+l1+m] + lit2; value = previousValue[:vp] + lit. Every 16th
// record is a restart point and holds its full key and value (p = m = l2 = vp = 0), so a Seek is a binary
// search over the restart keys (slices of the block) and a scan of at most 16 records, never a decode of the
// block. Keys and values are rebuilt in buffers of the reader: they are valid until its next call. Integers
// are big endian, varints are encoding/binary's.
//
// A block is damaged, and is model.Corrupt, never misread, when its header does not fit, when the restart
// table does not point at the records it names (every 16th record starts where the table says), when a
// record does not fit in the area of the records or refers to bytes the previous pair does not have, or when
// the last record does not end the area with the key the block is filed under (checked whenever a reader
// reaches the last pair). The entries carry their own CRC (validIndexValue) and the index digest covers keys
// and values: the block adds structure checks, not a checksum of its own.

const (
	indexBlockMagic    = 0xB1
	indexBlockHeader   = 1 + 4 // magic, n
	indexRestartEvery  = 16
	indexBlockDefaultB = 128 << 10
	// indexMinRun is the shortest run of equal bytes that a record copies from the previous key: it saves its
	// length and costs the varint that splits the literals.
	indexMinRun = 4
)

// indexRunBlockBytes is the encoded size at which a block is closed (it ends with the pair that reaches it,
// so a block is a little larger). A variable for the tests that need many small blocks.
var indexRunBlockBytes = indexBlockDefaultB

// rowsRunBlockBytes is the block size of the runs of the row store (rows.go). Its values are rows of a few
// hundred bytes to a few KiB, and an erasure rewrites the whole block that holds the row, so its blocks are
// smaller than the 128 KiB of the query indexes: 32 KiB is eight contiguous pages, which bolt still writes as
// one node. A variable for the tests that need many small blocks.
var rowsRunBlockBytes = 32 << 10

// runBlockBytes is the size at which a block of a run of the index name is closed.
func runBlockBytes(name string) int {
	if name == rowsIndex {
		return rowsRunBlockBytes
	}
	return indexRunBlockBytes
}

func commonPrefixLen(a, b []byte) int {
	n := min(len(a), len(b))
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return i
}

// longestEqualRun returns the start and the length of the longest run of equal bytes at the same offsets of a
// and b from offset from on.
func longestEqualRun(a, b []byte, from int) (start, length int) {
	n := min(len(a), len(b))
	for i := from; i < n; {
		if a[i] != b[i] {
			i++
			continue
		}
		j := i
		for j < n && a[j] == b[j] {
			j++
		}
		if j-i > length {
			start, length = i, j-i
		}
		i = j
	}
	return start, length
}

// blockBuilder encodes sorted, distinct pairs as one block.
type blockBuilder struct {
	buf      []byte
	n        int
	restarts []uint32
	last     []byte // the last key added
	lastV    []byte // the last value added
}

// start begins a block in a fresh buffer (bolt keeps the value of a Put by reference until the commit) with
// room for capHint bytes.
func (b *blockBuilder) start(capHint int) {
	b.buf = make([]byte, indexBlockHeader, indexBlockHeader+capHint)
	b.buf[0] = indexBlockMagic
	b.n = 0
	b.restarts = b.restarts[:0]
	b.last, b.lastV = b.last[:0], b.lastV[:0]
}

func (b *blockBuilder) add(k, v []byte) {
	var p, m, l2, vp int
	l1 := len(k)
	if b.n%indexRestartEvery == 0 {
		b.restarts = append(b.restarts, uint32(len(b.buf)))
	} else {
		p = commonPrefixLen(b.last, k)
		vp = commonPrefixLen(b.lastV, v)
		l1 = len(k) - p
		if start, run := longestEqualRun(b.last, k, p); run >= indexMinRun {
			l1, m, l2 = start-p, run, len(k)-start-run
		}
	}
	b.buf = binary.AppendUvarint(b.buf, uint64(p))
	b.buf = binary.AppendUvarint(b.buf, uint64(l1))
	b.buf = binary.AppendUvarint(b.buf, uint64(m))
	b.buf = binary.AppendUvarint(b.buf, uint64(l2))
	b.buf = binary.AppendUvarint(b.buf, uint64(vp))
	b.buf = binary.AppendUvarint(b.buf, uint64(len(v)-vp))
	b.buf = append(b.buf, k[p:p+l1]...)
	b.buf = append(b.buf, k[len(k)-l2:]...)
	b.buf = append(b.buf, v[vp:]...)
	b.last = append(b.last[:0], k...)
	b.lastV = append(b.lastV[:0], v...)
	b.n++
}

// size is the encoded size of the block so far, without its trailer.
func (b *blockBuilder) size() int { return len(b.buf) }

// finish closes the block and returns it; the builder is empty again (start begins the next).
func (b *blockBuilder) finish() []byte {
	for _, off := range b.restarts {
		b.buf = binary.BigEndian.AppendUint32(b.buf, off)
	}
	b.buf = binary.BigEndian.AppendUint32(b.buf, uint32(len(b.restarts)))
	binary.BigEndian.PutUint32(b.buf[1:], uint32(b.n))
	out := b.buf
	b.buf, b.n = nil, 0
	return out
}

// indexBlock is a block whose header was checked.
type indexBlock struct {
	raw    []byte
	n      int // pairs
	nr     int // restart points
	recEnd int // end of the records, start of the restart table
}

// parseIndexBlock checks the header and the trailer of a block value.
func parseIndexBlock(raw []byte) (indexBlock, bool) {
	// magic, n, one record (six varints and a key byte at least), one restart offset, r
	if len(raw) < indexBlockHeader+7+4+4 || raw[0] != indexBlockMagic {
		return indexBlock{}, false
	}
	n := int(binary.BigEndian.Uint32(raw[1:]))
	nr := int(binary.BigEndian.Uint32(raw[len(raw)-4:]))
	if n < 1 || nr != (n+indexRestartEvery-1)/indexRestartEvery || nr > (len(raw)-indexBlockHeader)/4-1 {
		return indexBlock{}, false
	}
	b := indexBlock{raw: raw, n: n, nr: nr, recEnd: len(raw) - 4 - 4*nr}
	if b.restart(0) != indexBlockHeader || b.recEnd <= indexBlockHeader {
		return indexBlock{}, false
	}
	return b, true
}

func (b indexBlock) restart(j int) int {
	return int(binary.BigEndian.Uint32(b.raw[b.recEnd+4*j:]))
}

// recordHdr is the decoded front of a record.
type recordHdr struct {
	p, l1, m, l2, vp, vl int
	size                 int // bytes of the six varints
}

// recordHeader decodes the front of a record; ok is false when the varints do not fit or when the literals
// do not fit in rec.
func recordHeader(rec []byte) (h recordHdr, ok bool) {
	var vals [6]int
	for i := range vals {
		v, w := binary.Uvarint(rec[h.size:])
		if w <= 0 || v > math.MaxInt32 {
			return h, false
		}
		vals[i] = int(v)
		h.size += w
	}
	h.p, h.l1, h.m, h.l2, h.vp, h.vl = vals[0], vals[1], vals[2], vals[3], vals[4], vals[5]
	return h, h.l1+h.l2+h.vl <= len(rec)-h.size
}

// restartKey is the full key of restart point j (a slice of the block).
func (b indexBlock) restartKey(j int) ([]byte, bool) {
	off := b.restart(j)
	if off < indexBlockHeader || off >= b.recEnd {
		return nil, false
	}
	h, ok := recordHeader(b.raw[off:b.recEnd])
	if !ok || h.p != 0 || h.m != 0 || h.l2 != 0 || h.vp != 0 || h.l1 == 0 {
		return nil, false
	}
	return b.raw[off+h.size : off+h.size+h.l1], true
}

// blockReader decodes the records of one block in order.
type blockReader struct {
	blk    indexBlock
	pos    int // offset of the next record
	idx    int // records decoded so far
	key    []byte
	val    []byte
	spare  []byte // the buffer of the key before key
	vspare []byte // the same for the value
	bad    bool
}

// reset stands before the first record of restart group g.
func (r *blockReader) reset(blk indexBlock, g int) {
	r.blk, r.idx, r.pos, r.bad = blk, g*indexRestartEvery, blk.restart(g), false
	r.key, r.val = r.key[:0], r.val[:0]
}

func (r *blockReader) fail() bool {
	r.bad = true
	return false
}

// next decodes the next record into key and val; false at the end of the block or when it is damaged (bad).
func (r *blockReader) next() bool {
	blk := r.blk
	if r.bad || r.idx >= blk.n {
		return false
	}
	atRestart := r.idx%indexRestartEvery == 0
	if atRestart && r.pos != blk.restart(r.idx/indexRestartEvery) || r.pos < indexBlockHeader || r.pos >= blk.recEnd {
		return r.fail()
	}
	h, ok := recordHeader(blk.raw[r.pos:blk.recEnd])
	if !ok || atRestart && (h.p != 0 || h.m != 0 || h.l2 != 0 || h.vp != 0) ||
		h.p > len(r.key) || h.m > 0 && h.p+h.l1+h.m > len(r.key) || h.vp > len(r.val) || h.p+h.l1+h.m+h.l2 == 0 {
		return r.fail()
	}
	lit := r.pos + h.size
	key := append(r.spare[:0], r.key[:h.p]...)
	key = append(key, blk.raw[lit:lit+h.l1]...)
	if h.m > 0 { // m == 0: p+l1 may be past the end of the previous key
		key = append(key, r.key[h.p+h.l1:h.p+h.l1+h.m]...)
	}
	key = append(key, blk.raw[lit+h.l1:lit+h.l1+h.l2]...)
	val := append(r.vspare[:0], r.val[:h.vp]...)
	val = append(val, blk.raw[lit+h.l1+h.l2:lit+h.l1+h.l2+h.vl]...)
	r.spare, r.key = r.key, key
	r.vspare, r.val = r.val, val
	r.pos = lit + h.l1 + h.l2 + h.vl
	r.idx++
	return true
}

// seek stands on the first pair whose key is >= key; false when there is none or the block is damaged.
func (r *blockReader) seek(blk indexBlock, key []byte) bool {
	lo, hi := 0, blk.nr
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		rk, ok := blk.restartKey(mid)
		if !ok {
			r.blk = blk
			return r.fail()
		}
		if bytes.Compare(rk, key) < 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	r.reset(blk, max(lo-1, 0))
	for r.next() {
		if bytes.Compare(r.key, key) >= 0 {
			return true
		}
	}
	return false
}

// endsRight reports whether the pair the reader stands on, when it is the last of its block, ends the area of
// the records and carries boltKey, the key the block is filed under; true for any other pair.
func (r *blockReader) endsRight(boltKey []byte) bool {
	if r.idx < r.blk.n {
		return true
	}
	return r.pos == r.blk.recEnd && bytes.Equal(r.key, boltKey)
}

var blockReaders = sync.Pool{New: func() any { return new(blockReader) }}

// damagedIndexValue is what a damaged block yields in place of a value: not nil (the key is there), not an
// index value (validIndexValue fails), so every consumer that checks its entries reports model.Corrupt.
var damagedIndexValue = []byte{}

// indexSourceCursor is the part of a bolt cursor the merged cursor needs of one source. The key and the value
// it returns are valid until its next call.
type indexSourceCursor interface {
	First() (k, v []byte)
	Seek(seek []byte) (k, v []byte)
	Next() (k, v []byte)
}

// indexSource is one bucket of an index: the base bucket or a block run.
type indexSource interface {
	// Get returns the value of key (valid for the life of the transaction), nil when the source has none.
	Get(key []byte) []byte
	// Delete removes key and reports whether the source held it.
	Delete(key []byte) (found bool, err error)
	Cursor() indexSourceCursor
}

// baseSource is a plain bolt bucket: the legacy data of an index and whatever indexSet.Put wrote.
type baseSource struct{ b *bolt.Bucket }

func (s baseSource) Get(key []byte) []byte { return s.b.Get(key) }

func (s baseSource) Delete(key []byte) (bool, error) {
	if s.b.Get(key) == nil {
		return false, nil
	}
	return true, s.b.Delete(key)
}

func (s baseSource) Cursor() indexSourceCursor { return s.b.Cursor() }

// blockRun is a run bucket in the block format. A bolt value of it is a block, or the reference of the payload record that holds
// the block (paylog.go: the blocks of a final run are moved out of bolt, so that bolt keeps one pointer per block).
type blockRun struct{ b *bolt.Bucket }

func (r blockRun) Cursor() indexSourceCursor { return &blockCursor{bc: r.b.Cursor(), tx: r.b.Tx()} }

// blockOf is the block that a bolt value of the run stands for; nil when its record cannot be read (damage).
func (r blockRun) blockOf(stored []byte) []byte { return storedTx(r.b.Tx(), stored) }

// locate stands rd on the first pair >= key of the block that holds it (the one bolt's Seek finds), and
// returns the bolt key and the bolt value of that block (a block or its payload reference). found is false when no pair is >=
// key; a damaged block is model.Corrupt.
func (r blockRun) locate(rd *blockReader, key []byte) (boltKey, stored []byte, found bool, err error) {
	boltKey, stored = r.b.Cursor().Seek(key)
	if boltKey == nil {
		return nil, nil, false, nil
	}
	blk, ok := parseIndexBlock(r.blockOf(stored))
	// The block is filed under its last key, which is >= key: a search that finds nothing is damage.
	if !ok || !rd.seek(blk, key) {
		return boltKey, stored, false, model.Fail(model.Corrupt)
	}
	return boltKey, stored, true, nil
}

// Get returns a copy of the value (a block holds it as a difference to the previous one).
func (r blockRun) Get(key []byte) []byte {
	rd := blockReaders.Get().(*blockReader)
	defer blockReaders.Put(rd)
	_, _, found, err := r.locate(rd, key)
	if err != nil {
		return damagedIndexValue
	}
	if !found || !bytes.Equal(rd.key, key) {
		return nil
	}
	return append(make([]byte, 0, len(rd.val)), rd.val...) // not nil, even when empty
}

// Delete rewrites the block that holds key without it (the rare path: erase), removes the block when key was
// its only pair, and refiles the block under its new last key when key was the last. The record of a block that lived in the
// payload log is owed a zeroing, and the rewritten block is stored in the run.
func (r blockRun) Delete(key []byte) (bool, error) {
	rd := blockReaders.Get().(*blockReader)
	defer blockReaders.Put(rd)
	boltKey, stored, found, err := r.locate(rd, key)
	if err != nil || !found || !bytes.Equal(rd.key, key) {
		return false, err
	}
	oldKey := bytes.Clone(boltKey) // the entry is about to be replaced under it
	r.b.FillPercent = 1.0
	blk, gone := rd.blk, rd.idx-1
	if err = owePayloadScrub(r.b.Tx(), stored); err != nil {
		return false, err
	}
	if blk.n == 1 {
		return true, r.b.Delete(oldKey)
	}
	var bb blockBuilder
	bb.start(len(blk.raw))
	rd.reset(blk, 0)
	for rd.next() {
		if rd.idx-1 != gone {
			bb.add(rd.key, rd.val)
		}
	}
	if rd.bad || rd.idx != blk.n || rd.pos != blk.recEnd {
		return false, model.Fail(model.Corrupt)
	}
	newKey := bytes.Clone(bb.last)
	if !bytes.Equal(newKey, oldKey) {
		if err := r.b.Delete(oldKey); err != nil {
			return false, err
		}
	}
	return true, r.b.Put(newKey, bb.finish())
}

// blockEdit is one change to a block run: the pair under Key is removed (Delete) or takes Value.
type blockEdit struct {
	Key, Value []byte
	Delete     bool
}

// edit applies edits, sorted by key and distinct, to the pairs the run holds and reports for each whether the
// run held its key. A block that has pairs to change is rewritten once however many of them it holds (removed
// when it loses its last pair, refiled under its new last key when that changes). It is the path of an erasure
// and of the publication of segments, which change many rows of a run: Delete per key would rewrite a block per row.
func (r blockRun) edit(edits []blockEdit) (found []bool, err error) {
	found = make([]bool, len(edits))
	rd := blockReaders.Get().(*blockReader)
	defer blockReaders.Put(rd)
	for i := 0; i < len(edits); {
		boltKey, stored := r.b.Cursor().Seek(edits[i].Key)
		raw := r.blockOf(stored)
		if boltKey == nil {
			break // no pair at or above the key: nor above the later keys
		}
		oldKey := bytes.Clone(boltKey) // the entry is about to be replaced under it
		j := i
		for j < len(edits) && bytes.Compare(edits[j].Key, oldKey) <= 0 {
			j++
		}
		blk, ok := parseIndexBlock(raw)
		if !ok {
			return found, model.Fail(model.Corrupt)
		}
		var bb blockBuilder
		bb.start(len(raw))
		changed := false
		rd.reset(blk, 0)
		for e := i; rd.next(); {
			for e < j && bytes.Compare(edits[e].Key, rd.key) < 0 {
				e++
			}
			if e < j && bytes.Equal(edits[e].Key, rd.key) {
				found[e], changed = true, true
				if !edits[e].Delete {
					bb.add(rd.key, edits[e].Value)
				}
				e++
				continue
			}
			bb.add(rd.key, rd.val)
		}
		if rd.bad || rd.idx != blk.n || rd.pos != blk.recEnd {
			return found, model.Fail(model.Corrupt)
		}
		i = j
		if !changed {
			continue
		}
		if err = owePayloadScrub(r.b.Tx(), stored); err != nil { // the record of the block as it was holds the erased pairs
			return found, err
		}
		r.b.FillPercent = 1.0
		if bb.n == 0 {
			if err = r.b.Delete(oldKey); err != nil {
				return found, err
			}
			continue
		}
		newKey := bytes.Clone(bb.last)
		if !bytes.Equal(newKey, oldKey) {
			if err = r.b.Delete(oldKey); err != nil {
				return found, err
			}
		}
		if err = r.b.Put(newKey, bb.finish()); err != nil {
			return found, err
		}
	}
	return found, nil
}

// blockCursor iterates a block run in key order, holding only the block it stands in. A damaged block is
// yielded as one entry (the bolt key of the block, damagedIndexValue) and ends the iteration; err records it.
//
// A Seek of a key that the held block answers (bolt's Seek would return that block again) is answered from it: the run's blocks are
// fetched from the payload log, 128 KiB for each, and a cursor that is asked for the keys of one tail in ascending order (the
// verification of the tail) stands in the same block for hundreds of them.
type blockCursor struct {
	bc   *bolt.Cursor
	tx   *bolt.Tx // resolves the payload references of the blocks
	rd   blockReader
	key  []byte // bolt key of the current block
	live bool   // standing on a pair
	err  error

	// held is true while rd.blk is the block filed under key. It is the block bolt's Seek finds for every key above lo (from lo on
	// when bound is boundIncl; for every key up to key when bound is boundNone, the first block): the block before it ends at lo,
	// or the Seek that found this block was for lo.
	held  bool
	bound blockBound
	lo    []byte // a copy: the key it was bolt's, or the caller's, may be gone
}

type blockBound uint8

const (
	boundNone blockBound = iota // no block before the held one
	boundExcl                   // the block before it ends at lo
	boundIncl                   // a Seek for lo found it
)

// Err is model.Corrupt after the cursor met a damaged block.
func (c *blockCursor) Err() error { return c.err }

func (c *blockCursor) First() (k, v []byte) {
	boltKey, raw := c.bc.First()
	return c.enter(boltKey, raw, nil, false, nil, boundNone)
}

func (c *blockCursor) Seek(seek []byte) (k, v []byte) {
	if c.held && c.answers(seek) {
		return c.yield(c.rd.seek(c.rd.blk, seek))
	}
	boltKey, raw := c.bc.Seek(seek)
	return c.enter(boltKey, raw, seek, true, seek, boundIncl)
}

// answers reports whether bolt's Seek of seek finds the held block.
func (c *blockCursor) answers(seek []byte) bool {
	if bytes.Compare(seek, c.key) > 0 {
		return false
	}
	switch c.bound {
	case boundExcl:
		return bytes.Compare(seek, c.lo) > 0
	case boundIncl:
		return bytes.Compare(seek, c.lo) >= 0
	}
	return true
}

// enter stands on the first pair of the block (boltKey, raw), or on the first pair >= seek when search is set. lo and bound say which
// Seeks find the block again (blockCursor.held).
func (c *blockCursor) enter(boltKey, raw, seek []byte, search bool, lo []byte, bound blockBound) (k, v []byte) {
	c.live, c.held, c.key = false, false, boltKey
	if boltKey == nil {
		return nil, nil
	}
	blk, ok := parseIndexBlock(storedTx(c.tx, raw))
	if ok {
		c.held, c.bound = true, bound
		c.lo = append(c.lo[:0], lo...)
	}
	if ok && search {
		ok = c.rd.seek(blk, seek)
	} else if ok {
		c.rd.reset(blk, 0)
		ok = c.rd.next()
	}
	return c.yield(ok)
}

func (c *blockCursor) yield(ok bool) (k, v []byte) {
	if !ok || !c.rd.endsRight(c.key) {
		c.err, c.live, c.held = model.Fail(model.Corrupt), false, false
		return c.key, damagedIndexValue
	}
	c.live = true
	return c.rd.key, c.rd.val
}

func (c *blockCursor) Next() (k, v []byte) {
	if !c.live {
		return nil, nil
	}
	if c.rd.idx < c.rd.blk.n {
		return c.yield(c.rd.next())
	}
	prev := c.key
	boltKey, raw := c.bc.Next()
	return c.enter(boltKey, raw, nil, false, prev, boundExcl)
}

// blockAppender writes sorted pairs into a run bucket as blocks of about target encoded bytes. With a payload log, a block is
// appended to the log and the run keeps its reference (the log is synced by the caller before the transaction commits).
type blockAppender struct {
	out     *bolt.Bucket
	target  int
	capHint int // room allocated for a block
	bb      blockBuilder
	written int         // bytes of the blocks put so far
	log     *payloadLog // nil: the blocks are stored in the run
}

func newBlockAppender(out *bolt.Bucket, target, capHint int) *blockAppender {
	out.FillPercent = 1.0
	return &blockAppender{out: out, target: target, capHint: min(capHint, target+4096)}
}

// add appends a pair (its slices are copied before add returns) and reports whether it closed a block, which
// is then in the bucket.
func (a *blockAppender) add(k, v []byte) (closed bool, err error) {
	if a.bb.buf == nil {
		a.bb.start(a.capHint)
	}
	a.bb.add(k, v)
	if a.bb.size() < a.target {
		return false, nil
	}
	return true, a.flush()
}

// flush puts the open block, if any.
func (a *blockAppender) flush() error {
	if a.bb.n == 0 {
		return nil
	}
	last := a.bb.last
	blk := a.bb.finish()
	a.written += len(blk)
	if a.log != nil {
		ref, err := a.log.append(blk)
		if err != nil {
			return err
		}
		return a.out.Put(last, ref)
	}
	return a.out.Put(last, blk) // Put copies the key
}
