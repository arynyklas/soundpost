// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// Records no reference names (D90 hardening of D89).
//
// An append writes its records into the payload log before the transaction that carries their references commits (externalize),
// so a crash between the two leaves records that no value names: dead space that is never read. It is also bytes: the record holds
// the batch, and an erasure that zeroes the records the references name (owePayloadScrub, scrubPayload) never learns of it. A batch
// the client retries is stored again, in a new record, and the erasure of that batch left the first copy in the file.
//
// The log therefore keeps a mark in the file (meta payload_swept): the position up to which every record is either named by a value
// or zeroed. A process that closes gracefully, without having left an append whose commit failed, moves the mark to the end of the
// log; a sweep (sweepPayloadOrphans) moves it to the end the log had when it was opened. A process that opens a log that is longer
// than its mark has a span a crash may have left unnamed records in. The erasure pass that follows a deletion sweeps that span
// before it reports the bytes gone: it collects every reference of the file (every bucket, nested ones included, and the page rows
// that carry one) and zeroes every byte of the span that no named record covers. What it zeroes is by construction not named: a
// reference committed after the span was cut can only name a record appended after it, and a record a reader may still hold is
// owed in payload_scrub, whose keys are references too.
//
// A process that itself left an append whose commit failed (the engine failed, or a background chunk returned an error) knows of
// records it cannot name: it never moves the mark at close, and its erasure pass stays pending until the restart sweeps them.

// payloadSweptKey is the meta key of the mark: seq (4 bytes) and offset (8 bytes).
const payloadSweptKey = "payload_swept"

// payloadPos is a position in the log: a file and an offset in it.
type payloadPos struct {
	seq uint32
	off int64
}

func (p payloadPos) bytes() []byte {
	var b [12]byte
	binary.BigEndian.PutUint32(b[:], p.seq)
	binary.BigEndian.PutUint64(b[4:], uint64(p.off))
	return b[:]
}

func parsePayloadPos(b []byte) (payloadPos, bool) {
	if len(b) != 12 {
		return payloadPos{}, false
	}
	return payloadPos{binary.BigEndian.Uint32(b), int64(binary.BigEndian.Uint64(b[4:]))}, true
}

// end is the position of the end of the log: where the next record goes.
func (l *payloadLog) end() payloadPos {
	l.mu.Lock()
	defer l.mu.Unlock()
	return payloadPos{l.seq, l.size}
}

// appended is the number of records appended since the log was opened.
func (l *payloadLog) appended() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.appends
}

// loadPayloadSwept reads the mark and decides whether the log holds a span the sweep owes. Only a file in the payload layout has a
// mark: such a file names records, and the mark says up to where it names every one. A file that is not in the layout names none, so
// a log it finds beside it (a layout that was reset under it: an image made by a predecessor of the replicated layout on a node that
// had the log, a restore that brought an older apply.db back) is unnamed in its whole length: the mark is forgotten (a stale mark
// would make the span the log held when the layout was reset look swept once the file adopts the layout again) and the whole log
// is the span.
func (e *Engine) loadPayloadSwept() error {
	var from payloadPos
	var stale bool
	if err := e.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("meta"))
		if layout := meta.Get([]byte("scan_index_version")); len(layout) == 1 && layout[0] == scanIndexPayload {
			if p, ok := parsePayloadPos(meta.Get([]byte(payloadSweptKey))); ok {
				from = p
			}
		} else {
			stale = meta.Get([]byte(payloadSweptKey)) != nil
		}
		return nil
	}); err != nil {
		return unavailableDB(err)
	}
	if stale {
		if err := e.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte("meta")).Delete([]byte(payloadSweptKey))
		}); err != nil {
			return unavailableDB(err)
		}
	}
	e.payloadSweptFrom = from
	e.payloadDebt.Store(from != e.payload.opened)
	e.payloadSweepSeen = true
	return nil
}

func (e *Engine) putPayloadSwept(pos payloadPos) error {
	return e.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("meta")).Put([]byte(payloadSweptKey), pos.bytes())
	})
}

// markPayloadClean moves the mark to the end of the log when the process closes: nothing it appended is unnamed. A process that
// had a span to sweep, or left an append whose commit failed, leaves the mark where it is. A failed write leaves it too (the next
// open sweeps).
func (e *Engine) markPayloadClean() {
	if !e.payloadSweepSeen || !e.payloadOn.Load() || e.payloadDebt.Load() || e.payloadDirty.Load() || e.failed {
		return
	}
	_ = e.putPayloadSwept(e.payload.end())
}

// payloadExtent is the bytes of one record (header and body): [off, end).
type payloadExtent struct{ off, end int64 }

// livePayloadExtents lists, by file, the records the references of the file name, in the span from from on.
//
// A reference lives in a bolt value of its own (a stored command, a block of a final run, a key of payload_scrub), in a page row of
// a legacy bucket (the `Log` of the row), and, in the runs layout, INSIDE the blocks of the runs: the rows of the row store are
// pairs of a block, and the page rows (the hot page of a batch) and the batch rows (the stored records of the batch) of
// scan_rows are references there. The block is a bolt value (a run below finalRunBytes) or one record of the log that a reference
// of the run names (a final run), so the references inside it are read by decoding the block. A walk of the bolt values alone does
// not see them, and the sweep zeroed the records of acknowledged pages and batches after a crash. A block that cannot be read or
// decoded is an error, not a skip: what it names cannot be told, and a sweep that zeroes what a damaged block might name destroys
// what is left.
func livePayloadExtents(ctx context.Context, tx *bolt.Tx, log *payloadLog, from payloadPos) (map[uint32][]payloadExtent, error) {
	live := map[uint32][]payloadExtent{}
	add := func(ref []byte) {
		seq, off, n, _, ok := parsePayloadRef(ref)
		if !ok || seq < from.seq {
			return
		}
		end := off + payloadHeaderLen + int64(n)
		if seq == from.seq && end <= from.off {
			return
		}
		live[seq] = append(live[seq], payloadExtent{off, end})
	}
	logField := []byte(`"Log":"`)
	note := func(v []byte) {
		switch {
		case isPayloadRef(v):
			add(v)
		case len(v) > payloadRefLen && v[0] == '{' && bytes.Contains(v, logField): // a page row that names its hot page
			if p, err := parsePageRef(v); err == nil {
				add(p.Log)
			}
		}
	}
	var walk func(b *bolt.Bucket) error
	walk = func(b *bolt.Bucket) error {
		n := 0
		return b.ForEach(func(k, v []byte) error {
			if n++; n&0x3fff == 0 {
				if err := ctx.Err(); err != nil {
					return model.Fail(model.Cancelled)
				}
			}
			if v == nil {
				if sub := b.Bucket(k); sub != nil {
					return walk(sub)
				}
				return nil
			}
			note(k) // the keys of payload_scrub are references
			note(v)
			return nil
		})
	}
	// walkRun is walk for the bucket of a run of the query indexes or of the row store: its values are blocks (or references to the
	// log records that hold them), whose pairs are what names the pages and the batches of the row store.
	var blocks blockReader
	walkRun := func(b *bolt.Bucket) error {
		n := 0
		return b.ForEach(func(_, v []byte) error {
			if n++; n&0xff == 0 {
				if err := ctx.Err(); err != nil {
					return model.Fail(model.Cancelled)
				}
			}
			note(v) // a block of the log: the record is named
			block := v
			if isPayloadRef(v) {
				// A record appended before the mark names records appended before it (the writer of a block logs what the block
				// names first), and what lies below the mark is not in the span: it need not be read.
				if seq, off, ln, _, _ := parsePayloadRef(v); seq < from.seq || seq == from.seq && off+payloadHeaderLen+int64(ln) <= from.off {
					return nil
				}
				var err error
				if block, err = log.readCold(v); err != nil {
					return err
				}
			}
			blk, ok := parseIndexBlock(block)
			if !ok {
				return model.Fail(model.Corrupt)
			}
			blocks.reset(blk, 0)
			for blocks.next() {
				note(blocks.val)
			}
			if blocks.bad || blocks.idx != blk.n || blocks.pos != blk.recEnd {
				return model.Fail(model.Corrupt)
			}
			return nil
		})
	}
	err := tx.ForEach(func(name []byte, b *bolt.Bucket) error {
		if isIndexRunBucket(name) {
			return walkRun(b)
		}
		return walk(b)
	})
	return live, err
}

// isIndexRunBucket reports whether a top-level bucket is the bucket of a run of one of the three block-run indexes
// (indexRunBucketName).
func isIndexRunBucket(name []byte) bool {
	for _, idx := range []string{"scan_time", "scan_postings", rowsIndex} {
		if len(name) == len(idx)+2+16 && bytes.HasPrefix(name, []byte(idx)) && name[len(idx)] == '.' && name[len(idx)+1] == 'r' {
			return true
		}
	}
	return false
}

// payloadSweepBlock is the size of one read of the sweep.
const payloadSweepBlock = 1 << 20

// zeroUnnamed zeroes the bytes of file seq in [from, to) that no extent of live covers, and makes that durable. It reads before it
// writes: a range that is zero already is not written.
func (l *payloadLog) zeroUnnamed(ctx context.Context, seq uint32, from, to int64, live []payloadExtent) (zeroed int64, err error) {
	if from >= to {
		return 0, nil
	}
	f, err := l.fs.OpenFile(payloadPath(l.dir, seq), os.O_RDWR, 0)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if fi, serr := f.Stat(); serr != nil {
		return 0, serr
	} else if fi.Size() < to {
		to = fi.Size()
	}
	sort.Slice(live, func(i, j int) bool { return live[i].off < live[j].off })
	buf := make([]byte, payloadSweepBlock)
	var wrote bool
	gap := func(a, b int64) error {
		for a < b {
			if err := ctx.Err(); err != nil {
				return model.Fail(model.Cancelled)
			}
			n := min(int64(len(buf)), b-a)
			if _, err := f.ReadAt(buf[:n], a); err != nil {
				return err
			}
			if !allZero(buf[:n]) {
				clear(buf[:n])
				if _, err := f.WriteAt(buf[:n], a); err != nil {
					return err
				}
				wrote = true
				zeroed += n
			}
			a += n
		}
		return nil
	}
	cur := from
	for _, x := range live {
		if x.off >= to {
			break
		}
		if x.off > cur {
			if err = gap(cur, x.off); err != nil {
				return zeroed, err
			}
		}
		cur = max(cur, x.end)
	}
	if cur < to {
		if err = gap(cur, to); err != nil {
			return zeroed, err
		}
	}
	if wrote {
		if err = f.Sync(); err != nil {
			return zeroed, err
		}
	}
	return zeroed, nil
}

func allZero(b []byte) bool {
	for len(b) >= 8 {
		if binary.LittleEndian.Uint64(b) != 0 {
			return false
		}
		b = b[8:]
	}
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// payloadSeqs lists the files of the log, ascending.
func (l *payloadLog) seqs() ([]uint32, error) {
	names, err := l.fs.Files(l.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []uint32
	for _, name := range names {
		if !strings.HasSuffix(name, ".spl") {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSuffix(name, ".spl"), 10, 32)
		if err != nil || name != payloadFileName(uint32(n)) {
			return nil, model.Fail(model.Corrupt)
		}
		out = append(out, uint32(n))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// sweepPayloadOrphans zeroes the records no reference names in the span the log had past its mark when it was opened (see the top
// of this file), then moves the mark to the end of the span. It does nothing when there is no span. The erasure pass calls it
// before it reports bytes gone. A file that is not in the payload layout has a span too when its directory holds a log
// (loadPayloadSwept); it keeps no mark, so the next open finds the span again.
func (e *Engine) sweepPayloadOrphans(ctx context.Context) error {
	if !e.payloadDebt.Load() {
		return nil
	}
	e.payloadSweepMu.Lock()
	defer e.payloadSweepMu.Unlock()
	if !e.payloadDebt.Load() {
		return nil
	}
	from, to := e.payloadSweptFrom, e.payload.opened
	var live map[uint32][]payloadExtent
	if err := e.db.View(func(tx *bolt.Tx) (err error) {
		live, err = livePayloadExtents(ctx, tx, e.payload, from)
		return err
	}); err != nil {
		return unavailableDB(err)
	}
	seqs, err := e.payload.seqs()
	if err != nil {
		return err
	}
	for _, seq := range seqs {
		if seq < from.seq || seq > to.seq || seq == 0 {
			continue
		}
		start, end := int64(0), int64(1<<62)
		if seq == from.seq {
			start = from.off
		}
		if seq == to.seq {
			end = to.off
		}
		if end == 1<<62 { // a file the log left complete: its size when it was opened is its size now
			size, err := e.payload.fs.Size(payloadPath(e.payload.dir, seq))
			if err != nil {
				return err
			}
			end = size
		}
		if _, err = e.payload.zeroUnnamed(ctx, seq, start, end, live[seq]); err != nil {
			return err
		}
	}
	if e.payloadOn.Load() {
		if err = e.putPayloadSwept(to); err != nil {
			return unavailableDB(err)
		}
	}
	e.payloadSweptFrom = to
	e.payloadDebt.Store(false)
	return nil
}
