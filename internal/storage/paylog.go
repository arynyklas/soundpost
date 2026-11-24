// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/durablefs"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The owned payload log (decision D89, L2w20Admission23).
//
// apply.db is a metadata primitive, not a telemetry store (the design's storage section), and the single-host gate showed the cost
// of using it as one: 30 GB of a 37 GB data directory after one hour at 2,000 records/s, about 18 KB of one bolt file per batch of
// four records, a working set that outgrew the 32 GB host's page cache at t=1,850 s (major faults from 0 to 2,500 a second, the
// acknowledged rate halving). What an append wrote into bolt was mostly payload: the command (replica_commands), the stored records
// (batches) and the hot page of the records (scan_pages), copy-on-write pages of a mapped file the process keeps resident.
//
// The payload log holds those bytes outside bolt, in append-only files `payload/NNNNNNNN.spl` of at most payloadFileLimit bytes.
// A record is a 12-byte header (magic "SPL1", the length, CRC32C of the bytes) and the bytes. Bolt keeps a payload reference in
// the place of the value: payloadRefLen bytes, the marker, the file, the offset of the record, the length and the CRC32C. A
// value that is not a reference is the bytes themselves (every value a previous release or a file before the layout holds), so
// both forms are legal in one file, and a reference is never written until the layout is adopted (adoptPayloadLayout: the
// installation is contracted, and the file's scan_index_version moves to scanIndexPayload, a number the previous builds refuse).
//
// Durability. An append writes the record into the file and the apply that carries its reference syncs the file first
// (externalize: the apply syncs the log before it starts the commit that carries the reference): a reference that reached disk names bytes that reached
// disk, and an acknowledged append is acknowledged after both. A crash between the two leaves bytes no reference names: they are
// dead space, never read.
//
// Erasure. The bytes of an erased command are zeroed in place (scrub, by the reference that named them) before the erasure is
// reported done: the references are owed by the commit that replaced them (payloadScrubBucket) and settled by the scrub pass.
const (
	payloadDirName   = "payload"
	payloadMarker    = 0xF1 // the first byte of a reference; no JSON value starts with it
	payloadRefLen    = 1 + 4 + 8 + 4 + 4
	payloadHeaderLen = 12
	// payloadFileLimit rolls to a new file; a variable of the tests.
	payloadFileLimitDefault = 256 << 20
	payloadScrubBucket      = "payload_scrub" // references owed a zeroing, key = the reference
)

// payloadDropEvery is how many synced bytes accumulate before their cached pages are queued to be dropped.
var payloadDropEvery int64 = 8 << 20

// payloadKeep is how long the pages of a synced record stay in the page cache before they are dropped. The readers of a record that
// was just written (the settlement of its window, the derivation of the window for a snapshot cut, the advance of the verified
// point a minute later) read it once each; dropped at the sync, every one of those reads was a read from the disk made inside a
// read transaction of apply.db, and a read transaction held across them keeps bolt from reusing the pages freed meanwhile: at the
// single-host gate (L2w20Admission36, G8) apply.db went from 0.33 to 2.66 GB in 20 s at the first snapshot cuts, and the log was read
// 4-5 times from the disk at its own write rate. A record is dropped once its readers have had their turn.
var payloadKeep = 3 * time.Minute

// dropSpan is a span of a payload file whose pages are to be dropped at at+payloadKeep.
type dropSpan struct {
	seq      uint32
	from, to int64
	at       time.Time
}

var payloadMagic = [4]byte{'S', 'P', 'L', '1'}
var payloadCRC = crc32.MakeTable(crc32.Castagnoli)

// payloadFileLimit is the size at which the log starts a new file.
var payloadFileLimit int64 = payloadFileLimitDefault

// payloadLog is the append-only files of one data directory.
type payloadLog struct {
	dir    string
	opened payloadPos // the end of the log when it was opened: what a crashed process left is before it, what this one appends after

	mu      sync.Mutex
	cur     *os.File // the file appended to; nil until the first append (or open)
	seq     uint32
	size    int64
	appends uint64 // records appended so far (a background chunk that fails after appending leaves records no commit names)
	synced  int64  // bytes of cur known durable
	dropped int64  // bytes of cur that were handed to queue (their pages are dropped at once or after payloadKeep)
	queue   []dropSpan
	pending []*os.File

	rmu   sync.RWMutex
	reads map[uint32]*os.File

	nreads atomic.Int64 // records read (read); a test and the diagnostic build count what a start reads
}

func payloadFileName(seq uint32) string { return fmt.Sprintf("%08d.spl", seq) }

// openPayloadLog opens the log of dir (the files that exist; nothing is created until the first append).
func openPayloadLog(dir string) (*payloadLog, error) {
	l := &payloadLog{dir: dir, reads: map[uint32]*os.File{}}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	var seqs []uint32
	for _, en := range entries {
		name := en.Name()
		if en.IsDir() || !strings.HasSuffix(name, ".spl") {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSuffix(name, ".spl"), 10, 32)
		if err != nil || name != payloadFileName(uint32(n)) {
			return nil, model.Fail(model.Corrupt)
		}
		seqs = append(seqs, uint32(n))
	}
	if len(seqs) == 0 {
		return l, nil
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	last := seqs[len(seqs)-1]
	f, err := os.OpenFile(filepath.Join(dir, payloadFileName(last)), os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	l.cur, l.seq, l.size, l.synced, l.dropped = f, last, fi.Size(), fi.Size(), fi.Size()
	l.opened = payloadPos{last, fi.Size()}
	return l, nil
}

func isPayloadRef(v []byte) bool { return len(v) == payloadRefLen && v[0] == payloadMarker }

// roll starts the next file; l.mu is held. The file that was appended to is synced before it is left, so that a reference to it
// never depends on a sync of a file nobody calls sync on again.
func (l *payloadLog) roll() error {
	if l.cur != nil {
		if err := l.cur.Sync(); err != nil {
			return err
		}
		l.pending = append(l.pending, l.cur)
		if l.size > l.dropped { // the tail the file leaves is dropped with the rest of its pages
			l.queue = append(l.queue, dropSpan{seq: l.seq, from: l.dropped, to: l.size, at: time.Now()})
		}
	}
	if err := durablefs.MkdirAll(l.dir); err != nil {
		return err
	}
	seq := l.seq + 1
	f, err := os.OpenFile(filepath.Join(l.dir, payloadFileName(seq)), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = durablefs.SyncDir(l.dir); err != nil {
		f.Close()
		return err
	}
	l.cur, l.seq, l.size, l.synced, l.dropped = f, seq, 0, 0, 0
	return nil
}

// dueDrops removes and returns the spans whose pages have been cached for payloadKeep; l.mu is held.
func (l *payloadLog) dueDrops(now time.Time) []dropSpan {
	n := 0
	for n < len(l.queue) && now.Sub(l.queue[n].at) >= payloadKeep {
		n++
	}
	if n == 0 {
		return nil
	}
	due := append([]dropSpan(nil), l.queue[:n]...)
	l.queue = append(l.queue[:0], l.queue[n:]...)
	return due
}

// pastKeep reports whether the pages of the end of a record that ends at end in file seq are no longer kept for the readers of a
// record just written: a reader of such a record drops its pages itself (readCold), the span is not queued any more. Whatever
// a node opened (the files it found) is past it; so is everything when payloadKeep is zero.
func (l *payloadLog) pastKeep(seq uint32, end int64) bool {
	if payloadKeep <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.queue {
		if s.seq == seq {
			return end <= s.from
		}
	}
	return seq != l.seq || end <= l.dropped
}

// append writes b as one record and returns its reference. The bytes are not durable until sync returns.
func (l *payloadLog) append(b []byte) ([]byte, error) {
	if len(b) == 0 || int64(len(b)) > 1<<31 {
		return nil, model.Fail(model.Invalid)
	}
	rec := make([]byte, payloadHeaderLen+len(b))
	copy(rec, payloadMagic[:])
	binary.BigEndian.PutUint32(rec[4:], uint32(len(b)))
	sum := crc32.Checksum(b, payloadCRC)
	binary.BigEndian.PutUint32(rec[8:], sum)
	copy(rec[payloadHeaderLen:], b)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cur == nil || l.size > 0 && l.size+int64(len(rec)) > payloadFileLimit {
		if err := l.roll(); err != nil {
			return nil, err
		}
	}
	if _, err := l.cur.WriteAt(rec, l.size); err != nil {
		return nil, err
	}
	ref := make([]byte, payloadRefLen)
	ref[0] = payloadMarker
	binary.BigEndian.PutUint32(ref[1:], l.seq)
	binary.BigEndian.PutUint64(ref[5:], uint64(l.size))
	binary.BigEndian.PutUint32(ref[13:], uint32(len(b)))
	binary.BigEndian.PutUint32(ref[17:], sum)
	l.size += int64(len(rec))
	l.appends++
	return ref, nil
}

// sync makes every record appended before the call durable.
func (l *payloadLog) sync() error {
	l.mu.Lock()
	f, target := l.cur, l.size
	if f == nil || l.synced >= target && len(l.pending) == 0 {
		l.mu.Unlock()
		return nil
	}
	pending := l.pending
	l.pending = nil
	l.mu.Unlock()
	for _, p := range pending {
		if err := p.Close(); err != nil {
			return err
		}
	}
	if err := f.Sync(); err != nil && !errors.Is(err, os.ErrClosed) { // a rolled file was synced when it was left
		return err
	}
	l.mu.Lock()
	if l.cur == f && target > l.synced {
		l.synced = target
	}
	if l.cur == f && target-l.dropped >= payloadDropEvery {
		l.queue = append(l.queue, dropSpan{seq: l.seq, from: l.dropped, to: target, at: time.Now()})
		l.dropped = target
	}
	due := l.dueDrops(time.Now())
	l.mu.Unlock()
	for _, s := range due {
		if f, err := l.reader(s.seq); err == nil {
			dropPayloadRange(f, s.from, s.to-s.from)
		}
	}
	return nil
}

func parsePayloadRef(ref []byte) (seq uint32, off int64, n uint32, sum uint32, ok bool) {
	if !isPayloadRef(ref) {
		return
	}
	return binary.BigEndian.Uint32(ref[1:]), int64(binary.BigEndian.Uint64(ref[5:])), binary.BigEndian.Uint32(ref[13:]), binary.BigEndian.Uint32(ref[17:]), true
}

func (l *payloadLog) reader(seq uint32) (*os.File, error) {
	l.rmu.RLock()
	f := l.reads[seq]
	l.rmu.RUnlock()
	if f != nil {
		return f, nil
	}
	l.rmu.Lock()
	defer l.rmu.Unlock()
	if f = l.reads[seq]; f != nil {
		return f, nil
	}
	f, err := os.Open(filepath.Join(l.dir, payloadFileName(seq)))
	if err != nil {
		return nil, err
	}
	adviseRandomReads(f)
	l.reads[seq] = f
	return f, nil
}

// payloadReadHook, when set (tests), runs at every read of a record of any log, before the file is read: a test that asserts a reader
// never waits for the disk inside a read transaction counts the transactions open at that moment.
var payloadReadHook atomic.Pointer[func()]

// read returns the bytes a reference names, verified (the record's header, length and CRC32C against the reference).
func (l *payloadLog) read(ref []byte) ([]byte, error) {
	l.nreads.Add(1)
	if hook := payloadReadHook.Load(); hook != nil {
		(*hook)()
	}
	seq, off, n, sum, ok := parsePayloadRef(ref)
	if !ok {
		return nil, model.Fail(model.Corrupt)
	}
	f, err := l.reader(seq)
	if err != nil {
		return nil, model.Fail(model.Corrupt)
	}
	buf := make([]byte, payloadHeaderLen+int(n))
	if _, err = f.ReadAt(buf, off); err != nil {
		return nil, model.Fail(model.Corrupt)
	}
	if [4]byte(buf[:4]) != payloadMagic || binary.BigEndian.Uint32(buf[4:]) != n || binary.BigEndian.Uint32(buf[8:]) != sum || crc32.Checksum(buf[payloadHeaderLen:], payloadCRC) != sum {
		return nil, model.Fail(model.Corrupt)
	}
	return buf[payloadHeaderLen:], nil
}

// refNames reports whether ref is a reference to a record that holds exactly b, without reading the record: the length and the CRC32C
// of the reference are those of b, and the file reaches the end of the record (a record the crash cut short is not held). The bytes of
// the record itself are checked by read, which every reader of the record calls, and by the full pass of the background verification.
func (l *payloadLog) refNames(ref, b []byte) bool {
	seq, off, n, sum, ok := parsePayloadRef(ref)
	if !ok || int(n) != len(b) || crc32.Checksum(b, payloadCRC) != sum {
		return false
	}
	f, err := l.reader(seq)
	if err != nil {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Size() >= off+payloadHeaderLen+int64(n)
}

// scrub overwrites the record a reference names with zeros and makes that durable. A record already zeroed is not an error.
func (l *payloadLog) scrub(ref []byte) error { return l.scrubAll([][]byte{ref}) }

// scrubAll zeroes the records the references name, one open and one sync per file.
func (l *payloadLog) scrubAll(refs [][]byte) error {
	type span struct {
		off int64
		n   uint32
	}
	bySeq := map[uint32][]span{}
	for _, ref := range refs {
		seq, off, n, _, ok := parsePayloadRef(ref)
		if !ok {
			return model.Fail(model.Corrupt)
		}
		bySeq[seq] = append(bySeq[seq], span{off, n})
	}
	for seq, spans := range bySeq {
		f, err := os.OpenFile(filepath.Join(l.dir, payloadFileName(seq)), os.O_WRONLY, 0)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, s := range spans {
			if _, err = f.WriteAt(make([]byte, payloadHeaderLen+int(s.n)), s.off); err != nil {
				f.Close()
				return err
			}
		}
		if err = f.Sync(); err != nil {
			f.Close()
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (l *payloadLog) close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var first error
	for _, f := range append(l.pending, l.cur) {
		if f != nil {
			if err := f.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	l.pending, l.cur = nil, nil
	l.rmu.Lock()
	for _, f := range l.reads {
		f.Close()
	}
	l.reads = map[uint32]*os.File{}
	l.rmu.Unlock()
	return first
}

// payloadLogs maps an open apply.db to its log: the readers of stored commands (window derivation, settlement, snapshots,
// erasure) hold a bolt bucket and not the engine.
var payloadLogs sync.Map // *bolt.DB -> *payloadLog

// storedValue is the bytes a value of a command or row bucket stands for: the value itself, or the record its payload reference
// names. A reference whose bytes cannot be read gives nil, which every caller already treats as a missing (corrupt) command.
func storedValue(b *bolt.Bucket, v []byte) []byte {
	if !isPayloadRef(v) {
		return v
	}
	return storedFromDB(b.Tx().DB(), v)
}

func storedFromDB(db *bolt.DB, v []byte) []byte {
	if !isPayloadRef(v) {
		return v
	}
	l, ok := payloadLogs.Load(db)
	if !ok {
		return nil
	}
	raw, err := l.(*payloadLog).read(v)
	if err != nil {
		return nil
	}
	return raw
}

// storedFromDBCold is storedFromDB for a reader that will not want the record again soon (readCold): the scan of every stored command
// that a plan or an erasure makes read the whole log, at the single-host gate 17,000 records a second for minutes, and left 70 % of it
// in the page cache of the scope (L2w20Admission36, G8: 174,773 reads in 12 s from the journal-expiry plan at 1,300 s).
func storedFromDBCold(db *bolt.DB, v []byte) []byte {
	if !isPayloadRef(v) {
		return v
	}
	l, ok := payloadLogs.Load(db)
	if !ok {
		return nil
	}
	raw, err := l.(*payloadLog).readCold(v)
	if err != nil {
		return nil
	}
	return raw
}

// storedTx is storedValue for a value read through a transaction (a row of the row store).
func storedTx(tx *bolt.Tx, v []byte) []byte { return storedFromDB(tx.DB(), v) }

// owePayloadScrub records, in the transaction that replaced or deleted a value, that the record its reference named still holds
// the old bytes.
func owePayloadScrub(tx *bolt.Tx, old []byte) error {
	if !isPayloadRef(old) {
		return nil
	}
	b, err := tx.CreateBucketIfNotExists([]byte(payloadScrubBucket))
	if err != nil {
		return err
	}
	return b.Put(old, []byte{1})
}

// payloadMinBytes is the size from which a value is stored in the log: a small command (a fence, a cancellation) costs less in the
// row than a record and a reference.
const payloadMinBytes = 256

// externalize moves the payload of one apply out of the transaction that will carry its references: the command, the stored records of
// the batch and the hot pages of its records are appended to the log, and the log is synced, before the transaction starts. A
// reference that reaches disk therefore names bytes that reached disk (paylog.go, Durability).
func (e *Engine) externalize(plan *applyPlan) error {
	if len(plan.payload) >= payloadMinBytes && !isRedactedCommand(plan.payload) { // a redacted command stays in its row (redactedCommands reads it there)
		ref, err := e.payload.append(plan.payload)
		if err != nil {
			return err
		}
		plan.ref = ref
	}
	if p := plan.prep; p != nil {
		if len(p.batches) >= payloadMinBytes {
			ref, err := e.payload.append(p.batches)
			if err != nil {
				return err
			}
			p.batchesRef = ref
		}
		if p.index != nil {
			for i := range p.index.pages {
				pg := &p.index.pages[i]
				if len(pg.ref.Hot) == 0 {
					continue
				}
				ref, err := e.payload.append(pg.ref.Hot)
				if err != nil {
					return err
				}
				pg.ref.Hot, pg.ref.Log = nil, ref
				if pg.meta, err = pageRefBytes(pg.ref); err != nil {
					return err
				}
			}
		}
	}
	if err := e.trip("payload_sync"); err != nil { // the records are written, not yet synced
		return err
	}
	if err := e.payload.sync(); err != nil {
		return err
	}
	return e.trip("payload_synced") // the records are durable, no reference to them is committed yet
}

// commandAt is the stored command at key of the replica_commands bucket: its bytes, whether they are in the row or in the log.
func commandAt(commands *bolt.Bucket, key []byte) []byte {
	return storedValue(commands, commands.Get(key))
}

// readCold is read for a record that will not be wanted again soon (the derivation of a window, a settlement part, the verification of
// a page): the pages of the record are forgotten once read. The log's pages are dropped after their sync so that the page cache of the
// scope is not the log; a read that leaves them cached, twice for each command (the record, then the file), made them the active pages
// of the scope, and at the gate they pushed out apply.db and the journals once the scope was full (L2w20Admission34, G6: active file 12
// GB, apply.db 0.81 -> 0.09 GB cached, refaults 25,000 a second). The verification of the tail did the same once a minute for every
// page of the last minute (L2w20Admission35: 71 % of the log cached at every size, the disk read rate equal to the log's write rate).
func (l *payloadLog) readCold(ref []byte) ([]byte, error) {
	raw, err := l.read(ref)
	if err != nil {
		return nil, err
	}
	if seq, off, n, _, ok := parsePayloadRef(ref); ok && l.pastKeep(seq, off+payloadHeaderLen+int64(n)) {
		if f, err := l.reader(seq); err == nil {
			dropPayloadRange(f, off, payloadHeaderLen+int64(n))
		}
	}
	return raw, nil
}

// commandAtCold is commandAt for a reader that will not want the record again soon (readCold).
func commandAtCold(commands *bolt.Bucket, key []byte) []byte {
	v := commands.Get(key)
	if !isPayloadRef(v) {
		return v
	}
	l, ok := payloadLogs.Load(commands.Tx().DB())
	if !ok {
		return nil
	}
	raw, err := l.(*payloadLog).readCold(v)
	if err != nil {
		return nil
	}
	return raw
}

// payloadScrubChunk bounds the records zeroed by one write transaction.
const payloadScrubChunk = 4096

var errPayloadScrubFull = errors.New("payload scrub chunk full")

// payloadScrubOwed reports whether a zeroing is owed (a read transaction: cheap, never the write lock).
func (e *Engine) payloadScrubOwed() bool {
	owed := false
	_ = e.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket([]byte(payloadScrubBucket)); b != nil {
			k, _ := b.Cursor().First()
			owed = k != nil
		}
		return nil
	})
	return owed
}

// scrubPayload zeroes, in the payload log, every record that no value names any more (owePayloadScrub: erased, replaced or
// published bytes), then forgets them, in write transactions that no reader overlaps: a reader that began before the replacement may
// still hold the reference and would find zeros (the rule of scrubChunk). busy is true when a reader stayed open through every
// attempt. A crash between the zeroing and the commit zeroes the same records again.
func (e *Engine) scrubPayload(ctx context.Context, cfg scrubConfig) (busy bool, err error) {
	for {
		var more bool
		for attempt := 0; ; attempt++ {
			more = false
			err = e.db.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(payloadScrubBucket))
				if b == nil {
					return nil
				}
				if k, _ := b.Cursor().First(); k == nil {
					return nil
				}
				if e.db.openReaders() > 0 || e.db.Stats().OpenTxN > 0 {
					return errScrubBusy
				}
				owed := make([][]byte, 0, 64)
				if err := b.ForEach(func(k, _ []byte) error {
					if len(owed) == payloadScrubChunk {
						more = true
						return errPayloadScrubFull
					}
					owed = append(owed, append([]byte(nil), k...))
					return nil
				}); err != nil && !errors.Is(err, errPayloadScrubFull) {
					return err
				}
				if err := e.payload.scrubAll(owed); err != nil {
					return err
				}
				for _, ref := range owed {
					if err := b.Delete(ref); err != nil {
						return err
					}
				}
				return nil
			})
			if err == nil {
				break
			}
			if !errors.Is(err, errScrubBusy) {
				return false, unavailableDB(err)
			}
			if attempt+1 >= cfg.attempts {
				return true, nil
			}
			select {
			case <-ctx.Done():
				return false, model.Fail(model.Cancelled)
			case <-time.After(cfg.backoff):
			}
		}
		if !more {
			return false, nil
		}
	}
}

// oweUnusedPayload owes a zeroing for the records externalize logged for a batch that the apply then stored in another shape (a
// sample the store held already is skipped, so the batch and its pages are derived again): nothing names them, and they hold the
// bytes of the batch.
func (p *batchPrep) oweUnusedPayload(tx *bolt.Tx) error {
	if err := owePayloadScrub(tx, p.batchesRef); err != nil {
		return err
	}
	if p.index != nil {
		for i := range p.index.pages {
			if err := owePayloadScrub(tx, p.index.pages[i].ref.Log); err != nil {
				return err
			}
		}
	}
	return nil
}
