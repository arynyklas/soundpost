// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"cmp"
	"compress/flate"
	"encoding/binary"
	"io"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The overlay of the admission ledger (D83, L2w20Admission28).
//
// Five tables of the ledger are written by every admission at places that are not together: the reservation keys
// (tableKeys), the reference counts of the series under each quota key (tableSeries) and the settled reference counts
// (tableChargeSeries), which are random keys, and the reservations (tableReservations) and the quota heads
// (tableQuotas), which are rewritten by every command. A commit of the single-host gate writes a few dozen distinct
// series and keys; in a B+tree each of them is a leaf page of its own, once at the reserve and once at the settle: 124
// of the 155 pages of a control commit were those, and the rest were the reservations and the heads. What a commit
// writes is bounded by what it carries only if the places of the tables are not written by the commit.
//
// So a commit appends what it changed (the records it put and the keys it deleted, in the five tables) as one blob to a
// log under sequential keys (the bucket adm_ov): a few pages, whatever the ledger holds. The records are read from
// the log's two newest generations, kept in memory as maps, and from the base table behind them. When the active
// generation holds as many bytes of records as the last fold wrote (at least ovFreezeMin, at most ovFreezeMax) it is
// frozen, a new one starts, and each of the next commits folds a bounded share of the frozen generation (ovFoldMin
// records, or twice what the commit appended) into the base tables in the order of the base, so that every page of a
// table is written once for all the records of the generation that fall on it; the frozen generation is dropped (its
// blobs deleted in one range, no page rewritten) when its last record is in the base. The base of the series tables is
// a set of ovBlocks blocks by the hash of the series (ledger_blocks.go): a fold writes at most that many blocks whatever
// the history is, and the other tables are plain sorted buckets.
//
// The overlay is a LOCAL layout. The records, their keys and values, the accumulator and every digest, patch and
// snapshot are those of the plain tables; reads see the log first and the base after it, in key order, tombstones
// hiding what lies behind them (mergeCursor). The version of the overlay (ov_meta.seq) moves with every commit that
// changes it, and the shared copy of the generations (ovShared, one per file) is used only by a transaction whose
// snapshot is the version the copy holds: a reader older than the copy loads the generations from the log of its own snapshot
// (once for all the readers of that version), and a copy that is behind or invalid is loaded once, by the first transaction
// that needs it (rebuild), and then follows the commits parked behind it (apply), so no transaction ever sees a state that is not
// its own and none loads what another is loading.

const (
	ovSlots = 5
	// ovChunk is the size of the pieces a blob is stored in: bolt keeps up to four elements in one leaf however big they
	// are, and writes the leaf whole whenever one of them is added, so a blob stored in one piece is written again by
	// each of the three commits that follow it.
	ovChunk    = 1000
	ovBaseFill = 0.9
)

// ovHandlerWait is how long a transaction whose snapshot is newer than the shared copy waits for the commit handler that brings
// the copy up to date before it loads its own: the handler of a commit that is done runs, and only a thread that was not
// scheduled for more than this (50 ms was less than the stalls of the 900 s runs at 600 % CPU) makes a load of the wait; a
// handler that is lost (a gap in the parked commits) costs one wait, once. A variable of the tests.
var ovHandlerWait = 500 * time.Millisecond

// ovParkMax is the commits that may wait, parked, for a copy that is invalid or behind (apply): the gate's 57 commits a second
// fill it in 72 s, and a gap that has not closed by then (every commit of that time holds a few kilobytes of records) leaves the
// copy invalid for the next reader to load.
var ovParkMax = 1 << 12

// The sizes of the overlay (variables so that the tests of the overlay can make a generation small).
var (
	// ovFreezeMin and ovFreezeMax are the bytes of records (keys and values; a record rewritten counts again) the active
	// generation holds when it is frozen and a new one starts: four times what the last fold wrote to the base tables,
	// within these bounds. A fold of the series tables writes every block, and a record takes six times more bytes in a
	// generation (the series, a quota key of seventy bytes, a count) than in its block (a number for the quota key), so
	// a generation of four times the bytes of a fold costs about as many bytes of fold as the log of its commits does.
	// The memory of the overlay is two generations at most: ovFreezeMax bounds it.
	ovFreezeMin = uint64(1 << 20)
	ovFreezeMax = uint64(24 << 20)
	// ovFoldMin is the records of the frozen generation a commit folds into the base tables when it appended fewer.
	ovFoldMin = 256
	// ovBulkEntries is the number of records of one commit above which they are written to the base tables at once
	// instead of the log (a replacement of the ledger, a migration): the overlay is folded first.
	ovBulkEntries = 1 << 14
)

var (
	ovLogBucket  = []byte("adm_ov")
	ovTierBucket = []byte("adm_tiers")
	ovMetaKey    = []byte("ov_meta")
)

// ovTableOf is the table of each slot of the overlay; the slot of a table is ovSlotOf.
var ovTableOf = [ovSlots]int{tableKeys, tableSeries, tableChargeSeries, tableReservations, tableQuotas}

// ovSeriesSlots are the slots of the series tables: their base is a set of blocks.
var ovSeriesSlots = [2]int{1, 2}

// ovCounters counts what the overlay wrote to the file (the blobs of the log, the blocks of the folds); the tests read it.
var ovCounters struct{ blobs, blobBytes, blocks, blockBytes atomic.Uint64 }

// ovStats counts, for a diagnostic build (diag_stats_on.go), the places where a commit or a reader of the overlay does a
// large piece of work under the writer lock: the fold steps, the delete of a folded generation's blobs, the rebuild of
// generations from the log, and the generations frozen. Three atomics per event.
var ovStats struct {
	foldSteps, foldNS, maxFoldNS atomic.Int64
	drops, dropNS, maxDropNS     atomic.Int64
	loads, loadNS, maxLoadNS     atomic.Int64
	freezes, parked              atomic.Int64
}

// ovNote adds one event that began at began to the count, the total and the longest of a counter group.
func ovNote(n, total, longest *atomic.Int64, began time.Time) {
	took := time.Since(began).Nanoseconds()
	n.Add(1)
	total.Add(took)
	for old := longest.Load(); took > old && !longest.CompareAndSwap(old, took); old = longest.Load() {
	}
}

// timedLoadGens is loadGens, counted.
func timedLoadGens(log *bolt.Bucket, m ovMeta) (active, frozen *ovGen) {
	began := time.Now()
	active, frozen = loadGens(log, m)
	ovNote(&ovStats.loads, &ovStats.loadNS, &ovStats.maxLoadNS, began)
	return active, frozen
}

// ovSlotOf is the slot of table in the overlay, -1 for a table that lives in its bucket alone.
func ovSlotOf(table int) int {
	switch table {
	case tableKeys:
		return 0
	case tableSeries:
		return 1
	case tableChargeSeries:
		return 2
	case tableReservations:
		return 3
	case tableQuotas:
		return 4
	}
	return -1
}

// ovBlocked says whether the base of the slot is a set of blocks (the series tables) and not a sorted bucket.
func ovBlocked(slot int) bool { return slot == 1 || slot == 2 }

// ovFreezeAt is the bytes of records at which the active generation is frozen, given what the last fold wrote.
func ovFreezeAt(lastFold uint64) uint64 { return min(max(lastFold*4, ovFreezeMin), ovFreezeMax) }

// tableCursor is the part of a bolt cursor the ledger reads its tables with.
type tableCursor interface {
	First() (key, value []byte)
	Next() (key, value []byte)
	Seek(seek []byte) (key, value []byte)
}

// ledgerTable is a table of the ledger: a bucket, or the overlay of one.
type ledgerTable interface {
	Get(key []byte) []byte
	Put(key, value []byte) error
	Delete(key []byte) error
	Cursor() tableCursor
}

// boltTable is a table that lives in its bucket alone.
type boltTable struct{ *bolt.Bucket }

func (b boltTable) Cursor() tableCursor { return b.Bucket.Cursor() }

// ovEnt is a record of a generation: v is nil for a deleted one. b is the block of a series record, set where the
// records are ordered for a fold (ovOrder).
type ovEnt struct {
	k string
	v []byte
	b uint32
}

// ovOrder sorts the records of slot in the order its base is written in: by key, and by block and key for blocks.
func ovOrder(slot int, ents []ovEnt) {
	if ovBlocked(slot) {
		for i := range ents {
			ents[i].b = blockOfKey(ents[i].k)
		}
		slices.SortFunc(ents, func(a, b ovEnt) int {
			if a.b != b.b {
				return cmp.Compare(a.b, b.b)
			}
			return strings.Compare(a.k, b.k)
		})
		return
	}
	slices.SortFunc(ents, func(a, b ovEnt) int { return strings.Compare(a.k, b.k) })
}

type ovMaps = [ovSlots]map[string][]byte

func newOvMaps() (m ovMaps) {
	for i := range m {
		m[i] = map[string][]byte{}
	}
	return
}

// ovGen is a generation of the log held in memory: per slot the newest value of each key it holds.
type ovGen struct {
	id     uint64
	m      ovMaps
	once   sync.Once
	ready  atomic.Bool // order has been made
	sorted [ovSlots][]ovEnt
}

func newOvGen(id uint64) *ovGen { return &ovGen{id: id, m: newOvMaps()} }

// order is the records of the generation in the order a fold writes them, per slot (made once: a frozen generation
// is never changed).
func (g *ovGen) order() *[ovSlots][]ovEnt {
	g.once.Do(func() {
		for slot := range g.m {
			ents := make([]ovEnt, 0, len(g.m[slot]))
			for k, v := range g.m[slot] {
				ents = append(ents, ovEnt{k: k, v: v})
			}
			ovOrder(slot, ents)
			g.sorted[slot] = ents
		}
		g.ready.Store(true)
	})
	return &g.sorted
}

func lookupGens(active, frozen *ovGen, slot int, key []byte) ([]byte, bool) {
	if v, ok := active.m[slot][string(key)]; ok {
		return v, true
	}
	if frozen != nil {
		if v, ok := frozen.m[slot][string(key)]; ok {
			return v, true
		}
	}
	return nil, false
}

// ovMeta is the state of the log, kept under ov_meta of the control bucket (written by every commit that changes the
// overlay, in the page the accumulator already dirties).
type ovMeta struct {
	seq       uint64 // the version: the commits that changed the overlay
	active    uint64 // the generation commits append to
	frozen    uint64 // the generation being folded into the base tables, 0 when none
	folded    uint64 // the records of the frozen generation already in the base tables, in the order of ovGen.order
	blobN     uint64 // the blobs of the active generation
	bytes     uint64 // the bytes of the records of the active generation (a record rewritten counts again)
	foldBytes uint64 // the bytes the fold of the frozen generation has written to the base tables
	lastFold  uint64 // the bytes the last complete fold wrote: the active generation is frozen at half of it (ovFreezeAt)
}

const ovMetaLen = 64

func readOvMeta(ctrl *bolt.Bucket) ovMeta {
	m := ovMeta{active: 1}
	if raw := ctrl.Get(ovMetaKey); len(raw) == ovMetaLen {
		f := func(i int) uint64 { return binary.BigEndian.Uint64(raw[i*8:]) }
		m = ovMeta{seq: f(0), active: f(1), frozen: f(2), folded: f(3), blobN: f(4), bytes: f(5), foldBytes: f(6), lastFold: f(7)}
	}
	return m
}

func (m ovMeta) encode() []byte {
	raw := make([]byte, ovMetaLen)
	for i, v := range [8]uint64{m.seq, m.active, m.frozen, m.folded, m.blobN, m.bytes, m.foldBytes, m.lastFold} {
		binary.BigEndian.PutUint64(raw[i*8:], v)
	}
	return raw
}

// blobKey is the key of piece i of blob n of generation gen.
func blobKey(gen, n uint64, i int) []byte {
	k := make([]byte, 18)
	binary.BigEndian.PutUint64(k, gen)
	binary.BigEndian.PutUint64(k[8:], n)
	binary.BigEndian.PutUint16(k[16:], uint16(i))
	return k
}

// putBlob stores a blob as pieces of ovChunk bytes under sequential keys.
func putBlob(log *bolt.Bucket, gen, n uint64, blob []byte) error {
	for i := 0; ; i++ {
		end := min(len(blob), (i+1)*ovChunk)
		if err := log.Put(blobKey(gen, n, i), blob[i*ovChunk:end]); err != nil {
			return err
		}
		if end == len(blob) {
			return nil
		}
	}
}

var flateWriters = sync.Pool{New: func() any {
	w, _ := flate.NewWriter(io.Discard, flate.BestSpeed)
	return w
}}

// encodeBlob is the records of one commit as a blob: per slot the count and the records in key order, each key as
// the length it shares with the one before it and the rest, each value as its length plus one (zero: deleted), the
// whole compressed (the quota keys a series is charged under repeat in every record).
func encodeBlob(ents *ovMaps) []byte {
	raw := make([]byte, 0, 2048)
	for slot := range ents {
		keys := make([]string, 0, len(ents[slot]))
		for k := range ents[slot] {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		raw = binary.AppendUvarint(raw, uint64(len(keys)))
		prev := ""
		for _, k := range keys {
			shared := 0
			for shared < len(prev) && shared < len(k) && prev[shared] == k[shared] {
				shared++
			}
			raw = binary.AppendUvarint(raw, uint64(shared))
			raw = binary.AppendUvarint(raw, uint64(len(k)-shared))
			raw = append(raw, k[shared:]...)
			if v := ents[slot][k]; v == nil {
				raw = append(raw, 0)
			} else {
				raw = binary.AppendUvarint(raw, uint64(len(v))+1)
				raw = append(raw, v...)
			}
			prev = k
		}
	}
	var buf bytes.Buffer
	buf.WriteByte(1)
	w := flateWriters.Get().(*flate.Writer)
	w.Reset(&buf)
	_, _ = w.Write(raw)
	_ = w.Close()
	flateWriters.Put(w)
	return buf.Bytes()
}

// decodeBlob calls fn for every record of a blob.
func decodeBlob(blob []byte, fn func(slot int, k string, v []byte)) error {
	if len(blob) < 1 || blob[0] != 1 {
		return model.Fail(model.Corrupt)
	}
	r := flate.NewReader(bytes.NewReader(blob[1:]))
	raw, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		return model.Fail(model.Corrupt)
	}
	uvarint := func() (uint64, bool) {
		v, n := binary.Uvarint(raw)
		if n <= 0 {
			return 0, false
		}
		raw = raw[n:]
		return v, true
	}
	for slot := range ovSlots {
		count, ok := uvarint()
		if !ok {
			return model.Fail(model.Corrupt)
		}
		prev := ""
		for ; count > 0; count-- {
			shared, ok1 := uvarint()
			rest, ok2 := uvarint()
			if !ok1 || !ok2 || shared > uint64(len(prev)) || rest > uint64(len(raw)) {
				return model.Fail(model.Corrupt)
			}
			k := prev[:shared] + string(raw[:rest])
			raw = raw[rest:]
			vl, ok := uvarint()
			if !ok || vl > uint64(len(raw))+1 {
				return model.Fail(model.Corrupt)
			}
			var v []byte
			if vl > 0 {
				v = raw[: vl-1 : vl-1]
				raw = raw[vl-1:]
			}
			fn(slot, k, v)
			prev = k
		}
	}
	return nil
}

// loadGens reads the generations the snapshot of meta holds from the log.
func loadGens(log *bolt.Bucket, m ovMeta) (active, frozen *ovGen) {
	active = newOvGen(m.active)
	if m.frozen != 0 {
		frozen = newOvGen(m.frozen)
	}
	if log == nil {
		return
	}
	var (
		cur  []byte
		curG *ovGen
		key  [16]byte
		have bool
	)
	flush := func() {
		if curG == nil {
			return
		}
		if err := decodeBlob(cur, func(slot int, k string, val []byte) { curG.m[slot][k] = val }); err != nil {
			panic("control: the overlay log of the ledger is corrupt")
		}
	}
	c := log.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if len(k) != 18 {
			continue
		}
		if !have || !bytes.Equal(k[:16], key[:]) {
			flush()
			have = true
			copy(key[:], k[:16])
			cur, curG = nil, nil
			gen, n := binary.BigEndian.Uint64(k), binary.BigEndian.Uint64(k[8:])
			switch {
			case gen == m.active:
				if n < m.blobN { // the others were appended by the transaction that is reading its own writes
					curG = active
				}
			case m.frozen != 0 && gen == m.frozen:
				curG = frozen
			}
		}
		if curG != nil {
			cur = append(cur, v...)
		}
	}
	flush()
	return
}

// ovShared is the generations of the newest committed version of the overlay of one file, shared by the transactions
// that read that version.
type ovShared struct {
	mu     sync.RWMutex
	ok     bool
	seq    uint64
	active *ovGen
	frozen *ovGen
	writer *ovWriter
	// parked is the commits whose handlers ran before the copy held the version they started from, by that version.
	parked map[uint64]*ovWriter
	// build is held by the transaction that loads the shared copy from the log: one load at a time for all that need it. oldMu
	// is held by the one that loads the generations of a version older than the copy, for the readers of that version (old is the
	// last such load); a load for the copy never waits for one of those.
	build sync.Mutex
	oldMu sync.Mutex
	old   *ovOld
}

// ovOld is the generations loaded for the readers of one version that is older than the shared copy.
type ovOld struct {
	seq            uint64
	active, frozen *ovGen
}

// ovRegistry maps a bolt handle to its shared generations.
var ovRegistry sync.Map

func ovSharedOf(db *bolt.DB) *ovShared {
	if v, ok := ovRegistry.Load(db); ok {
		return v.(*ovShared)
	}
	v, _ := ovRegistry.LoadOrStore(db, &ovShared{})
	return v.(*ovShared)
}

func forgetOverlay(db *bolt.DB) { ovRegistry.Delete(db) }

type ovOpKind uint8

const (
	ovAppend ovOpKind = iota + 1
	ovFreeze
	ovDrop
	ovReset
)

// ovOp is a change of the generations a transaction made, replayed on the shared copy when it commits.
type ovOp struct {
	kind ovOpKind
	ents ovMaps
}

// ovWriter is what the write transaction tx changed in the overlay: the records of its commands that are not in the
// log yet (pend), the ones it appended (done), and the changes of the generations to make on the shared copy when it
// commits.
type ovWriter struct {
	tx         *bolt.Tx
	base, meta ovMeta
	pend, done ovMaps
	ops        []ovOp
	touched    bool
	// voided says that the shared generations no longer describe the ledger of this transaction (it was emptied or
	// its overlay folded whole).
	voided     bool
	registered bool
}

// apply brings the shared copy to the version w committed. The handlers of two commits can run in either order (bbolt runs a
// commit's handlers after it released the writer lock, and the next writer may commit before the goroutine of the first is
// scheduled again), and a copy a reader loaded from its own snapshot is a version or fifty behind by the time it is installed
// (a load takes a second, the commits one in 17 ms): a copy that drops itself at the first commit it does not follow is
// loaded again by the next reader, and again, each time under the lock of the next writer (the stalls of L2w20Admission30's
// d3a). So w is parked under the version it started from, and the copy takes the parked commits in order as soon as it
// holds the version before them. Only a gap that does not close (ovParkMax parked commits) invalidates it.
func (sh *ovShared) apply(w *ovWriter) {
	sh.mu.Lock()
	if sh.writer == w {
		sh.writer = nil
	}
	if sh.ok && sh.seq >= w.meta.seq { // loaded from a snapshot that holds this commit
		sh.mu.Unlock()
		return
	}
	if !sh.ok || sh.seq != w.base.seq {
		ovStats.parked.Add(1) // ahead of its predecessor's handler, or the copy is not installed
	}
	if sh.parked == nil {
		sh.parked = map[uint64]*ovWriter{}
	}
	sh.parked[w.base.seq] = w
	if len(sh.parked) > ovParkMax {
		clear(sh.parked)
		sh.ok, sh.active, sh.frozen = false, nil, nil
	}
	ordered := sh.drain()
	sh.mu.Unlock()
	for _, g := range ordered {
		go g.order() // the next folds want it
	}
}

// drain applies the parked commits that follow the version of the copy, in order; the generations frozen on the way are
// returned (sh.mu is held). Nothing is applied to an invalid copy: the commits stay parked for the one that is installed.
func (sh *ovShared) drain() (frozen []*ovGen) {
	for sh.ok {
		w := sh.parked[sh.seq]
		if w == nil {
			return frozen
		}
		delete(sh.parked, sh.seq)
		for _, op := range w.ops {
			switch op.kind {
			case ovAppend:
				for slot := range op.ents {
					for k, v := range op.ents[slot] {
						sh.active.m[slot][k] = v
					}
				}
			case ovFreeze:
				sh.frozen = sh.active
				sh.active = newOvGen(sh.frozen.id + 1)
				frozen = append(frozen, sh.frozen)
			case ovDrop:
				sh.frozen = nil
			case ovReset:
				sh.frozen = nil
				sh.active = newOvGen(w.meta.active)
			}
		}
		sh.seq = w.meta.seq
	}
	return frozen
}

// install makes the generations of version seq the shared copy, unless the copy is valid and not behind it, and applies the
// commits parked behind that version (sh.mu is held). The commits the load already holds are forgotten.
func (sh *ovShared) install(active, frozen *ovGen, seq uint64) []*ovGen {
	if sh.ok && seq <= sh.seq {
		return nil
	}
	sh.active, sh.frozen, sh.seq, sh.ok = active, frozen, seq, true
	for base := range sh.parked {
		if base < seq {
			delete(sh.parked, base)
		}
	}
	return sh.drain()
}

// ovTx is the overlay as one transaction sees it.
type ovTx struct {
	tx    *bolt.Tx
	ctrl  *bolt.Bucket
	log   *bolt.Bucket
	tiers *bolt.Bucket
	tbl   [ovSlots]*bolt.Bucket
	store [ovSlots]*blockStore
	sh    *ovShared
	snap  ovMeta
	wr    *ovWriter
	// privSet says the transaction reads generations of its own (its snapshot is not the version of the shared copy).
	privSet                bool
	privActive, privFrozen *ovGen
}

func newOvTx(tx *bolt.Tx, ctrl *bolt.Bucket, raw [ledgerTableCount]*bolt.Bucket) (*ovTx, error) {
	log, tiers := tx.Bucket(ovLogBucket), tx.Bucket(ovTierBucket)
	if log == nil || tiers == nil {
		return nil, model.Fail(model.Corrupt)
	}
	ov := &ovTx{tx: tx, ctrl: ctrl, log: log, tiers: tiers, sh: ovSharedOf(tx.DB()), snap: readOvMeta(ctrl)}
	for slot, table := range ovTableOf {
		ov.tbl[slot] = raw[table]
	}
	ov.refresh()
	if tx.Writable() {
		ov.sh.mu.Lock()
		if w := ov.sh.writer; w != nil && w.tx == tx {
			ov.wr, ov.snap = w, w.base
		}
		ov.sh.mu.Unlock()
	}
	return ov, nil
}

// refresh sets what depends on the buckets of the tables (after they were created again).
func (ov *ovTx) refresh() {
	for slot := range ov.tbl {
		if ov.tx.Writable() {
			ov.tbl[slot].FillPercent = ovBaseFill
		}
		if ovBlocked(slot) {
			ov.store[slot] = &blockStore{b: ov.tbl[slot], tiers: ov.tiers}
		}
	}
	if ov.tx.Writable() {
		ov.log.FillPercent = 1
	}
}

func (ov *ovTx) writer() *ovWriter {
	if ov.wr == nil {
		ov.sh.mu.Lock()
		if w := ov.sh.writer; w != nil && w.tx == ov.tx {
			ov.wr, ov.snap = w, w.base
		} else {
			ov.wr = &ovWriter{tx: ov.tx, base: ov.snap, meta: ov.snap, pend: newOvMaps(), done: newOvMaps()}
			ov.sh.writer = ov.wr
		}
		ov.sh.mu.Unlock()
	}
	return ov.wr
}

// settle makes the transaction able to read the generations of its snapshot: either the shared copy holds that
// version, or the transaction holds generations of its own.
func (ov *ovTx) settle() {
	sh := ov.sh
	want := ov.snap.seq
	deadline := time.Now().Add(ovHandlerWait)
	for {
		sh.mu.RLock()
		ok, seq := sh.ok, sh.seq
		sh.mu.RUnlock()
		switch {
		case ok && seq == want:
			return
		case ok && seq > want:
			ov.privActive, ov.privFrozen = sh.privateGens(ov)
			ov.privSet = true
			return
		case ok && time.Now().Before(deadline):
			time.Sleep(50 * time.Microsecond) // the handler of the commit that made this version is on its way
			continue
		}
		sh.rebuild(ov)
	}
}

// rebuild loads the generations of the snapshot of ov and installs them as the shared copy, unless the transaction that came
// first did: every transaction that finds the copy invalid, or late, needs the same ones, and a load is the work of a second
// at the size the ledger reaches at the single-host gate (the log of two generations of up to 24 MiB of records, inflated and
// decoded): dozens of them at once, one for each transaction that was waiting, were the stalls of two to fifteen seconds of
// the 900 s runs (loads 8-15 and 5-15 s of load time in a two-second sample, L2w20Admission30/d3a).
func (sh *ovShared) rebuild(ov *ovTx) {
	want := ov.snap.seq
	sh.build.Lock()
	defer sh.build.Unlock()
	sh.mu.RLock()
	ok, seq := sh.ok, sh.seq
	sh.mu.RUnlock()
	if ok && seq >= want { // installed, or brought up to date by its handlers, while this transaction waited: the caller looks again
		return
	}
	active, frozen := timedLoadGens(ov.log, ov.snap)
	sh.mu.Lock()
	ordered := sh.install(active, frozen, want)
	sh.mu.Unlock()
	for _, g := range ordered {
		go g.order()
	}
}

// privateGens is the generations of a reader older than the shared copy: the last ones built for an old version are kept for the
// readers of that version, which are the ones that arrive together (the readers that began before one commit and look at the
// ledger after it). A transaction that writes holds its own writes in the log it reads and shares nothing.
func (sh *ovShared) privateGens(ov *ovTx) (active, frozen *ovGen) {
	if ov.tx.Writable() {
		return timedLoadGens(ov.log, ov.snap)
	}
	sh.oldMu.Lock()
	defer sh.oldMu.Unlock()
	if o := sh.old; o != nil && o.seq == ov.snap.seq {
		return o.active, o.frozen
	}
	active, frozen = timedLoadGens(ov.log, ov.snap)
	sh.old = &ovOld{seq: ov.snap.seq, active: active, frozen: frozen}
	return active, frozen
}

// withGens calls fn with the generations of the transaction's snapshot.
func (ov *ovTx) withGens(fn func(active, frozen *ovGen)) {
	for {
		if ov.privSet {
			fn(ov.privActive, ov.privFrozen)
			return
		}
		sh := ov.sh
		sh.mu.RLock()
		if sh.ok && sh.seq == ov.snap.seq {
			fn(sh.active, sh.frozen)
			sh.mu.RUnlock()
			return
		}
		sh.mu.RUnlock()
		ov.settle()
	}
}

// lookup is the record of key in the overlay: found with a nil value is a deleted record.
func (ov *ovTx) lookup(slot int, key []byte) ([]byte, bool) {
	if w := ov.wr; w != nil {
		if v, ok := w.pend[slot][string(key)]; ok {
			return v, true
		}
		if v, ok := w.done[slot][string(key)]; ok {
			return v, true
		}
		if w.voided {
			return nil, false
		}
	}
	for {
		if ov.privSet {
			return lookupGens(ov.privActive, ov.privFrozen, slot, key)
		}
		sh := ov.sh
		sh.mu.RLock()
		if sh.ok && sh.seq == ov.snap.seq {
			v, ok := lookupGens(sh.active, sh.frozen, slot, key)
			sh.mu.RUnlock()
			return v, ok
		}
		sh.mu.RUnlock()
		ov.settle()
	}
}

func (ov *ovTx) baseGet(slot int, key []byte) []byte {
	if ovBlocked(slot) {
		return ov.store[slot].get(key)
	}
	return ov.tbl[slot].Get(key)
}

// ovTable is the overlay of one table.
type ovTable struct {
	ov   *ovTx
	slot int
}

func (t *ovTable) Get(key []byte) []byte {
	if v, ok := t.ov.lookup(t.slot, key); ok {
		return v
	}
	return t.ov.baseGet(t.slot, key)
}

func (t *ovTable) Put(key, value []byte) error {
	if !t.ov.tx.Writable() {
		return bolt.ErrTxNotWritable
	}
	w := t.ov.writer()
	w.touched = true
	w.pend[t.slot][string(key)] = append([]byte{}, value...)
	return nil
}

func (t *ovTable) Delete(key []byte) error {
	if !t.ov.tx.Writable() {
		return bolt.ErrTxNotWritable
	}
	w := t.ov.writer()
	w.touched = true
	w.pend[t.slot][string(key)] = nil
	return nil
}

func (t *ovTable) Cursor() tableCursor { return t.ov.cursor(t.slot) }

// sliceIter is a cursor over records in key order; a deleted record has a nil value.
type sliceIter struct {
	ents []ovEnt
	i    int
}

func (s *sliceIter) at() ([]byte, []byte) {
	if s.i >= len(s.ents) {
		return nil, nil
	}
	return []byte(s.ents[s.i].k), s.ents[s.i].v
}

func (s *sliceIter) First() ([]byte, []byte) { s.i = 0; return s.at() }

func (s *sliceIter) Next() ([]byte, []byte) {
	if s.i < len(s.ents) {
		s.i++
	}
	return s.at()
}

func (s *sliceIter) Seek(p []byte) ([]byte, []byte) {
	ps := string(p)
	s.i = sort.Search(len(s.ents), func(i int) bool { return s.ents[i].k >= ps })
	return s.at()
}

// mergeCursor is the cursor over a table: the records of the overlay in front of the base table behind them.
type mergeCursor struct {
	over, base     tableCursor
	ok, bk, ov, bv []byte
}

func (c *mergeCursor) settle() ([]byte, []byte) {
	for {
		switch {
		case c.ok == nil && c.bk == nil:
			return nil, nil
		case c.bk == nil || c.ok != nil && bytes.Compare(c.ok, c.bk) <= 0:
			same := c.bk != nil && bytes.Equal(c.ok, c.bk)
			k, v := c.ok, c.ov
			c.ok, c.ov = c.over.Next()
			if same {
				c.bk, c.bv = c.base.Next()
			}
			if v == nil {
				continue // deleted in the overlay
			}
			return k, v
		default:
			k, v := c.bk, c.bv
			c.bk, c.bv = c.base.Next()
			return k, v
		}
	}
}

func (c *mergeCursor) First() ([]byte, []byte) {
	c.ok, c.ov = c.over.First()
	c.bk, c.bv = c.base.First()
	return c.settle()
}

func (c *mergeCursor) Seek(p []byte) ([]byte, []byte) {
	c.ok, c.ov = c.over.Seek(p)
	c.bk, c.bv = c.base.Seek(p)
	return c.settle()
}

func (c *mergeCursor) Next() ([]byte, []byte) { return c.settle() }

// effective is the records of the overlay of slot as the transaction sees them (the newest of each key), in key order.
func (ov *ovTx) effective(slot int) []ovEnt {
	eff := map[string][]byte{}
	add := func(m map[string][]byte) {
		for k, v := range m {
			eff[k] = v
		}
	}
	w := ov.wr
	if w == nil || !w.voided {
		ov.withGens(func(active, frozen *ovGen) {
			if frozen != nil {
				add(frozen.m[slot])
			}
			add(active.m[slot])
		})
	}
	if w != nil {
		add(w.done[slot])
		add(w.pend[slot])
	}
	ents := make([]ovEnt, 0, len(eff))
	for k, v := range eff {
		ents = append(ents, ovEnt{k: k, v: v})
	}
	slices.SortFunc(ents, func(a, b ovEnt) int { return strings.Compare(a.k, b.k) })
	return ents
}

func (ov *ovTx) cursor(slot int) tableCursor {
	var base tableCursor
	if ovBlocked(slot) {
		base = &sliceIter{ents: ov.store[slot].records()}
	} else {
		base = ov.tbl[slot].Cursor()
	}
	ents := ov.effective(slot)
	if len(ents) == 0 {
		return base
	}
	return &mergeCursor{over: &sliceIter{ents: ents}, base: base}
}

// applyBase writes records ordered by ovOrder to the base table of slot and returns the bytes it wrote.
func (ov *ovTx) applyBase(slot int, ents []ovEnt) (uint64, error) {
	if ovBlocked(slot) {
		return ov.store[slot].fold(ents)
	}
	b := ov.tbl[slot]
	var written uint64
	for _, e := range ents {
		if e.v == nil {
			if err := b.Delete([]byte(e.k)); err != nil {
				return written, err
			}
		} else {
			if err := b.Put([]byte(e.k), e.v); err != nil {
				return written, err
			}
			written += uint64(len(e.k) + len(e.v))
		}
	}
	return written, nil
}

// foldMap writes the records of m to the base table of slot and returns the bytes it wrote.
func (ov *ovTx) foldMap(slot int, m map[string][]byte) (uint64, error) {
	ents := make([]ovEnt, 0, len(m))
	for k, v := range m {
		ents = append(ents, ovEnt{k: k, v: v})
	}
	ovOrder(slot, ents)
	return ov.applyBase(slot, ents)
}

// wipe empties the overlay and its base tables (a replacement of the ledger).
func (ov *ovTx) wipe() error {
	w := ov.writer()
	for slot, table := range ovTableOf {
		name := []byte(ledgerTables[table])
		if err := ov.tx.DeleteBucket(name); err != nil {
			return err
		}
		b, err := ov.tx.CreateBucket(name)
		if err != nil {
			return err
		}
		ov.tbl[slot] = b
	}
	for _, name := range [][]byte{ovTierBucket, ovLogBucket} {
		if err := ov.tx.DeleteBucket(name); err != nil {
			return err
		}
		b, err := ov.tx.CreateBucket(name)
		if err != nil {
			return err
		}
		if string(name) == string(ovTierBucket) {
			ov.tiers = b
		} else {
			ov.log = b
		}
	}
	ov.refresh()
	m := &w.meta
	*m = ovMeta{seq: m.seq, active: max(m.active, m.frozen) + 1}
	w.pend, w.done = newOvMaps(), newOvMaps()
	w.ops = append(w.ops, ovOp{kind: ovReset})
	w.voided, w.touched = true, true
	return nil
}

// dropBlobs deletes the blobs of generation gen from the log: one range of sequential keys.
func (ov *ovTx) dropBlobs(gen uint64) error {
	var prefix [8]byte
	binary.BigEndian.PutUint64(prefix[:], gen)
	var keys [][]byte
	c := ov.log.Cursor()
	for k, _ := c.Seek(prefix[:]); k != nil && bytes.HasPrefix(k, prefix[:]); k, _ = c.Next() {
		keys = append(keys, bytes.Clone(k))
	}
	for _, k := range keys {
		if err := ov.log.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

// seal is the end of a transaction that wrote the overlay (ledgerTx.flush): its records go to the log as one blob
// (or to the base tables when there are very many), the frozen generation is folded a step, a full active one is
// frozen, and the meta of the log is written with the version of the commit.
func (ov *ovTx) seal() error {
	w := ov.wr
	if w == nil || !w.touched {
		return nil
	}
	n, size := 0, uint64(0)
	for slot := range w.pend {
		n += len(w.pend[slot])
		for k, v := range w.pend[slot] {
			size += uint64(len(k) + len(v))
		}
	}
	if n > ovBulkEntries {
		if err := ov.sealBulk(); err != nil {
			return err
		}
		return ov.writeMeta()
	}
	m := &w.meta
	if n > 0 {
		blob := encodeBlob(&w.pend)
		ovCounters.blobs.Add(1)
		ovCounters.blobBytes.Add(uint64(len(blob)))
		if err := putBlob(ov.log, m.active, m.blobN, blob); err != nil {
			return err
		}
		m.blobN++
		m.bytes += size
		w.ops = append(w.ops, ovOp{kind: ovAppend, ents: w.pend})
		for slot := range w.pend {
			for k, v := range w.pend[slot] {
				w.done[slot][k] = v
			}
		}
		w.pend = newOvMaps()
	}
	switch {
	case w.base.frozen != 0 && m.frozen == w.base.frozen:
		began := time.Now()
		err := ov.foldStep(n)
		ovNote(&ovStats.foldSteps, &ovStats.foldNS, &ovStats.maxFoldNS, began)
		if err != nil {
			return err
		}
	case w.base.frozen == 0 && m.frozen == 0 && m.bytes >= ovFreezeAt(m.lastFold):
		m.frozen, m.active = m.active, m.active+1
		m.folded, m.blobN, m.bytes, m.foldBytes = 0, 0, 0, 0
		w.ops = append(w.ops, ovOp{kind: ovFreeze})
		ovStats.freezes.Add(1)
	}
	return ov.writeMeta()
}

func (ov *ovTx) writeMeta() error {
	w := ov.wr
	w.meta.seq = w.base.seq + 1
	if err := ov.ctrl.Put(ovMetaKey, w.meta.encode()); err != nil {
		return err
	}
	if !w.registered {
		w.registered = true
		sh := ov.sh
		ov.tx.OnCommit(func() { sh.apply(w) })
	}
	return nil
}

// foldStep folds the next records of the frozen generation into the base tables: twice what the commit appended, at
// least ovFoldMin, and to the end of the block the last of them falls in.
func (ov *ovTx) foldStep(appended int) error {
	w := ov.wr
	var fz *ovGen
	ov.withGens(func(_, frozen *ovGen) { fz = frozen })
	if fz == nil {
		return model.Fail(model.Corrupt)
	}
	if !fz.ready.Load() {
		go fz.order() // a fold waits for the order of the frozen generation (once, by a sort of its records), it does not make the commit wait
		return nil
	}
	sorted := fz.order()
	total := 0
	for slot := range sorted {
		total += len(sorted[slot])
	}
	from := int(w.meta.folded)
	to := min(total, from+max(ovFoldMin, 2*appended))
	to = alignFold(sorted, to)
	off := 0
	for slot := range sorted {
		n := len(sorted[slot])
		if lo, hi := max(from-off, 0), min(to-off, n); lo < hi {
			written, err := ov.applyBase(slot, sorted[slot][lo:hi])
			if err != nil {
				return err
			}
			w.meta.foldBytes += written
		}
		off += n
	}
	w.meta.folded = uint64(to)
	if to < total {
		return nil
	}
	dropAt := time.Now()
	err := ov.dropBlobs(w.meta.frozen)
	ovNote(&ovStats.drops, &ovStats.dropNS, &ovStats.maxDropNS, dropAt)
	if err != nil {
		return err
	}
	w.meta.lastFold = w.meta.foldBytes
	w.meta.frozen, w.meta.folded, w.meta.foldBytes = 0, 0, 0
	w.ops = append(w.ops, ovOp{kind: ovDrop})
	return nil
}

// alignFold moves the end of a fold step (a position in the records of all slots in turn) to the end of the block its
// last record falls in, so that no block is written by two steps.
func alignFold(sorted *[ovSlots][]ovEnt, end int) int {
	off := 0
	for slot := range sorted {
		n := len(sorted[slot])
		if end <= off+n {
			if end > off && ovBlocked(slot) {
				i := end - off
				for i < n && sorted[slot][i].b == sorted[slot][i-1].b {
					i++
				}
				return off + i
			}
			return end
		}
		off += n
	}
	return end
}

// sealBulk writes the records of a transaction that wrote very many to the base tables, with everything the overlay
// holds before them, and leaves the overlay empty.
func (ov *ovTx) sealBulk() error {
	w := ov.wr
	var written uint64
	for slot := range w.pend {
		eff := map[string][]byte{}
		if !w.voided {
			ov.withGens(func(active, frozen *ovGen) {
				if frozen != nil {
					for k, v := range frozen.m[slot] {
						eff[k] = v
					}
				}
				for k, v := range active.m[slot] {
					eff[k] = v
				}
			})
		}
		for k, v := range w.done[slot] {
			eff[k] = v
		}
		for k, v := range w.pend[slot] {
			eff[k] = v
		}
		n, err := ov.foldMap(slot, eff)
		if err != nil {
			return err
		}
		written += n
	}
	m := &w.meta
	if err := ov.dropBlobs(m.active); err != nil {
		return err
	}
	if m.frozen != 0 {
		if err := ov.dropBlobs(m.frozen); err != nil {
			return err
		}
	}
	*m = ovMeta{seq: m.seq, active: max(m.active, m.frozen) + 1, lastFold: written}
	w.pend, w.done = newOvMaps(), newOvMaps()
	w.ops = append(w.ops, ovOp{kind: ovReset})
	w.voided = true
	return nil
}
