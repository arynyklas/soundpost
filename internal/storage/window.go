// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

// Windowed slot snapshots (01.07-W1).
//
// The command history of a slot is cut into windows of snapshotWindow consecutive commands. A
// locally cut snapshot no longer carries the history inside its envelope: the envelope holds a
// small window table (slotSnapshotV2) and the history travels as two files per window, the
// commands themselves (win-<n>.cmd) and an evidence sidecar (win-<n>.evd: the reservations the
// window's batches consumed and the cancellations it carries). Only a window that is full is
// sealed; a sealed window never changes except by redaction, so the node keeps one record per
// sealed window in replica_data (windowRecord: the SHA-256 of both files, the redaction-invariant
// identity of the commands, the charge digest and the window's share of the deletion ledger) and
// the next cut takes the unchanged window files from the previous snapshot instead of reading
// the history again. A cut therefore costs the windows written since the previous cut plus the
// open window, and the table; the sealed-window records are rewritten (dropped and recomputed at
// the next cut or check) by redaction, the only writer that changes a stored command.
//
// Peers never see a compact state: a snapshot sent to a peer is cut whole (slotMachine.Snapshot,
// slotSnapshot version 1), and Restore still installs that form.
const (
	windowMagic    = "SPWC0001"
	windowHeader   = 16
	maxWindowEntry = 1 << 30
)

// snapshotWindow is the number of commands per window.
var snapshotWindow uint64 = 4096

// SetSnapshotWindow changes the window size of every later cut of this process and returns the
// previous size. A snapshot names the size it was cut with, so snapshots of different sizes stay
// readable; the setting exists for tools and tests that need several windows over small histories.
func SetSnapshotWindow(n uint64) uint64 {
	old := snapshotWindow
	if n > 0 {
		snapshotWindow = n
	}
	return old
}

// SnapshotWindow reports the window size new cuts use.
func SnapshotWindow() uint64 { return snapshotWindow }

// settlePartSpan is the number of commands of a settlement part: control settles the consumed reservations
// of a window a part at a time while the window is still open (control/settle.go), so the rows that wait for
// the window to seal never exceed a part per group (and the parts nobody settled yet). The window size must
// be a multiple of it and larger; for a window that is not, there are no parts and a window settles whole.
var settlePartSpan uint64 = 64

// SetSettlePartSpan changes the part size of every later pass of this process (0 turns parts off) and
// returns the previous size; it exists for tools and tests that settle small histories.
func SetSettlePartSpan(n uint64) uint64 {
	old := settlePartSpan
	settlePartSpan = n
	return old
}

// partSpanOf is the part size for windows of span commands: 0 when there are no parts.
func partSpanOf(span uint64) uint64 {
	if p := settlePartSpan; p != 0 && p < span && span%p == 0 {
		return p
	}
	return 0
}

// partSpanIf is partSpanOf(span) when cond holds and 0 otherwise.
func partSpanIf(cond bool, span uint64) uint64 {
	if cond {
		return partSpanOf(span)
	}
	return 0
}

// windowPartSpan is the part size of the windows this engine derives and offers for settlement. Parts exist
// only in the runs layout, that is once the installation is contracted and no member runs a release that
// does not know them (it refuses a window record that carries them and control's records of settled parts).
func (e *Engine) windowPartSpan(span uint64) uint64 {
	return partSpanIf(e.runsLayout.Load(), span)
}

// windowPart is one part of a window as the node derived it: the batches it consumed (and how many of them
// physical erasure rewrote) and their charge digest, the one control settles the part by.
type windowPart struct {
	J        uint32     `json:"j"`
	Batches  uint64     `json:"batches,string"`
	Redacted uint64     `json:"redacted,string"`
	Charge   model.Hash `json:"charge"`
}

// windowParts cuts the consumed reservations of the window that starts at first into parts of part commands
// and returns the parts that carry batches. The reservations are in cursor order (windowBuilder, a sidecar).
func windowParts(consumed []ReservationEvidence, first, part uint64) []windowPart {
	var out []windowPart
	var run []ReservationEvidence
	var cur windowPart
	flush := func() {
		if len(run) != 0 {
			cur.Charge = chargeDigest(run)
			out = append(out, cur)
			run = nil
		}
	}
	for _, ev := range consumed {
		j := uint32((uint64(ev.Cursor.Index) - first) / part)
		if len(run) != 0 && j != cur.J {
			flush()
		}
		if len(run) == 0 {
			cur = windowPart{J: j}
		}
		run = append(run, ev)
		cur.Batches++
		if ev.Redacted {
			cur.Redacted++
		}
	}
	flush()
	return out
}

type windowFile struct {
	Size   uint64     `json:"size,string"`
	SHA256 model.Hash `json:"sha256"`
}

// windowRef is one window as the compact snapshot state names it.
type windowRef struct {
	N        uint64     `json:"n,string"`
	First    uint64     `json:"first,string"`
	Count    uint64     `json:"count,string"`
	File     windowFile `json:"file"`
	Ev       windowFile `json:"ev"`
	Identity model.Hash `json:"identity"`
	Batches  uint64     `json:"batches,string"`
	Redacted uint64     `json:"redacted,string"`
	Cancels  uint64     `json:"cancels,string"`
	Charge   model.Hash `json:"charge"`
}

// windowRecord is the persisted form of a sealed window and the in-memory form of every window.
type windowRecord struct {
	windowRef
	Ledger   []replica.LedgerEntry `json:"ledger"`
	Barriers uint64                `json:"barriers,string"`
	// Parts are the parts of the window that carry batches, derived with the record when the window is cut
	// into parts (partSpanOf); a record an earlier release persisted has none.
	Parts []windowPart `json:"parts,omitempty"`
}

// slotSnapshotV2 is the compact machine state of a locally cut slot snapshot.
type slotSnapshotV2 struct {
	Version     uint16       `json:"version"`
	Identity    model.ID     `json:"identity"`
	Slot        uint16       `json:"slot"`
	Application model.Uint64 `json:"application"`
	Span        model.Uint64 `json:"span"`
	Windows     []windowRef  `json:"windows"`
}

// windowSidecar is the evidence file of a window.
type windowSidecar struct {
	Version   uint16                 `json:"version"`
	Window    uint64                 `json:"window,string"`
	Consumed  []ReservationEvidence  `json:"consumed"`
	Cancelled []CancellationEvidence `json:"cancelled"`
}

func winName(n uint64) string { return fmt.Sprintf("win-%08d.cmd", n) }
func evName(n uint64) string  { return fmt.Sprintf("win-%08d.evd", n) }

func wrecKey(slot uint16, n uint64) []byte {
	return metaKey(slot, "wrec:"+strconv.FormatUint(n, 10))
}

// errWindowMoved reports that a window changed between the table a cut named and the moment its
// files were written (a redaction in between). The cut is repeated.
var errWindowMoved = errors.New("storage: snapshot window changed during the cut")

// stateVersion reads the version of a machine state without decoding the history it may carry.
func stateVersion(raw []byte) uint16 {
	var peek struct {
		Version uint16 `json:"version"`
	}
	if json.Unmarshal(raw, &peek) != nil {
		return 0
	}
	return peek.Version
}

// commandIdentity is the class of a stored command that redaction leaves alone: the digest of
// its exact bytes, or for a redacted command the digest of the bytes it replaced (sameCommand).
func commandIdentity(raw []byte) model.Hash {
	if r := redactionOf(raw); r != nil {
		return r.Original
	}
	return model.HashCanonical(raw)
}

// chargeDigest is the digest of what a set of consumed reservations charges, in cursor order. A
// window's digest and the same digest derived from the control cut's consumed reservations agree
// exactly when control already holds every one of them with the same charge (model.ChargeDigest:
// control computes it too, when it settles a window).
func chargeDigest(ev []ReservationEvidence) model.Hash {
	items := make([]model.ChargeItem, len(ev))
	for i, e := range ev {
		items[i] = model.ChargeItem{ID: e.ID, Org: e.Org, Project: e.Project, Source: e.Source, Hash: e.Hash, Bytes: e.Bytes, Series: e.Series, Cursor: e.Cursor}
	}
	return model.ChargeDigest(items)
}

// batchEvidence derives the consumption evidence of one stored batch command.
func batchEvidence(entry walEntry) (ReservationEvidence, error) {
	if entry.Batch == nil || entry.Receipt == nil {
		return ReservationEvidence{}, model.Fail(model.Corrupt)
	}
	r := entry.Batch.Reservation
	ev := ReservationEvidence{ID: r.ID, Org: r.Org, Project: r.Project, Source: r.Source, Hash: r.Hash, Bytes: r.Bytes, Series: append([]string(nil), r.Series...), Cursor: entry.Receipt.Cursor}
	if entry.Type == "batch_redacted" {
		set := map[string]bool{}
		for _, rec := range entry.Batch.Records {
			if rec.Kind != model.Metric {
				continue
			}
			id, err := model.CanonicalSeriesID(r.Project, rec)
			if err != nil {
				return ReservationEvidence{}, model.Fail(model.Corrupt)
			}
			set[id] = true
		}
		ev.Redacted = true
		for id := range set {
			ev.Retained = append(ev.Retained, id)
		}
		sort.Strings(ev.Retained)
	}
	return ev, nil
}

// windowBuilder accumulates one window from consecutive commands.
type windowBuilder struct {
	rec       windowRecord
	file      hash.Hash
	size      uint64
	ident     hash.Hash
	sink      io.Writer
	consumed  []ReservationEvidence
	cancelled []CancellationEvidence
	next      uint64
	part      uint64 // the window is cut into parts of this many commands (0: not cut), see windowParts
}

func newWindowBuilder(n, first uint64, sink io.Writer) (*windowBuilder, error) {
	b := &windowBuilder{sink: sink, next: first}
	b.file, b.ident = sha256.New(), sha256.New()
	b.rec.N, b.rec.First = n, first
	var head [windowHeader]byte
	copy(head[:8], windowMagic)
	binary.BigEndian.PutUint64(head[8:], first)
	return b, b.write(head[:])
}

func (b *windowBuilder) write(p []byte) error {
	b.size += uint64(len(p))
	b.file.Write(p)
	if b.sink != nil {
		_, err := b.sink.Write(p)
		return err
	}
	return nil
}

// windowCommandsDerived counts the commands read into a window record (a cut, a check or a
// restore re-derives a window from them): the measure of how much history a cut reads.
var windowCommandsDerived atomic.Uint64

// windowBytesStaged counts the bytes cuts wrote into their staging directory (window files and evidence files): with the bytes the
// snapshot store then copied from it (replica.SnapshotBytesCopied) the measure of what a cut writes for its windows.
var windowBytesStaged atomic.Uint64

// add appends the command stored at the next index.
func (b *windowBuilder) add(raw []byte) error {
	windowCommandsDerived.Add(1)
	index := b.next
	b.next++
	var size [4]byte
	if uint64(len(raw)) > maxWindowEntry {
		return model.Fail(model.Corrupt)
	}
	binary.BigEndian.PutUint32(size[:], uint32(len(raw)))
	if err := b.write(size[:]); err != nil {
		return err
	}
	if err := b.write(raw); err != nil {
		return err
	}
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], index)
	id := commandIdentity(raw)
	b.ident.Write(n[:])
	b.ident.Write(id[:])
	var entry walEntry
	if json.Unmarshal(raw, &entry) != nil {
		return model.Fail(model.Corrupt)
	}
	switch entry.Type {
	case "batch", "batch_redacted":
		ev, err := batchEvidence(entry)
		if err != nil {
			return err
		}
		if uint64(ev.Cursor.Index) != index {
			return model.Fail(model.Corrupt)
		}
		b.consumed = append(b.consumed, ev)
		b.rec.Batches++
		if ev.Redacted {
			b.rec.Redacted++
		}
	case "cancel":
		if entry.Cancel == nil {
			return model.Fail(model.Corrupt)
		}
		b.cancelled = append(b.cancelled, CancellationEvidence{ID: entry.Cancel.ReservationID, Hash: entry.Cancel.Hash, Fence: entry.Cancel.Fence})
		b.rec.Cancels++
	}
	switch entry.Type {
	case "fence", "cancel", "artifact_gc", "delete_barrier":
		if entry.Type == "delete_barrier" {
			b.rec.Barriers++
		}
		b.rec.Ledger = append(b.rec.Ledger, replica.LedgerEntry{Index: index, Kind: entry.Type, Hash: model.HashCanonical(raw)})
	}
	return nil
}

// finish seals the record and returns the evidence sidecar bytes.
func (b *windowBuilder) finish() (windowRecord, []byte, error) {
	b.rec.Count = b.next - b.rec.First
	b.rec.File = windowFile{Size: b.size}
	copy(b.rec.File.SHA256[:], b.file.Sum(nil))
	copy(b.rec.Identity[:], b.ident.Sum(nil))
	b.rec.Charge = chargeDigest(b.consumed)
	if b.part != 0 {
		b.rec.Parts = windowParts(b.consumed, b.rec.First, b.part)
	}
	if b.consumed == nil {
		b.consumed = []ReservationEvidence{}
	}
	if b.cancelled == nil {
		b.cancelled = []CancellationEvidence{}
	}
	if b.rec.Ledger == nil {
		b.rec.Ledger = []replica.LedgerEntry{}
	}
	raw, err := json.Marshal(windowSidecar{Version: 1, Window: b.rec.N, Consumed: b.consumed, Cancelled: b.cancelled})
	if err != nil {
		return windowRecord{}, nil, err
	}
	b.rec.Ev = windowFile{Size: uint64(len(raw)), SHA256: model.HashCanonical(raw)}
	return b.rec, raw, nil
}

// computeWindow derives a window from the stored commands of a bucket of the caller's transaction (treeCommands); computeWindowFrom
// is the derivation over any source of the commands.
func computeWindow(commands *bolt.Bucket, slot uint16, n, first, count, part uint64, sink io.Writer, poll *cancelPoll) (windowRecord, []byte, error) {
	return computeWindowFrom(treeCommands(commands, slot), n, first, count, part, sink, poll)
}

// computeWindowFrom derives a window from the stored commands, cut into parts of part commands when part is not
// zero. With a sink it also streams the window's command file. A poll that reports cancellation stops it between two commands.
func computeWindowFrom(src commandSource, n, first, count, part uint64, sink io.Writer, poll *cancelPoll) (windowRecord, []byte, error) {
	b, err := newWindowBuilder(n, first, sink)
	if err != nil {
		return windowRecord{}, nil, err
	}
	b.part = part
	if err = src(first, count, func(_ uint64, raw []byte) error {
		if err := poll.tick(); err != nil {
			return err
		}
		return b.add(raw)
	}); err != nil {
		return windowRecord{}, nil, err
	}
	return b.finish()
}

// windowCheckpoint is a state a derivation of the open window passed through: the commands the window file holds then and the size and
// SHA-256 of that file, which a snapshot cut may have published.
type windowCheckpoint struct {
	count uint64
	file  windowFile
}

// windowCheckpoints is how many checkpoints of a slot's window are kept: the files of the last cuts.
const windowCheckpoints = 8

// windowCache is the derivation of the window a slot is filling (the last window of its history), kept between cuts. A cut used to derive
// the whole open window again, twice (the record, then the files), a quarter of a millisecond of CPU and one random read of the payload log
// for each of up to 4,096 commands of 10 KB, for each of the 64 groups every 16 MiB of journal: at the single-host gate that was the
// largest reader of the payload log, up to 8 GB of it for every 17 minutes of load, and with the page cache of the scope full those reads
// came from the disk (L2w20Admission34). The builder is extended by the commands applied since the last derivation, so the commands a
// cut reads are the ones added since the cut before, whatever the position in the window and the length of the history.
// The cache is valid while no command has been rewritten: erasure, the only writer of a stored command, takes cutMu exclusively and
// bumps Engine.cutEpoch first; an entry built under another epoch is rebuilt from the commands.
type windowCache struct {
	mu    sync.Mutex
	epoch uint64
	b     *windowBuilder
	part  uint64
	rec   windowRecord       // the record at the last finish
	side  []byte             // the evidence file at the last finish
	cps   []windowCheckpoint // oldest first
	// sealed is the last window of the slot the cache derived to its end: the window that sealed, kept until the next one does, so that the
	// cut or the settlement pass that finds it sealed takes its record from the cache, and the cut writes its file from the previous
	// snapshot's file and the commands added since, as for any cut of an open window.
	sealed sealedWindow
}

// sealedWindow is the state of a window the cache derived to its end.
type sealedWindow struct {
	ok    bool
	epoch uint64
	part  uint64
	rec   windowRecord
	side  []byte
	cps   []windowCheckpoint
}

// matches reports whether this is the derivation of exactly the window of the record under the epoch.
func (s *sealedWindow) matches(epoch uint64, want windowRecord) bool {
	return s.ok && s.epoch == epoch && s.rec.fits(want.N, want.First, want.Count) && s.rec.File == want.File && s.rec.Ev == want.Ev
}

// deriveWindow is computeWindowFrom without a sink for the window n of slot (count commands from first). The window the slot is filling
// (open: it holds the commands up to the slot's last) is the slot's cache, extended by the commands added since the cut before; a window
// that has sealed (sealed: it is full) is taken from the cache when the cache holds it, finished by the commands it still lacked, and
// derived from the commands only when it does not (a restart, an erasure). The derivation passes the cut gate, which bounds how many
// of them the 64 slots of an engine run at once. The caller holds cutMu shared and no read transaction: the commands are read through
// fetchedCommands.
func (e *Engine) deriveWindow(slot uint16, n, first, count, part uint64, open, sealed bool) (windowRecord, error) {
	src := e.fetchedCommands(slot)
	defer e.cutGate.enter()()
	c := &e.windows[slot]
	epoch, end := e.cutEpoch.Load(), first+count
	c.mu.Lock()
	if c.sealed.ok && c.sealed.epoch == epoch && c.sealed.part == part && c.sealed.rec.fits(n, first, count) {
		rec := c.sealed.rec
		c.mu.Unlock()
		return rec, nil
	}
	holds := c.b != nil && c.epoch == epoch && c.part == part && c.b.rec.N == n && c.b.rec.First == first && c.b.next <= end
	if !open && !holds {
		c.mu.Unlock()
		rec, _, err := computeWindowFrom(src, n, first, count, part, nil, nil)
		return rec, err
	}
	defer c.mu.Unlock()
	if !holds {
		b, err := newWindowBuilder(n, first, nil)
		if err != nil {
			return windowRecord{}, err
		}
		b.part = part
		c.b, c.epoch, c.part, c.rec, c.side, c.cps = b, epoch, part, windowRecord{}, nil, nil
	}
	if c.b.next == end && c.rec.N == n && c.rec.First == first && c.rec.Count == count && c.side != nil {
		return c.rec, nil // the record of this very state
	}
	if err := src(c.b.next, end-c.b.next, func(_ uint64, raw []byte) error { return c.b.add(raw) }); err != nil {
		c.b = nil
		return windowRecord{}, err
	}
	rec, side, err := c.b.finish()
	if err != nil {
		c.b = nil
		return windowRecord{}, err
	}
	c.rec, c.side = rec, side
	c.cps = append(c.cps, windowCheckpoint{count: count, file: rec.File})
	if len(c.cps) > windowCheckpoints {
		c.cps = append(c.cps[:0], c.cps[len(c.cps)-windowCheckpoints:]...)
	}
	if sealed {
		c.sealed = sealedWindow{ok: true, epoch: epoch, part: part, rec: rec, side: side, cps: c.cps}
		c.b, c.rec, c.side, c.cps = nil, windowRecord{}, nil, nil
	}
	return rec, nil
}

// dropWindowCaches forgets what the slots derived: the stored commands are about to change under them.
func (e *Engine) dropWindowCaches() { e.cutEpoch.Add(1) }

// windowIdentity is windowRecord.Identity of the window of count commands from first, and nothing else of its
// derivation: the digest of the index and the redaction-invariant identity of each command (commandIdentity), which
// takes the hash of the stored bytes, not a decode of the command. A check that compares identities (verifyCompact)
// used to derive the whole record, decoding every command of the open window (a quarter of a millisecond each at
// 10 KB): 38 CPU-s of a restart's 50 s after the single-host load (L2w20Admission21).
func windowIdentity(commands *bolt.Bucket, slot uint16, first, count uint64) (model.Hash, error) {
	h := sha256.New()
	for i := uint64(0); i < count; i++ {
		raw := commandAt(commands, commandKey(slot, first+i))
		if raw == nil {
			return model.Hash{}, model.Fail(model.Corrupt)
		}
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], first+i)
		id := commandIdentity(raw)
		h.Write(n[:])
		h.Write(id[:])
	}
	var out model.Hash
	copy(out[:], h.Sum(nil))
	return out, nil
}

func (r windowRecord) fits(n, first, count uint64) bool {
	return r.N == n && r.First == first && r.Count == count
}

// windowTableOf derives the windows of the first app commands of slot (from window number from on; with
// sealedOnly the open window is left out, which costs a decode of every command in it each time: the settlement
// pass must not pay it). Sealed windows come from their persisted record; a missing or mismatching one is
// derived from the commands (and persisted when persist is set); the open window is always derived. It reads the
// stored commands through fetchedCommands (short read transactions, the payload log outside them) and takes no engine lock: the caller holds cutMu shared (the commands
// below app change only by erasure, which takes it exclusively) and no engine lock, and passes the index of
// the slot it read under mu (windowTableAt, SettleCandidatesFor).
func (e *Engine) windowTableOf(slot uint16, app uint64, persist, sealedOnly bool, from uint64) ([]windowRecord, error) {
	span := snapshotWindow
	// The persisted records are read in one short transaction; the windows that have none are derived after it, the payload log read
	// outside any transaction (fetchedCommands).
	stored := map[uint64]windowRecord{}
	err := e.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		if meta == nil {
			return model.Fail(model.Corrupt)
		}
		for first := from*span + 1; first <= app; first += span {
			n := (first - 1) / span
			count := min(span, app-first+1)
			if count != span {
				continue
			}
			if raw := meta.Get(wrecKey(slot, n)); raw != nil {
				var rec windowRecord
				if json.Unmarshal(raw, &rec) == nil && rec.fits(n, first, count) {
					stored[n] = rec
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var out, fresh []windowRecord
	for first := from*span + 1; first <= app; first += span {
		n := (first - 1) / span
		count := min(span, app-first+1)
		sealed := count == span
		if !sealed && sealedOnly {
			continue
		}
		if rec, ok := stored[n]; ok {
			out = append(out, rec)
			continue
		}
		rec, err := e.deriveWindow(slot, n, first, count, e.windowPartSpan(span), first+span > app, sealed)
		if err != nil {
			return nil, err
		}
		if sealed {
			fresh = append(fresh, rec)
		}
		out = append(out, rec)
	}
	if persist && len(fresh) > 0 {
		err = e.db.Update(func(tx *bolt.Tx) error {
			meta := tx.Bucket([]byte("replica_data"))
			for _, rec := range fresh {
				raw, err := json.Marshal(rec)
				if err != nil {
					return err
				}
				if err = meta.Put(wrecKey(slot, rec.N), raw); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// windowTableAt is the window table of the first application commands of slot, for a snapshot cut pinned at that index
// (pinnedSlotCut), and holds e.mu only for a moment: deriving the open window decodes every command in it (a second of CPU at the
// single-host load, 2,048 commands of 10 KB), and e.mu is the lock every append of every slot passes, so a cut that derived
// it under e.mu stopped the whole engine, and the 64 cuts that fell together stopped it for a minute (L2w20Admission19). The
// slot's group may go on applying while the table is derived (the cut holds neither its locks nor e.mu): the commands the
// table names are those at or below application, which a command applied later does not change, and the one writer that
// rewrites stored commands, erasure, takes cutMu exclusively; the derivation holds it shared. The caller holds no engine lock.
func (e *Engine) windowTableAt(slot uint16, application uint64) ([]windowRecord, error) {
	e.cutMu.RLock()
	defer e.cutMu.RUnlock()
	e.mu.Lock()
	unusable := e.failed || e.closed
	e.mu.Unlock()
	if unusable {
		return nil, model.Fail(model.Unavailable)
	}
	return e.windowTableOf(slot, application, true, false, 0)
}

// dropWindowTx forgets the sealed-window record of the window holding the command at index: the
// command is about to be rewritten (redaction), so the record no longer describes it.
func dropWindowTx(tx *bolt.Tx, slot uint16, index uint64) error {
	if index == 0 {
		return nil
	}
	return tx.Bucket([]byte("replica_data")).Delete(wrecKey(slot, (index-1)/snapshotWindow))
}

// validateWindowRecordsTx re-derives every persisted window record from the commands (the
// background full verification): a record the commands no longer match is corruption. A poll that reports cancellation stops it.
func validateWindowRecordsTx(tx *bolt.Tx, poll *cancelPoll) error {
	meta, commands := tx.Bucket([]byte("replica_data")), tx.Bucket([]byte("replica_commands"))
	if meta == nil || commands == nil {
		return nil
	}
	for slot := range uint16(64) {
		prefix := metaKey(slot, "wrec:")
		cursor := meta.Cursor()
		for k, v := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = cursor.Next() {
			var rec windowRecord
			if json.Unmarshal(v, &rec) != nil || rec.Count == 0 || rec.First == 0 {
				return model.Fail(model.Corrupt)
			}
			if string(k) != string(wrecKey(slot, rec.N)) || rec.First != rec.N*rec.Count+1 {
				return model.Fail(model.Corrupt)
			}
			again, _, err := computeWindow(commands, slot, rec.N, rec.First, rec.Count, partSpanIf(len(rec.Parts) != 0, rec.Count), nil, poll)
			if err != nil {
				return err
			}
			if len(rec.Parts) == 0 {
				again.Parts = nil // a record an earlier release persisted has no parts; they are derived state
			}
			want, _ := json.Marshal(rec)
			got, _ := json.Marshal(again)
			if !bytes.Equal(want, got) {
				return model.Fail(model.Corrupt)
			}
		}
	}
	return nil
}

func refsOf(table []windowRecord) []windowRef {
	out := make([]windowRef, len(table))
	for i, r := range table {
		out[i] = r.windowRef
	}
	return out
}

// checkWindowTable validates the structure of a compact state against its own totals.
func (s slotSnapshotV2) checkWindows() error {
	span, total := uint64(s.Span), uint64(0)
	if s.Version != 2 || span == 0 {
		return model.Fail(model.Corrupt)
	}
	for i, w := range s.Windows {
		last := i == len(s.Windows)-1
		if w.N != uint64(i) || w.First != total+1 || w.Count == 0 || w.Count > span || !last && w.Count != span {
			return model.Fail(model.Corrupt)
		}
		total += w.Count
	}
	if total != uint64(s.Application) {
		return model.Fail(model.Corrupt)
	}
	return nil
}

// compactState decodes the machine state of a snapshot when it is a compact one; ok is false for
// the whole-history form (version 1).
func compactState(snapshot replica.Snapshot) (slotSnapshotV2, bool, error) {
	state, err := snapshot.MachineState()
	if err != nil {
		return slotSnapshotV2{}, false, model.Fail(model.Corrupt)
	}
	if stateVersion(state) != 2 {
		return slotSnapshotV2{}, false, nil
	}
	var st slotSnapshotV2
	if model.StrictJSON(state, &st) != nil || st.checkWindows() != nil || uint64(st.Application) != uint64(snapshot.Manifest.Cursor.Index) {
		return slotSnapshotV2{}, true, model.Fail(model.Corrupt)
	}
	// The files the table names must be the files the manifest hashed.
	byName := map[string]replica.SnapshotFile{}
	for _, f := range snapshot.Manifest.Files {
		byName[f.Name] = f
	}
	for _, w := range st.Windows {
		for _, f := range []struct {
			name string
			file windowFile
		}{{"files/" + winName(w.N), w.File}, {"files/" + evName(w.N), w.Ev}} {
			have, ok := byName[f.name]
			if !ok || have.Size != f.file.Size || have.SHA256 != f.file.SHA256 {
				return slotSnapshotV2{}, true, model.Fail(model.Corrupt)
			}
		}
	}
	return st, true, nil
}

// readWindowFile streams the commands of one window of a snapshot to visit, verifying the file's
// header, count, size and SHA-256 as it goes. Memory is one command.
func readWindowFile(snapshot replica.Snapshot, ref windowRef, visit func(index uint64, raw []byte) error) error {
	in, err := snapshot.File("files/" + winName(ref.N))
	if err != nil {
		return model.Fail(model.Corrupt)
	}
	defer in.Close()
	h := sha256.New()
	r := bufio.NewReaderSize(io.TeeReader(in, h), 256<<10)
	var head [windowHeader]byte
	if _, err = io.ReadFull(r, head[:]); err != nil || string(head[:8]) != windowMagic || binary.BigEndian.Uint64(head[8:]) != ref.First {
		return model.Fail(model.Corrupt)
	}
	size := uint64(windowHeader)
	for i := uint64(0); i < ref.Count; i++ {
		var l [4]byte
		if _, err = io.ReadFull(r, l[:]); err != nil {
			return model.Fail(model.Corrupt)
		}
		n := binary.BigEndian.Uint32(l[:])
		if n > maxWindowEntry {
			return model.Fail(model.Corrupt)
		}
		raw := make([]byte, n)
		if _, err = io.ReadFull(r, raw); err != nil {
			return model.Fail(model.Corrupt)
		}
		size += 4 + uint64(n)
		if err = visit(ref.First+i, raw); err != nil {
			return err
		}
	}
	if _, err = r.ReadByte(); err != io.EOF || size != ref.File.Size || model.Hash(h.Sum(nil)) != ref.File.SHA256 {
		return model.Fail(model.Corrupt)
	}
	return nil
}

// readSidecar returns the evidence file of a window, verified against the hash the table names.
func readSidecar(snapshot replica.Snapshot, ref windowRef) (windowSidecar, error) {
	in, err := snapshot.File("files/" + evName(ref.N))
	if err != nil {
		return windowSidecar{}, model.Fail(model.Corrupt)
	}
	defer in.Close()
	raw, err := io.ReadAll(io.LimitReader(in, int64(ref.Ev.Size)+1))
	if err != nil || uint64(len(raw)) != ref.Ev.Size || model.HashCanonical(raw) != ref.Ev.SHA256 {
		return windowSidecar{}, model.Fail(model.Corrupt)
	}
	var sc windowSidecar
	if model.StrictJSON(raw, &sc) != nil || sc.Version != 1 || sc.Window != ref.N {
		return windowSidecar{}, model.Fail(model.Corrupt)
	}
	return sc, nil
}

// windowSyncChunk is how many bytes of a window file a cut writes before it syncs them: one fsync of the 50 MB a window file grows to queued
// the raft journals of every group, which fsync the same disk, behind a burst of that many dirty pages (fsync probe 1 ms idle, 20-163 ms
// during the cuts: latgrow-report). The file is the same bytes; what is written when changes.
var windowSyncChunk = 4 << 20

// chunkSyncWriter writes to f and syncs it after every windowSyncChunk bytes; before, when set, runs ahead of each of those syncs.
type chunkSyncWriter struct {
	f       *os.File
	pending int
	before  func() error
}

func (w *chunkSyncWriter) Write(p []byte) (int, error) {
	n, err := w.f.Write(p)
	w.pending += n
	if err == nil && w.pending >= windowSyncChunk {
		w.pending = 0
		if w.before != nil {
			if err = w.before(); err != nil {
				return n, err
			}
		}
		err = w.f.Sync()
	}
	return n, err
}

// writeWindowFiles materialises one window's two files into dir and verifies them against the
// record the compact state was written from.
func (e *Engine) writeWindowFiles(src commandSource, want windowRecord, dir string) error {
	f, err := os.OpenFile(filepath.Join(dir, winName(want.N)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	cw := &chunkSyncWriter{f: f, before: func() error { return e.trip("window_stage_sync") }}
	bw := bufio.NewWriterSize(cw, 256<<10)
	got, side, err := computeWindowFrom(src, want.N, want.First, want.Count, 0, bw, nil)
	if err == nil {
		err = bw.Flush()
	}
	if err == nil {
		err = f.Sync()
	}
	if ce := f.Close(); err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	if got.File != want.File || got.Ev != want.Ev || got.Identity != want.Identity {
		return errWindowMoved
	}
	ev, err := os.OpenFile(filepath.Join(dir, evName(want.N)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = ev.Write(side)
	if err == nil {
		err = ev.Sync()
	}
	if ce := ev.Close(); err == nil {
		err = ce
	}
	if err == nil {
		windowBytesStaged.Add(want.File.Size + uint64(len(side)))
	}
	return err
}

// writeWindowFilesFromPrior is writeWindowFiles for a window whose record the slot's cache derived (deriveWindow), when the snapshot the cut
// supersedes holds the window's file as of an earlier cut of the same derivation (prior): that file is copied and hashed, and the commands
// added since are the only ones read from the store; the evidence file is the one the derivation wrote. The result is checked against the
// record as writeWindowFiles checks it. ok is false when this was not possible (no cache of this very state, no prior file, a prior file that is not
// the one the cache passed through, a result that is not the record): nothing is left in dir and the caller derives the window whole.
func (e *Engine) writeWindowFilesFromPrior(src commandSource, slot uint16, want windowRecord, dir string, prior func(uint64) (*os.File, windowFile, bool)) (ok bool, err error) {
	if prior == nil {
		return false, nil
	}
	c := &e.windows[slot]
	c.mu.Lock()
	epoch := e.cutEpoch.Load()
	var side []byte
	var cps []windowCheckpoint
	valid := false
	switch {
	case c.sealed.matches(epoch, want):
		valid, side, cps = true, c.sealed.side, append(cps, c.sealed.cps...)
	case c.b != nil && c.epoch == epoch && c.rec.fits(want.N, want.First, want.Count) && c.rec.File == want.File && c.rec.Ev == want.Ev:
		valid, side, cps = true, c.side, append(cps, c.cps...)
	}
	c.mu.Unlock()
	if !valid {
		return false, nil
	}
	in, have, found := prior(want.N)
	if !found {
		return false, nil
	}
	defer in.Close()
	var from *windowCheckpoint
	for i := range cps {
		if cps[i].file == have && cps[i].count < want.Count {
			from = &cps[i]
		}
	}
	if from == nil {
		return false, nil
	}
	cmdPath, evPath := filepath.Join(dir, winName(want.N)), filepath.Join(dir, evName(want.N))
	fail := func(err error) (bool, error) {
		_ = os.Remove(cmdPath)
		_ = os.Remove(evPath)
		return false, err
	}
	f, err := os.OpenFile(cmdPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return false, err
	}
	cw := &chunkSyncWriter{f: f, before: func() error { return e.trip("window_stage_sync") }}
	bw := bufio.NewWriterSize(cw, 256<<10)
	h := sha256.New()
	if n, err := io.CopyN(io.MultiWriter(bw, h), in, int64(have.Size)); err != nil || uint64(n) != have.Size || model.Hash(h.Sum(nil)) != have.SHA256 {
		f.Close()
		return fail(nil)
	}
	size := have.Size
	var length [4]byte
	err = src(want.First+from.count, want.Count-from.count, func(_ uint64, raw []byte) error {
		windowCommandsDerived.Add(1)
		binary.BigEndian.PutUint32(length[:], uint32(len(raw)))
		h.Write(length[:])
		h.Write(raw)
		size += 4 + uint64(len(raw))
		if _, err := bw.Write(length[:]); err != nil {
			return err
		}
		_, err := bw.Write(raw)
		return err
	})
	if err == nil {
		err = bw.Flush()
	}
	if err == nil {
		err = f.Sync()
	}
	if ce := f.Close(); err == nil {
		err = ce
	}
	if err != nil {
		return fail(err)
	}
	if size != want.File.Size || model.Hash(h.Sum(nil)) != want.File.SHA256 {
		return fail(nil)
	}
	ev, err := os.OpenFile(evPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fail(err)
	}
	_, err = ev.Write(side)
	if err == nil {
		err = ev.Sync()
	}
	if ce := ev.Close(); err == nil {
		err = ce
	}
	if err != nil {
		return fail(err)
	}
	windowBytesStaged.Add(size + uint64(len(side)))
	return true, nil
}
