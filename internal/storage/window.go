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

// cutTable remembers the window table of the last compact cut so PinFiles and the ledger of the
// same CreateSnapshot see the table the state was written from.
type cutTable struct {
	application uint64
	windows     []windowRecord
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

// computeWindow derives a window from the stored commands. With a sink it also streams the
// window's command file.
func computeWindow(commands *bolt.Bucket, slot uint16, n, first, count uint64, sink io.Writer) (windowRecord, []byte, error) {
	b, err := newWindowBuilder(n, first, sink)
	if err != nil {
		return windowRecord{}, nil, err
	}
	for i := uint64(0); i < count; i++ {
		raw := commands.Get(commandKey(slot, first+i))
		if raw == nil {
			return windowRecord{}, nil, model.Fail(model.Corrupt)
		}
		if err = b.add(raw); err != nil {
			return windowRecord{}, nil, err
		}
	}
	return b.finish()
}

func (r windowRecord) fits(n, first, count uint64) bool {
	return r.N == n && r.First == first && r.Count == count
}

// windowTableLocked returns the windows of a slot's applied history. Sealed windows come from
// their persisted record; a missing or mismatching one is derived from the commands (and
// persisted when persist is set). The open window is always derived. e.mu is held.
func (e *Engine) windowTableLocked(slot uint16, persist bool) ([]windowRecord, error) {
	app, span := e.indexes[slot], snapshotWindow
	var out, fresh []windowRecord
	err := e.db.View(func(tx *bolt.Tx) error {
		meta, commands := tx.Bucket([]byte("replica_data")), tx.Bucket([]byte("replica_commands"))
		if meta == nil || commands == nil {
			return model.Fail(model.Corrupt)
		}
		for first := uint64(1); first <= app; first += span {
			n := (first - 1) / span
			count := min(span, app-first+1)
			sealed := count == span
			if sealed {
				if raw := meta.Get(wrecKey(slot, n)); raw != nil {
					var rec windowRecord
					if json.Unmarshal(raw, &rec) == nil && rec.fits(n, first, count) {
						out = append(out, rec)
						continue
					}
				}
			}
			rec, _, err := computeWindow(commands, slot, n, first, count, nil)
			if err != nil {
				return err
			}
			if sealed {
				fresh = append(fresh, rec)
			}
			out = append(out, rec)
		}
		return nil
	})
	if err != nil {
		return nil, err
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

// dropWindowTx forgets the sealed-window record of the window holding the command at index: the
// command is about to be rewritten (redaction), so the record no longer describes it.
func dropWindowTx(tx *bolt.Tx, slot uint16, index uint64) error {
	if index == 0 {
		return nil
	}
	return tx.Bucket([]byte("replica_data")).Delete(wrecKey(slot, (index-1)/snapshotWindow))
}

// validateWindowRecordsTx re-derives every persisted window record from the commands (the
// background full verification): a record the commands no longer match is corruption.
func validateWindowRecordsTx(tx *bolt.Tx) error {
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
			again, _, err := computeWindow(commands, slot, rec.N, rec.First, rec.Count, nil)
			if err != nil {
				return err
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

// writeWindowFiles materialises one window's two files into dir and verifies them against the
// record the compact state was written from.
func writeWindowFiles(commands *bolt.Bucket, slot uint16, want windowRecord, dir string) error {
	f, err := os.OpenFile(filepath.Join(dir, winName(want.N)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(f, 256<<10)
	got, side, err := computeWindow(commands, slot, want.N, want.First, want.Count, bw)
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
	return err
}
