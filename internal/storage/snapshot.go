// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/arynyklas/soundpost/internal/durablefs"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

// snapshotState is the engine's snapshot bookkeeping. Its zero value is usable.
type snapshotState struct {
	pinned   map[string]int
	retired  map[string]bool
	coverage []model.Cursor
	hold     atomic.Bool // restored intake stays closed until quota reconciliation is persisted
}

const (
	restorePendingFile = "restore-quota.pending"
	quotaCertFile      = "quota-reconciliation.json"
)

// ---- Machine side: ledger and pinned transfer set ---------------------------

// DeletionLedger lists every retained tombstone-class command of the slot: source
// fences, cancellation fences and artifact deletions, each with the digest of its
// committed bytes. The generation is the storage manifest's tombstone generation, plus
// one per delete barrier in the history. Each sealed window carries its own share of the
// ledger in its record, so the ledger is assembled from the window records and the open
// window instead of reading the whole history.
func (m *slotMachine) DeletionLedger() (replica.Ledger, error) {
	e := m.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed || e.closed {
		return replica.Ledger{}, model.Fail(model.Unavailable)
	}
	ledger := replica.Ledger{Version: 1, Group: e.group(m.slot), Generation: e.catalog.Manifest.TombstoneGeneration, Entries: []replica.LedgerEntry{}}
	table, err := e.windowTableLocked(m.slot, true)
	if err != nil {
		return replica.Ledger{}, err
	}
	for _, rec := range table {
		ledger.Generation += rec.Barriers
		ledger.Entries = append(ledger.Entries, rec.Ledger...)
	}
	return ledger, nil
}

// PinFiles pins the files of a cut (replica.FileMachine). Every slot supplies the window files of
// the table CompactSnapshot just wrote: a window whose files the selected snapshot already
// holds is named, not read (replica.PinnedFile.Reuse); any other is written, verified against the
// table, into a staging directory the release removes. Slot 0 also carries the derived segment
// transfer set (so 64 slot snapshots do not copy it 64 times), again naming a segment the
// selected snapshot holds. Compaction defers the removal of any pinned segment until release.
func (m *slotMachine) PinFiles() ([]replica.PinnedFile, func(), error) {
	e := m.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed || e.closed {
		return nil, nil, model.Fail(model.Unavailable)
	}
	have := map[string]replica.SnapshotFile{}
	if m.snaps != nil {
		if cur, ok := m.snaps.Current(); ok {
			for _, f := range cur.Manifest.Files {
				have[f.Name] = f
			}
		}
	}
	reusable := func(name string, size uint64, sum model.Hash) bool {
		h, ok := have["files/"+name]
		return ok && h.Size == size && h.SHA256 == sum
	}
	cut := m.cut
	if cut == nil || cut.application != e.indexes[m.slot] {
		table, err := e.windowTableLocked(m.slot, true)
		if err != nil {
			return nil, nil, err
		}
		cut = &cutTable{application: e.indexes[m.slot], windows: table}
	}
	var files []replica.PinnedFile
	var stage string
	removeStage := func() {
		if stage != "" {
			_ = os.RemoveAll(stage)
		}
	}
	for _, rec := range cut.windows {
		type part struct {
			name  string
			file  windowFile
			reuse bool
		}
		parts := []part{{name: winName(rec.N), file: rec.File}, {name: evName(rec.N), file: rec.Ev}}
		fresh := false
		for i := range parts {
			parts[i].reuse = reusable(parts[i].name, parts[i].file.Size, parts[i].file.SHA256)
			fresh = fresh || !parts[i].reuse
		}
		if fresh {
			if stage == "" {
				parent := filepath.Join(e.dir, "snapshot-stage")
				if err := os.MkdirAll(parent, 0700); err != nil {
					return nil, nil, err
				}
				var err error
				if stage, err = os.MkdirTemp(parent, fmt.Sprintf("cut-%d-", m.slot)); err != nil {
					return nil, nil, err
				}
			}
			err := e.db.View(func(tx *bolt.Tx) error {
				return writeWindowFiles(tx.Bucket([]byte("replica_commands")), m.slot, rec, stage)
			})
			if err != nil {
				removeStage()
				return nil, nil, err
			}
		}
		for _, p := range parts {
			if p.reuse {
				files = append(files, replica.PinnedFile{Name: p.name, Reuse: true, Size: p.file.Size, SHA256: p.file.SHA256})
			} else {
				files = append(files, replica.PinnedFile{Name: p.name, Path: filepath.Join(stage, p.name)})
			}
		}
	}
	var paths []string
	if m.slot == 0 {
		if e.catalog.File != "" {
			path := filepath.Join(e.dir, e.catalog.File)
			files = append(files, replica.PinnedFile{Name: "storage-manifest.json", Path: path})
			paths = append(paths, path)
		}
		for i, s := range e.catalog.Manifest.Segments {
			path, err := segmentPath(e.dir, s.File)
			if err != nil {
				removeStage()
				return nil, nil, err
			}
			name := fmt.Sprintf("segment-%06d.sps", i)
			if reusable(name, s.Bytes, s.Checksum) {
				files = append(files, replica.PinnedFile{Name: name, Reuse: true, Size: s.Bytes, SHA256: s.Checksum})
			} else {
				files = append(files, replica.PinnedFile{Name: name, Path: path})
			}
			paths = append(paths, path)
		}
		if e.snap.pinned == nil {
			e.snap.pinned = map[string]int{}
			e.snap.retired = map[string]bool{}
		}
		for _, path := range paths {
			e.snap.pinned[path]++
		}
	}
	var once sync.Once
	return files, func() {
		once.Do(func() {
			removeStage()
			if len(paths) == 0 {
				return
			}
			e.mu.Lock()
			defer e.mu.Unlock()
			for _, path := range paths {
				if e.snap.pinned[path] <= 1 {
					delete(e.snap.pinned, path)
					if e.snap.retired[path] {
						delete(e.snap.retired, path)
						_ = durablefs.Remove(path)
					}
				} else {
					e.snap.pinned[path]--
				}
			}
		})
	}, nil
}

// retireFileLocked removes a replaced segment unless a snapshot copy is reading
// it; a pinned file is reclaimed by the last release instead.
func (e *Engine) retireFileLocked(path string) error {
	if e.snap.pinned[path] > 0 {
		e.snap.retired[path] = true
		return nil
	}
	return durablefs.Remove(path)
}

// ---- Engine-level cuts --------------------------------------------------------

// EngineSnapshot is one verified cut D: a snapshot for every owned group.
type EngineSnapshot struct {
	Identity model.ID
	Slots    []replica.Snapshot
}

func snapshotFault(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, replica.ErrCorrupt), errors.Is(err, replica.ErrNoLedger):
		return model.Fail(model.Corrupt)
	case errors.Is(err, replica.ErrNoSnapshot):
		return model.Fail(model.NotFound)
	}
	return storageReplicaFault(err)
}

// CreateSnapshots cuts and verifies a snapshot of every group while intake,
// flush and compaction continue. Each slot's cut is consistent with its own
// receipts and ledger; the returned per-slot cursors are the cut D.
func (e *Engine) CreateSnapshots(ctx context.Context) (EngineSnapshot, error) {
	if e.repl == nil {
		return EngineSnapshot{}, model.Fail(model.Unavailable)
	}
	// A cut copies the retry table: finish any redaction the erase pass owes it first.
	if err := e.redactReplica(ctx); err != nil {
		return EngineSnapshot{}, err
	}
	out := EngineSnapshot{Identity: e.identity, Slots: make([]replica.Snapshot, 0, 64)}
	coverage := make([]model.Cursor, 0, 64)
	for slot, group := range e.repl.groups {
		cursor := group.Status().ApplicationCursor
		var snapshot replica.Snapshot
		var err error
		for attempt := 0; ; attempt++ {
			// A redaction between the window table a cut names and the moment its files are written,
			// or another snapshot selected in between, makes that attempt moot: repeat it.
			if snapshot, err = group.CreateSnapshot(ctx, cursor); err == nil || attempt >= 3 || !errors.Is(err, errWindowMoved) && !errors.Is(err, replica.ErrReuseLost) {
				break
			}
		}
		if err != nil {
			return EngineSnapshot{}, snapshotFault(err)
		}
		if _, err = group.Snapshots().VerifyCut(); err != nil {
			return EngineSnapshot{}, snapshotFault(err)
		}
		out.Slots = append(out.Slots, snapshot)
		coverage = append(coverage, model.Cursor{Group: e.group(uint16(slot)), Index: snapshot.Manifest.Cursor.Index})
	}
	e.mu.Lock()
	e.snap.coverage = coverage
	e.mu.Unlock()
	return out, nil
}

// CompactJournals truncates every group's Raft journal to its verified snapshot.
func (e *Engine) CompactJournals(ctx context.Context) error {
	if e.repl == nil {
		return model.Fail(model.Unavailable)
	}
	for _, group := range e.repl.groups {
		if _, err := group.CompactJournal(ctx); err != nil {
			return snapshotFault(err)
		}
	}
	return nil
}

// seedSnapshotCoverage restores, after a restart, the coverage CreateSnapshots last recorded: every
// group's selected snapshot is on disk, so the next publication must not report "nothing
// snapshotted". Only the cheap structural read of the CURRENT pointer is used; the cut is verified
// whenever it is used to truncate a journal.
func (e *Engine) seedSnapshotCoverage(groups []*replica.Group) {
	coverage, any := make([]model.Cursor, len(groups)), false
	for slot, group := range groups {
		coverage[slot] = model.Cursor{Group: e.group(uint16(slot))}
		if snapshot, ok := group.Snapshots().Current(); ok {
			coverage[slot].Index = snapshot.Manifest.Cursor.Index
			any = true
		}
	}
	if !any {
		return
	}
	e.mu.Lock()
	if e.snap.coverage == nil {
		e.snap.coverage = coverage
	}
	e.mu.Unlock()
}

func (e *Engine) snapshotCoverageLocked() []model.Cursor {
	return append([]model.Cursor(nil), e.snap.coverage...)
}

// SlotDirectory is the group directory EnableReplication uses for slot.
func SlotDirectory(raftDirectory string, slot uint16) string {
	return filepath.Join(raftDirectory, fmt.Sprintf("slot-%d", slot))
}

// ---- Reading a snapshot ------------------------------------------------------------

type slotEntry struct {
	raw   []byte
	entry walEntry
}

// slotEntries decodes the command history inside a verified slot snapshot.
func slotEntries(snapshot replica.Snapshot) ([]slotEntry, error) {
	state, err := snapshot.MachineState()
	if err != nil {
		return nil, model.Fail(model.Corrupt)
	}
	var decoded slotSnapshot
	if model.StrictJSON(state, &decoded) != nil || decoded.Version != 1 || uint64(len(decoded.Entries)) != uint64(decoded.Application) || uint64(decoded.Application) != uint64(snapshot.Manifest.Cursor.Index) {
		return nil, model.Fail(model.Corrupt)
	}
	out := make([]slotEntry, len(decoded.Entries))
	for i, raw := range decoded.Entries {
		out[i].raw = raw
		if json.Unmarshal(raw, &out[i].entry) != nil {
			return nil, model.Fail(model.Corrupt)
		}
	}
	return out, nil
}

// evidenceDigest is the digest of a command's replay-relevant bytes; the
// CommitSet proof attached at apply time is excluded so the journal form and the
// stored form agree.
func evidenceDigest(entry walEntry) (model.Hash, error) {
	if entry.Redaction != nil {
		// A redacted command stands for the journal original: backup replay certificates are
		// derived from the journal form, so both forms must yield the same digest.
		return entry.Redaction.Original, nil
	}
	entry.CommitSet = nil
	raw, err := json.Marshal(entry)
	if err != nil {
		return model.Hash{}, err
	}
	return model.HashCanonical(raw), nil
}

// ---- C12 certificates (typed interface; no other module defines these yet) ----

// ControlCut is the control checkpoint C taken at installation backup: the
// processed evidence highwater H of every data group and the reservations
// control held at C.
type ControlCut struct {
	Revision     model.Revision                        `json:"revision"`
	Processed    []model.Cursor                        `json:"processed"`
	Reservations map[string]model.AdmissionReservation `json:"reservations"`
}

// DeclaredGap mirrors a committed RecordEvidenceGap: evidence in (After,Through]
// of Group expired unprocessed and control knows it.
type DeclaredGap struct {
	Group   model.ID     `json:"group"`
	After   model.Uint64 `json:"after"`
	Through model.Uint64 `json:"through"`
	Reason  string       `json:"reason"`
}

// ReplayInterval is a replay-or-gap interval certificate for one run of one
// group. Mode "replay" carries a digest of every command in the run; mode "gap"
// names the declared gap that explains the missing run.
type ReplayInterval struct {
	Group   model.ID     `json:"group"`
	After   model.Uint64 `json:"after"`
	Through model.Uint64 `json:"through"`
	Mode    string       `json:"mode"`
	Count   model.Uint64 `json:"count"`
	Digest  model.Hash   `json:"digest"`
	Reason  string       `json:"reason,omitempty"`
}

// ReplayCertificate covers (H, D] of every group; a missing group or run fails the backup.
type ReplayCertificate struct {
	Version   uint16           `json:"version"`
	Intervals []ReplayInterval `json:"intervals"`
	Digest    model.Hash       `json:"digest"`
}

// ReservationEvidence is one reservation the data cut consumed.
type ReservationEvidence struct {
	ID      model.ID     `json:"id"`
	Org     model.ID     `json:"org"`
	Project model.ID     `json:"project"`
	Source  model.ID     `json:"source"`
	Hash    model.Hash   `json:"hash"`
	Bytes   model.Uint64 `json:"bytes"`
	Series  []string     `json:"series"`
	// Redacted marks a batch physical erasure rewrote. Retained then lists the
	// canonical metric series its kept records still carry and replaces Series
	// in the restored-index cross-check; Series stays the charged set because
	// erasure refunds no quota.
	Redacted bool         `json:"redacted,omitempty"`
	Retained []string     `json:"retained,omitempty"`
	Cursor   model.Cursor `json:"cursor"`
}

// CancellationEvidence is a committed cancellation fence carried by the cut.
type CancellationEvidence struct {
	ID    model.ID     `json:"id"`
	Hash  model.Hash   `json:"hash"`
	Fence model.Cursor `json:"fence"`
}

// WindowEvidence summarises what one window of one group's history consumed (bundle version 2).
// Charge is the digest of the window's consumed reservations as the data holds them and Identity
// the digest of its commands. A window is Detail when control's cut does not already hold exactly
// those reservations (or the window carries redacted batches, whose retained series control cannot
// know): the evidence of its reservations is then listed in QuotaEvidence.Consumed. Otherwise the
// reservations are the ones the control cut holds as consumed in that window, and Charge proves it.
type WindowEvidence struct {
	Group    model.ID   `json:"group"`
	N        uint64     `json:"n,string"`
	First    uint64     `json:"first,string"`
	Count    uint64     `json:"count,string"`
	Span     uint64     `json:"span,string"`
	Batches  uint64     `json:"batches,string"`
	Redacted uint64     `json:"redacted,string"`
	Charge   model.Hash `json:"charge"`
	Identity model.Hash `json:"identity"`
	Detail   bool       `json:"detail,omitempty"`
}

// QuotaEvidence is the reservation consumption/release evidence a sealed D carries. Version 1
// lists every consumed reservation; version 2 lists the windows of every group and the
// reservations of the Detail windows only, so its size follows the number of windows and the
// reservations control does not already hold, not the length of the history.
type QuotaEvidence struct {
	Version   uint16                 `json:"version"`
	Windows   []WindowEvidence       `json:"windows,omitempty"`
	Consumed  []ReservationEvidence  `json:"consumed"`
	Cancelled []CancellationEvidence `json:"cancelled"`
	Digest    model.Hash             `json:"digest"`
}

// BackupBundle is the sealed result of an installation backup.
type BackupBundle struct {
	Version    uint16                     `json:"version"`
	Identity   model.ID                   `json:"identity"`
	Cut        ControlCut                 `json:"cut"`
	Snapshots  []replica.SnapshotManifest `json:"snapshots"`
	Replay     ReplayCertificate          `json:"replay"`
	Quota      QuotaEvidence              `json:"quota"`
	Generation uint64                     `json:"generation,string"`
	Digest     model.Hash                 `json:"digest"`
}

func (b BackupBundle) seal() model.Hash {
	b.Digest = model.Hash{}
	raw, err := json.Marshal(b)
	if err != nil {
		return model.Hash{}
	}
	return model.HashCanonical(raw)
}
func (r ReplayCertificate) seal() model.Hash {
	r.Digest = model.Hash{}
	raw, _ := json.Marshal(r)
	return model.HashCanonical(raw)
}
func (q QuotaEvidence) seal() model.Hash {
	q.Digest = model.Hash{}
	raw, _ := json.Marshal(q)
	return model.HashCanonical(raw)
}

// ---- Backup: capture C/H, pin, seal D ------------------------------------------------

// Backup is one in-progress installation backup. Copying may continue while
// intake proceeds; the pinned post-H journal cannot be reclaimed until Seal or
// Abort.
type Backup struct {
	engine  *Engine
	cut     ControlCut
	pins    []*replica.JournalPin // by slot
	mu      sync.Mutex
	aborted bool
	sealed  bool
}

// BeginBackup validates C/H and atomically pins the post-H journal of every
// group before returning. A cut that names a group more or fewer than the
// installation owns, or a highwater beyond what the group applied, is refused.
func (e *Engine) BeginBackup(ctx context.Context, cut ControlCut) (*Backup, error) {
	if e.repl == nil {
		return nil, model.Fail(model.Unavailable)
	}
	if len(cut.Processed) != 64 {
		return nil, model.Fail(model.Invalid)
	}
	processed := map[model.ID]model.Uint64{}
	for _, c := range cut.Processed {
		if _, dup := processed[c.Group]; dup {
			return nil, model.Fail(model.Invalid)
		}
		processed[c.Group] = c.Index
	}
	b := &Backup{engine: e, cut: cut, pins: make([]*replica.JournalPin, 64)}
	for slot, group := range e.repl.groups {
		after, ok := processed[e.group(uint16(slot))]
		if !ok {
			b.release()
			return nil, model.Fail(model.Invalid)
		}
		if uint64(after) > uint64(group.Status().ApplicationCursor.Index) {
			b.release()
			return nil, model.Fail(model.Stale)
		}
		pin, err := group.PinJournal(uint64(after))
		if err != nil {
			b.release()
			return nil, snapshotFault(err)
		}
		b.pins[slot] = pin
	}
	e.trackBackup(b)
	return b, nil
}

func (b *Backup) release() {
	b.engine.untrackBackup(b)
	for i, pin := range b.pins {
		if pin != nil {
			_ = pin.Release()
			b.pins[i] = nil
		}
	}
}

// Abort releases every pin; the evidence becomes reclaimable again.
func (b *Backup) Abort() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.aborted = true
	b.release()
}

// NoteDeletion records that privacy deletion touched pinned evidence. The
// conservative reaction is to abort: the backup must restart after the deletion
// fence instead of sealing evidence it may no longer hold.
func (b *Backup) NoteDeletion() { b.Abort() }

// SealedBackup is the bundle plus the verified per-slot snapshot directories.
type SealedBackup struct {
	Bundle    BackupBundle
	Snapshots []replica.Snapshot
}

// Seal cuts D>=H and proves the whole post-H history: every command in (H, D] of
// every group is either replayable from the pinned journal or inside a declared
// gap. Anything else - a missing group, a hole nobody declared - fails the backup.
func (b *Backup) Seal(ctx context.Context, gaps []DeclaredGap) (SealedBackup, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.aborted || b.sealed {
		return SealedBackup{}, model.Fail(model.Conflict)
	}
	e := b.engine
	cut, err := e.CreateSnapshots(ctx)
	if err != nil {
		return SealedBackup{}, err
	}
	processed := map[model.ID]uint64{}
	for _, c := range b.cut.Processed {
		processed[c.Group] = uint64(c.Index)
	}
	var intervals []ReplayInterval
	manifests := make([]replica.SnapshotManifest, 0, 64)
	for slot, snapshot := range cut.Slots {
		group := e.group(uint16(slot))
		after, through := processed[group], uint64(snapshot.Manifest.Cursor.Index)
		if through < after {
			return SealedBackup{}, model.Fail(model.Stale)
		}
		entries, err := b.pins[slot].Entries(through)
		if err != nil {
			return SealedBackup{}, snapshotFault(err)
		}
		runs, err := replayIntervals(group, after, through, entries, gaps)
		if err != nil {
			return SealedBackup{}, err
		}
		intervals = append(intervals, runs...)
		manifests = append(manifests, snapshot.Manifest)
	}
	slots, err := quotaEvidenceFor(cut.Slots, b.cut.Reservations, false)
	if err != nil {
		return SealedBackup{}, err
	}
	bundle := BackupBundle{Version: slots.Version, Identity: e.identity, Cut: b.cut, Snapshots: manifests, Replay: ReplayCertificate{Version: 1, Intervals: intervals}, Quota: slots, Generation: manifests[0].Generation}
	bundle.Replay.Digest = bundle.Replay.seal()
	bundle.Digest = bundle.seal()
	if err = verifyReplayAgainstSnapshots(bundle, cut.Slots); err != nil {
		return SealedBackup{}, err
	}
	b.sealed = true
	b.release()
	return SealedBackup{Bundle: bundle, Snapshots: cut.Slots}, nil
}

func intervalDigest(entries map[uint64]model.Hash, after, through uint64) model.Hash {
	h := sha256.New()
	for i := after + 1; i <= through; i++ {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], i)
		h.Write(n[:])
		sum := entries[i]
		h.Write(sum[:])
	}
	var out model.Hash
	copy(out[:], h.Sum(nil))
	return out
}

func replayIntervals(group model.ID, after, through uint64, entries []replica.ReplayEntry, gaps []DeclaredGap) ([]ReplayInterval, error) {
	digests := map[uint64]model.Hash{}
	for _, r := range entries {
		var walled walEntry
		if json.Unmarshal(r.Payload, &walled) != nil {
			return nil, model.Fail(model.Corrupt)
		}
		d, err := evidenceDigest(walled)
		if err != nil {
			return nil, model.Fail(model.Corrupt)
		}
		digests[r.ApplicationIndex] = d
	}
	var out []ReplayInterval
	start := after + 1
	for start <= through {
		_, present := digests[start]
		end := start
		for end+1 <= through {
			if _, p := digests[end+1]; p != present {
				break
			}
			end++
		}
		if present {
			out = append(out, ReplayInterval{Group: group, After: model.Uint64(start - 1), Through: model.Uint64(end), Mode: "replay", Count: model.Uint64(end - start + 1), Digest: intervalDigest(digests, start-1, end)})
		} else {
			var gap *DeclaredGap
			for i := range gaps {
				if gaps[i].Group == group && uint64(gaps[i].After) == start-1 && uint64(gaps[i].Through) == end && gaps[i].Reason != "" {
					gap = &gaps[i]
				}
			}
			if gap == nil {
				// A hole nobody declared: the pinned journal does not hold the
				// evidence and control never recorded losing it.
				return nil, model.Fail(model.Unavailable)
			}
			out = append(out, ReplayInterval{Group: group, After: gap.After, Through: gap.Through, Mode: "gap", Count: model.Uint64(end - start + 1), Reason: gap.Reason, Digest: model.HashCanonical([]byte(fmt.Sprintf("gap:%s:%d:%d:%s", group, start-1, end, gap.Reason)))})
		}
		start = end + 1
	}
	if len(out) == 0 { // H == D: an explicit empty interval proves the group was covered
		out = append(out, ReplayInterval{Group: group, After: model.Uint64(after), Through: model.Uint64(through), Mode: "replay", Digest: intervalDigest(digests, after, through)})
	}
	return out, nil
}

// verifyReplayAgainstSnapshots re-derives every replay interval from the
// command history inside the sealed snapshots themselves, so the certificate
// proves the snapshot bytes - not just the live journal - hold the evidence.
func verifyReplayAgainstSnapshots(bundle BackupBundle, slots []replica.Snapshot) error {
	if len(slots) != 64 || len(bundle.Snapshots) != 64 || bundle.Replay.Digest != bundle.Replay.seal() {
		return model.Fail(model.Corrupt)
	}
	for i, snapshot := range slots {
		if snapshot.Manifest.Checksum != bundle.Snapshots[i].Checksum {
			return model.Fail(model.Corrupt)
		}
		if err := verifyReplayAgainstSnapshotsFor(bundle, snapshot); err != nil {
			return err
		}
	}
	return nil
}

func quotaEvidence(slots []replica.Snapshot) (QuotaEvidence, error) {
	out := QuotaEvidence{Version: 1, Consumed: []ReservationEvidence{}, Cancelled: []CancellationEvidence{}}
	for _, snapshot := range slots {
		entries, err := slotEntries(snapshot)
		if err != nil {
			return QuotaEvidence{}, err
		}
		for _, e := range entries {
			switch e.entry.Type {
			case "batch", "batch_redacted":
				if e.entry.Batch == nil || e.entry.Receipt == nil {
					return QuotaEvidence{}, model.Fail(model.Corrupt)
				}
				r := e.entry.Batch.Reservation
				ev := ReservationEvidence{ID: r.ID, Org: r.Org, Project: r.Project, Source: r.Source, Hash: r.Hash, Bytes: r.Bytes, Series: append([]string(nil), r.Series...), Cursor: e.entry.Receipt.Cursor}
				if e.entry.Type == "batch_redacted" {
					set := map[string]bool{}
					for _, rec := range e.entry.Batch.Records {
						if rec.Kind != model.Metric {
							continue
						}
						id, ierr := model.CanonicalSeriesID(r.Project, rec)
						if ierr != nil {
							return QuotaEvidence{}, model.Fail(model.Corrupt)
						}
						set[id] = true
					}
					ev.Redacted = true
					for id := range set {
						ev.Retained = append(ev.Retained, id)
					}
					sort.Strings(ev.Retained)
				}
				out.Consumed = append(out.Consumed, ev)
			case "cancel":
				if e.entry.Cancel == nil {
					return QuotaEvidence{}, model.Fail(model.Corrupt)
				}
				out.Cancelled = append(out.Cancelled, CancellationEvidence{ID: e.entry.Cancel.ReservationID, Hash: e.entry.Cancel.Hash, Fence: e.entry.Cancel.Fence})
			}
		}
	}
	sort.Slice(out.Consumed, func(i, j int) bool { return bytes.Compare(out.Consumed[i].ID[:], out.Consumed[j].ID[:]) < 0 })
	sort.Slice(out.Cancelled, func(i, j int) bool { return bytes.Compare(out.Cancelled[i].ID[:], out.Cancelled[j].ID[:]) < 0 })
	out.Digest = out.seal()
	return out, nil
}

// ---- Restore: install, reconcile quotas, then open intake ----------------------------

// QuotaCharge is the live logical charge on one quota key.
type QuotaCharge struct {
	Bytes  model.Uint64      `json:"bytes"`
	Series map[string]uint64 `json:"series"`
}

// QuotaReconciliation is the verified certificate that must be persisted before
// a restored engine admits anything.
type QuotaReconciliation struct {
	Version         uint16                 `json:"version"`
	Backup          model.Hash             `json:"backup"`
	ControlRevision model.Revision         `json:"control_revision"`
	Charges         map[string]QuotaCharge `json:"charges"`
	Consumed        []model.ID             `json:"consumed"`
	AddedAfterCut   []model.ID             `json:"added_after_cut"`
	Refunded        []model.ID             `json:"refunded"`
	Pending         []model.ID             `json:"pending"`
	SeriesDigest    map[string]model.Hash  `json:"series_digest"`
	Digest          model.Hash             `json:"digest"`
}

func (q QuotaReconciliation) seal() model.Hash {
	q.Digest = model.Hash{}
	raw, _ := json.Marshal(q)
	return model.HashCanonical(raw)
}

func quotaKeys(org, project, source model.ID) []string {
	return []string{"org:" + org.String(), "project:" + org.String() + ":" + project.String(), "source:" + org.String() + ":" + project.String() + ":" + source.String()}
}

// ReconcileQuota reconstructs exactly one control charge per consumed
// reservation - including reservations created after C - and reconciles those
// control holds against the cut without an unsafe refund or double charge.
func ReconcileQuota(bundle BackupBundle) (QuotaReconciliation, error) {
	if bundle.Version != 1 && bundle.Version != 2 || bundle.Digest != bundle.seal() || bundle.Quota.Digest != bundle.Quota.seal() || bundle.Quota.Version != bundle.Version {
		return QuotaReconciliation{}, model.Fail(model.Corrupt)
	}
	evidence, err := bundle.ConsumedEvidence()
	if err != nil {
		return QuotaReconciliation{}, err
	}
	consumed := map[model.ID]ReservationEvidence{}
	for _, c := range evidence {
		if _, dup := consumed[c.ID]; dup {
			return QuotaReconciliation{}, model.Fail(model.Corrupt)
		}
		consumed[c.ID] = c
	}
	cancelled := map[model.ID]CancellationEvidence{}
	for _, c := range bundle.Quota.Cancelled {
		cancelled[c.ID] = c
	}
	type live struct {
		org, project, source model.ID
		bytes                model.Uint64
		series               []string
	}
	charged := map[model.ID]live{}
	cert := QuotaReconciliation{Version: 1, Backup: bundle.Digest, ControlRevision: bundle.Cut.Revision, Charges: map[string]QuotaCharge{}, SeriesDigest: map[string]model.Hash{}, Consumed: []model.ID{}, AddedAfterCut: []model.ID{}, Refunded: []model.ID{}, Pending: []model.ID{}}
	touch := func(org, project, source model.ID) {
		for _, k := range quotaKeys(org, project, source) {
			if _, ok := cert.Charges[k]; !ok {
				cert.Charges[k] = QuotaCharge{Series: map[string]uint64{}}
			}
		}
	}
	ids := make([]string, 0, len(bundle.Cut.Reservations))
	for id := range bundle.Cut.Reservations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, key := range ids {
		r := bundle.Cut.Reservations[key]
		if r.ID.String() != key {
			return QuotaReconciliation{}, model.Fail(model.Corrupt)
		}
		touch(r.Org, r.Project, r.Source)
		data, used := consumed[r.ID]
		_, fenced := cancelled[r.ID]
		switch {
		case used && fenced, used && r.State == "cancelled":
			return QuotaReconciliation{}, model.Fail(model.Conflict)
		case used:
			if data.Hash != r.Hash || data.Bytes != r.Bytes || r.State == "consumed" && (r.Cursor == nil || *r.Cursor != data.Cursor) {
				return QuotaReconciliation{}, model.Fail(model.Conflict)
			}
			charged[r.ID] = live{r.Org, r.Project, r.Source, r.Bytes, r.Series}
			cert.Consumed = append(cert.Consumed, r.ID)
		case r.State == "consumed":
			// Control says consumed but the sealed data has no such batch: unprovable.
			return QuotaReconciliation{}, model.Fail(model.Unavailable)
		case fenced:
			cert.Refunded = append(cert.Refunded, r.ID) // committed no-use fence proves the refund is safe
		case r.State == "cancelled":
			return QuotaReconciliation{}, model.Fail(model.Unavailable) // refunded without a fence in D
		default:
			charged[r.ID] = live{r.Org, r.Project, r.Source, r.Bytes, r.Series}
			cert.Pending = append(cert.Pending, r.ID)
		}
	}
	for _, c := range evidence {
		if _, known := bundle.Cut.Reservations[c.ID.String()]; known {
			continue
		}
		touch(c.Org, c.Project, c.Source) // created after C, consumed in D: reconstruct its single charge
		charged[c.ID] = live{c.Org, c.Project, c.Source, c.Bytes, c.Series}
		cert.Consumed = append(cert.Consumed, c.ID)
		cert.AddedAfterCut = append(cert.AddedAfterCut, c.ID)
	}
	for _, l := range charged {
		for _, key := range quotaKeys(l.org, l.project, l.source) {
			c := cert.Charges[key]
			c.Bytes += l.bytes
			for _, s := range l.series {
				c.Series[s]++
			}
			cert.Charges[key] = c
		}
	}
	// Consumed-only series per project for the restored-index cross-check.
	perProject := map[string]map[string]bool{}
	for _, c := range evidence {
		k := c.Org.String() + ":" + c.Project.String()
		if perProject[k] == nil {
			perProject[k] = map[string]bool{}
		}
		indexed := c.Series
		if c.Redacted {
			indexed = c.Retained // erased records' series are charged but no longer indexed
		}
		for _, s := range indexed {
			perProject[k][s] = true
		}
	}
	for k, set := range perProject {
		cert.SeriesDigest[k] = seriesSetDigest(set)
	}
	sortIDs := func(v []model.ID) { sort.Slice(v, func(i, j int) bool { return bytes.Compare(v[i][:], v[j][:]) < 0 }) }
	sortIDs(cert.Consumed)
	sortIDs(cert.AddedAfterCut)
	sortIDs(cert.Refunded)
	sortIDs(cert.Pending)
	cert.Digest = cert.seal()
	return cert, nil
}

func seriesSetDigest(set map[string]bool) model.Hash {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return model.HashCanonical([]byte(strings.Join(keys, "\n")))
}

// Apply returns quotas with exactly the reconciled charge on every key a
// reservation touched; limits, configuration and unrelated keys are untouched.
func (q QuotaReconciliation) Apply(quotas map[string]model.QuotaState) map[string]model.QuotaState {
	out := make(map[string]model.QuotaState, len(quotas)+len(q.Charges))
	for k, v := range quotas {
		out[k] = v
	}
	for key, charge := range q.Charges {
		state := out[key]
		state.Bytes = charge.Bytes
		state.Series = make(map[string]uint64, len(charge.Series))
		for s, n := range charge.Series {
			state.Series[s] = n
		}
		out[key] = state
	}
	return out
}

// InstallBackup installs every slot snapshot of a sealed bundle into raftDirectory
// (the directory later passed to EnableReplication) and closes intake until a
// QuotaReconciliation is committed. Missing data or proof fails the whole
// installation; nothing is selected unless every group verifies.
func (e *Engine) InstallBackup(ctx context.Context, raftDirectory string, bundle BackupBundle, open func(slot uint16) (io.ReadCloser, error)) error {
	if e.repl != nil || bundle.Version != 1 && bundle.Version != 2 || bundle.Identity != e.identity || bundle.Digest != bundle.seal() || len(bundle.Snapshots) != 64 || len(bundle.Replay.Intervals) < 64 || bundle.Replay.Digest != bundle.Replay.seal() || len(bundle.Cut.Processed) != 64 {
		return model.Fail(model.Invalid)
	}
	if _, err := ReconcileQuota(bundle); err != nil {
		return err // missing consumption/release proof blocks readiness
	}
	stores := make([]*replica.SnapshotStore, 64)
	for slot := range uint16(64) {
		m := bundle.Snapshots[slot]
		if m.Group != e.group(slot) {
			return model.Fail(model.Invalid)
		}
		store, err := replica.OpenSnapshotStore(SlotDirectory(raftDirectory, slot), m.Group, e.trip)
		if err != nil {
			return snapshotFault(err)
		}
		stores[slot] = store
	}
	if err := e.writeHold(bundle.Digest); err != nil {
		return err
	}
	if err := e.writeDeletionGate(bundle.Digest); err != nil {
		return err
	}
	installed := make([]replica.Snapshot, 64)
	for slot := range uint16(64) {
		in, err := open(slot)
		if err != nil {
			return model.Fail(model.Unavailable)
		}
		err = stores[slot].InstallSnapshot(ctx, bundle.Snapshots[slot], in)
		in.Close()
		if err != nil {
			return snapshotFault(err)
		}
		current, ok := stores[slot].Current()
		if !ok {
			return model.Fail(model.Corrupt)
		}
		if err = verifyReplayAgainstSnapshotsFor(bundle, current); err != nil {
			return err
		}
		installed[slot] = current
	}
	// The consumption/release proof must be exactly what the installed bytes carry.
	evidence, err := quotaEvidenceFor(installed, bundle.Cut.Reservations, true)
	if err != nil {
		return err
	}
	if evidence.Version != bundle.Quota.Version || evidence.Digest != bundle.Quota.Digest {
		return model.Fail(model.Corrupt)
	}
	return nil
}

func verifyReplayAgainstSnapshotsFor(bundle BackupBundle, snapshot replica.Snapshot) error {
	group := snapshot.Manifest.Group
	var processed uint64
	for _, c := range bundle.Cut.Processed {
		if c.Group == group {
			processed = uint64(c.Index)
		}
	}
	digests, total, err := evidenceDigests(snapshot, processed)
	if err != nil {
		return err
	}
	next, seen := processed, false
	for _, in := range bundle.Replay.Intervals {
		if in.Group != group {
			continue
		}
		if uint64(in.After) != next || uint64(in.Through) < uint64(in.After) || uint64(in.Through) > total {
			return model.Fail(model.Corrupt)
		}
		switch in.Mode {
		case "replay":
			if uint64(in.Count) != uint64(in.Through)-uint64(in.After) || uint64(in.Count) != 0 && intervalDigest(digests, uint64(in.After), uint64(in.Through)) != in.Digest {
				return model.Fail(model.Corrupt)
			}
		case "gap":
			if in.Reason == "" || uint64(in.Count) != uint64(in.Through)-uint64(in.After) {
				return model.Fail(model.Corrupt)
			}
		default:
			return model.Fail(model.Corrupt)
		}
		next, seen = uint64(in.Through), true
	}
	if !seen || next != uint64(snapshot.Manifest.Cursor.Index) {
		return model.Fail(model.Corrupt)
	}
	return nil
}

// writeHold stamps the restore-quota marker with temp + fsync + rename, so a crash leaves the
// previous marker or the new one and never a short file.
func (e *Engine) writeHold(digest model.Hash) error {
	path := filepath.Join(e.dir, restorePendingFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(digest.String()), 0600); err != nil {
		return err
	}
	if err := durablefs.SyncFileAndDir(tmp); err != nil {
		return err
	}
	if err := durablefs.Rename(tmp, path); err != nil {
		return err
	}
	e.snap.hold.Store(true)
	return nil
}

// loadRestoreHold re-arms the intake gate after a restart of a restored engine. A marker
// temporary left by a crash inside writeHold arms it too: the stamp never completed, so
// reconciliation has not, and intake must stay closed until the restore stamps it again.
func (e *Engine) loadRestoreHold() error {
	for _, name := range []string{restorePendingFile, restorePendingFile + ".tmp"} {
		if _, err := os.Stat(filepath.Join(e.dir, name)); err == nil {
			e.snap.hold.Store(true)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return e.loadDeletionGate()
}

// RestoreReady reports whether a restored engine may admit and serve receipts.
func (e *Engine) RestoreReady() error {
	if e.snap.hold.Load() || e.tomb.gate.Load() {
		return model.Fail(model.Unavailable)
	}
	return nil
}

// CommitQuotaReconciliation verifies the certificate against the restored
// engine - bound to the installed bundle and cross-checked against the series
// recomputed from the restored project index - persists it, and only then opens
// intake. A mismatch leaves intake closed.
func (e *Engine) CommitQuotaReconciliation(ctx context.Context, cert QuotaReconciliation) error {
	e.proposalMu.Lock()
	defer e.proposalMu.Unlock()
	if e.repl == nil {
		return model.Fail(model.Unavailable)
	}
	pending, err := os.ReadFile(filepath.Join(e.dir, restorePendingFile))
	if err != nil {
		return model.Fail(model.Conflict)
	}
	if cert.Version != 1 || cert.Digest != cert.seal() || strings.TrimSpace(string(pending)) != cert.Backup.String() {
		return model.Fail(model.Corrupt)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return model.Fail(model.Unavailable)
	}
	recomputed := map[string]map[string]bool{}
	err = e.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("batches")).ForEach(func(k, v []byte) error {
			parts := strings.Split(string(k), ":")
			if len(parts) < 2 {
				return model.Fail(model.Corrupt)
			}
			project, perr := model.ParseID(parts[1])
			if perr != nil {
				return model.Fail(model.Corrupt)
			}
			var records []model.Record
			if json.Unmarshal(v, &records) != nil {
				return model.Fail(model.Corrupt)
			}
			for _, r := range records {
				if r.Kind != model.Metric {
					continue
				}
				id, ierr := model.CanonicalSeriesID(project, r)
				if ierr != nil {
					return model.Fail(model.Corrupt)
				}
				name := parts[0] + ":" + parts[1]
				if recomputed[name] == nil {
					recomputed[name] = map[string]bool{}
				}
				recomputed[name][id] = true
			}
			return nil
		})
	})
	if err != nil {
		return err
	}
	// An absent entry is the empty series set on either side: a project whose
	// batches carry no metric series (logs, spans, or everything erased) has an
	// empty digest in the certificate and no metric in the restored index.
	for name, want := range cert.SeriesDigest {
		if want != seriesSetDigest(recomputed[name]) {
			return model.Fail(model.Corrupt)
		}
	}
	for name, set := range recomputed {
		if _, ok := cert.SeriesDigest[name]; !ok && len(set) > 0 {
			return model.Fail(model.Corrupt)
		}
	}
	raw, err := json.Marshal(cert)
	if err != nil {
		return err
	}
	certPath := filepath.Join(e.dir, quotaCertFile)
	if err = os.WriteFile(certPath, raw, 0600); err != nil {
		return err
	}
	if err = durablefs.SyncFileAndDir(certPath); err != nil {
		return err
	}
	if err = e.trip("quota_certificate_persisted"); err != nil {
		return err
	}
	if err = durablefs.Remove(filepath.Join(e.dir, restorePendingFile)); err != nil {
		return err
	}
	e.snap.hold.Store(false)
	return nil
}
