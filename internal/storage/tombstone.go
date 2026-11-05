// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/durablefs"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

const (
	tombstoneBucket     = "tombstones"
	deletionPendingFile = "restore-deletion.pending"
	deletionGenerationK = "deletion_generation"
)

// DeletionView lets the engine honour a deletion from the instant control
// commits Begin, before every slot has a barrier. It must return the predicates
// of operations in phase fencing or complete.
type DeletionView interface {
	ActiveDeletions(ctx context.Context, org model.ID, projects []model.ID) ([]model.DeletePredicate, error)
}

type viewHolder struct{ view DeletionView }

// tombstoneState is the engine's deletion bookkeeping. Its zero value is usable.
type tombstoneState struct {
	view    atomic.Pointer[viewHolder]
	gate    atomic.Bool // a restored engine stays closed until the deletion ledger is applied
	mu      sync.Mutex
	backups map[*Backup]struct{}
}

// BindDeletions installs the control-state deletion view exactly once.
func (e *Engine) BindDeletions(v DeletionView) error {
	if v == nil {
		return model.Fail(model.Invalid)
	}
	if !e.tomb.view.CompareAndSwap(nil, &viewHolder{view: v}) {
		return model.Fail(model.Conflict)
	}
	return nil
}

func tombstoneKey(slot uint16, operation model.ID) []byte {
	return append(slotKey(slot), operation.String()...)
}

// tombstonesWithPrefix lists the tombstones whose key starts with prefix, in key
// (slot, operation) order. A database that never saw a deletion has no bucket.
func tombstonesWithPrefix(tx *bolt.Tx, prefix []byte) ([]model.DeleteBarrier, error) {
	bucket := tx.Bucket([]byte(tombstoneBucket))
	if bucket == nil {
		return nil, nil
	}
	var out []model.DeleteBarrier
	c := bucket.Cursor()
	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		var barrier model.DeleteBarrier
		if len(k) <= 2 || json.Unmarshal(v, &barrier) != nil {
			return nil, model.Fail(model.Corrupt)
		}
		out = append(out, barrier)
	}
	return out, nil
}

// validateTombstoneBatch is the ordered, deterministic rejection: a batch with
// any record covered by a tombstone already applied in this slot is refused as a
// whole (atomic admission).
func validateTombstoneBatch(tx *bolt.Tx, b model.NormalizedBatch) error {
	barriers, err := tombstonesWithPrefix(tx, slotKey(b.RouteSlot))
	if err != nil {
		return err
	}
	for _, barrier := range barriers {
		for _, record := range b.Records {
			if barrier.Predicate.CoversRecord(b.Org, b.Project, record) {
				return model.Fail(model.Conflict)
			}
		}
	}
	return nil
}

func validateTombstoneBlob(tx *bolt.Tx, m model.BlobManifest, slot uint16) error {
	barriers, err := tombstonesWithPrefix(tx, slotKey(slot))
	if err != nil {
		return err
	}
	for _, barrier := range barriers {
		if barrier.Predicate.CoversBlob(m) {
			return model.Fail(model.Conflict)
		}
	}
	return nil
}

// orderedRejection classifies an ordered validation failure: Conflict/Stale is a
// deterministic rejection recorded in the log, anything else trips the engine.
func orderedRejection(err error) (bool, error) {
	if err == nil {
		return false, nil
	}
	var fault *model.Fault
	if errors.As(err, &fault) && (fault.Code == model.Conflict || fault.Code == model.Stale) {
		return true, nil
	}
	return false, err
}

func (e *Engine) applyDeleteBarrier(tx *bolt.Tx, slot uint16, index uint64, entry walEntry) error {
	barrier := entry.DeleteBarrier
	if barrier == nil || entry.Batch != nil || entry.Receipt != nil || entry.Cancel != nil || entry.Fence != nil || entry.Artifact != nil || entry.ArtifactGC != nil || entry.Rejection != nil {
		return model.Fail(model.Corrupt)
	}
	if barrier.Cursor != (model.Cursor{Group: e.group(slot), Index: model.Uint64(index)}) || barrier.Predicate.Validate() != nil {
		return model.Fail(model.Corrupt)
	}
	bucket, err := tx.CreateBucketIfNotExists([]byte(tombstoneBucket))
	if err != nil {
		return err
	}
	key := tombstoneKey(slot, barrier.Predicate.Operation)
	if bucket.Get(key) != nil {
		return nil
	}
	raw, err := json.Marshal(barrier)
	if err != nil {
		return err
	}
	return bucket.Put(key, raw)
}

// deletionPredicates is the union of the bound control view and every locally
// applied tombstone of the organization, fetched fresh on every call so a
// deletion that begins mid-iteration takes effect at the next read.
func (e *Engine) deletionPredicates(ctx context.Context, org model.ID, projects []model.ID) ([]model.DeletePredicate, error) {
	var out []model.DeletePredicate
	seen := map[model.ID]bool{}
	if holder := e.tomb.view.Load(); holder != nil {
		preds, err := holder.view.ActiveDeletions(ctx, org, projects)
		if err != nil {
			return nil, err
		}
		for _, p := range preds {
			if p.Validate() != nil {
				return nil, model.Fail(model.Corrupt)
			}
			if p.Org == org && !seen[p.Operation] {
				seen[p.Operation] = true
				out = append(out, p)
			}
		}
	}
	err := e.db.View(func(tx *bolt.Tx) error {
		barriers, err := tombstonesWithPrefix(tx, nil)
		if err != nil {
			return err
		}
		for _, b := range barriers {
			if b.Predicate.Org == org && !seen[b.Predicate.Operation] {
				seen[b.Predicate.Operation] = true
				out = append(out, b.Predicate)
			}
		}
		return nil
	})
	return out, err
}

// readDeletions gates every read path: while a restore has not applied its
// deletion ledger nothing is served, and a retired project is indistinguishable
// from an unknown one.
func (e *Engine) readDeletions(ctx context.Context, org model.ID, projects []model.ID) ([]model.DeletePredicate, error) {
	if e.tomb.gate.Load() {
		return nil, model.Fail(model.Unavailable)
	}
	preds, err := e.deletionPredicates(ctx, org, projects)
	if err != nil {
		return nil, err
	}
	for _, p := range preds {
		for _, project := range projects {
			if p.RetiresProject(org, project) {
				return nil, model.Fail(model.NotFound)
			}
		}
	}
	return preds, nil
}

func entityPredicateActive(preds []model.DeletePredicate) bool {
	for _, p := range preds {
		if p.Mode == model.DeleteEntity {
			return true
		}
	}
	return false
}

// coveredRow reports whether row i of a decoded page is hidden. Range
// predicates only need the indexed signal time; entity predicates need the
// decoded replay/profile root (callers force payload decoding for them).
func coveredRow(preds []model.DeletePredicate, org model.ID, kind model.Kind, p Page, i int) bool {
	if len(preds) == 0 {
		return false
	}
	record := model.Record{Kind: kind, ObservedAt: p.Times[i]}
	if i < len(p.Values) {
		record.Payload = p.Values[i]
	}
	for _, pred := range preds {
		if pred.CoversRecord(org, p.Projects[i], record) {
			return true
		}
	}
	return false
}

// writeDeletions is the pre-commit twin of the ordered rejection: it consults
// the control view (immediate after Begin) and every local tombstone and fails
// closed when the view cannot answer.
func (e *Engine) writeDeletions(ctx context.Context, b model.NormalizedBatch) error {
	preds, err := e.deletionPredicates(ctx, b.Org, []model.ID{b.Project})
	if err != nil {
		return err
	}
	for _, p := range preds {
		for _, record := range b.Records {
			if p.CoversRecord(b.Org, b.Project, record) {
				return model.Fail(model.Conflict)
			}
		}
	}
	return nil
}

func (e *Engine) writeBlobDeletions(ctx context.Context, m model.BlobManifest) error {
	preds, err := e.deletionPredicates(ctx, m.Org, []model.ID{m.Project})
	if err != nil {
		return err
	}
	for _, p := range preds {
		if p.CoversBlob(m) {
			return model.Fail(model.Conflict)
		}
	}
	return nil
}

// readBlobDeletions hides a deleted artifact root before any fragment is released.
func (e *Engine) readBlobDeletions(ctx context.Context, m model.BlobManifest) error {
	preds, err := e.readDeletions(ctx, m.Org, []model.ID{m.Project})
	if err != nil {
		return err
	}
	for _, p := range preds {
		if p.CoversBlob(m) {
			return model.Fail(model.NotFound)
		}
	}
	return nil
}

// RecordDeleteBarrier commits the tombstone of p in one data slot. It is
// idempotent per (slot, operation) and, being a barrier rather than intake, works
// while a restored engine is still gated.
func (e *Engine) RecordDeleteBarrier(ctx context.Context, slot uint16, p model.DeletePredicate) (model.Cursor, error) {
	if slot >= 64 {
		return model.Cursor{}, model.Fail(model.Invalid)
	}
	if err := p.Validate(); err != nil {
		return model.Cursor{}, err
	}
	cursor, committed, err := e.recordDeleteBarrier(ctx, slot, p)
	if err == nil && committed {
		e.noteDeletion()
	}
	return cursor, err
}

func (e *Engine) recordDeleteBarrier(ctx context.Context, slot uint16, p model.DeletePredicate) (model.Cursor, bool, error) {
	e.proposalMu.Lock()
	defer e.proposalMu.Unlock()
	if e.repl == nil {
		return model.Cursor{}, false, model.Fail(model.Unavailable)
	}
	if _, err := e.repl.groups[slot].ReadIndex(ctx); err != nil {
		return model.Cursor{}, false, storageReplicaFault(err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return model.Cursor{}, false, model.Fail(model.Unavailable)
	}
	if ctx.Err() != nil {
		return model.Cursor{}, false, model.Fail(model.Cancelled)
	}
	var existing *model.DeleteBarrier
	if err := e.db.View(func(tx *bolt.Tx) error {
		barriers, err := tombstonesWithPrefix(tx, tombstoneKey(slot, p.Operation))
		if err != nil {
			return err
		}
		if len(barriers) == 1 {
			existing = &barriers[0]
		}
		return nil
	}); err != nil {
		return model.Cursor{}, false, err
	}
	if existing != nil {
		if existing.Predicate.Digest() != p.Digest() {
			return model.Cursor{}, false, model.Fail(model.Conflict)
		}
		return existing.Cursor, false, nil
	}
	cursor := model.Cursor{Group: e.group(slot), Index: model.Uint64(e.indexes[slot] + 1)}
	entry := walEntry{Type: "delete_barrier", DeleteBarrier: &model.DeleteBarrier{Predicate: p, Cursor: cursor}}
	if err := e.commit(slot, uint64(cursor.Index), entry); err != nil {
		return model.Cursor{}, false, err
	}
	return cursor, true, nil
}

// DeleteBarriers lists the locally applied tombstones ordered by (slot, operation).
func (e *Engine) DeleteBarriers(ctx context.Context) ([]model.DeleteBarrier, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return nil, model.Fail(model.Unavailable)
	}
	if ctx.Err() != nil {
		return nil, model.Fail(model.Cancelled)
	}
	var out []model.DeleteBarrier
	err := e.db.View(func(tx *bolt.Tx) error {
		var err error
		out, err = tombstonesWithPrefix(tx, nil)
		return err
	})
	return out, err
}

// ---- Backups: a deletion invalidates evidence a running backup pinned --------------

func (e *Engine) trackBackup(b *Backup) {
	e.tomb.mu.Lock()
	defer e.tomb.mu.Unlock()
	if e.tomb.backups == nil {
		e.tomb.backups = map[*Backup]struct{}{}
	}
	e.tomb.backups[b] = struct{}{}
}

func (e *Engine) untrackBackup(b *Backup) {
	e.tomb.mu.Lock()
	defer e.tomb.mu.Unlock()
	delete(e.tomb.backups, b)
}

// noteDeletion aborts every in-progress installation backup. It must not run
// with e.mu or a group lock held: Backup.Abort releases journal pins.
func (e *Engine) noteDeletion() {
	e.tomb.mu.Lock()
	backups := make([]*Backup, 0, len(e.tomb.backups))
	for b := range e.tomb.backups {
		backups = append(backups, b)
	}
	e.tomb.mu.Unlock()
	for _, b := range backups {
		b.NoteDeletion()
	}
}

// ---- Restore gate ---------------------------------------------------------------------

func (e *Engine) writeDeletionGate(digest model.Hash) error {
	path := filepath.Join(e.dir, deletionPendingFile)
	if err := os.WriteFile(path, []byte(digest.String()), 0600); err != nil {
		return err
	}
	if err := durablefs.SyncFileAndDir(path); err != nil {
		return err
	}
	e.tomb.gate.Store(true)
	return nil
}

func (e *Engine) loadDeletionGate() error {
	if _, err := os.Stat(filepath.Join(e.dir, deletionPendingFile)); err == nil {
		e.tomb.gate.Store(true)
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ApplyDeletionLedger re-establishes every deletion a restored backup predates:
// the ledger proves which tombstones exist (digests) and the predicates carry
// their content. Each tombstone is committed as a barrier in all 64 slots; only
// then is the applied generation persisted and the restore gate lifted.
func (e *Engine) ApplyDeletionLedger(ctx context.Context, ledger replica.Ledger, tombstones []model.DeletePredicate) error {
	if len(tombstones) != len(ledger.Entries) || ledger.Generation < uint64(len(tombstones)) {
		return model.Fail(model.Corrupt)
	}
	operations := map[model.ID]bool{}
	for i, p := range tombstones {
		if ledger.Entries[i].Index != uint64(i)+1 || ledger.Entries[i].Hash != p.Digest() {
			return model.Fail(model.Corrupt)
		}
		if err := p.Validate(); err != nil {
			return err
		}
		if operations[p.Operation] {
			return model.Fail(model.Invalid)
		}
		operations[p.Operation] = true
	}
	var applied uint64
	if err := e.db.View(func(tx *bolt.Tx) error {
		if raw := tx.Bucket([]byte("meta")).Get([]byte(deletionGenerationK)); len(raw) == 8 {
			applied = binary.BigEndian.Uint64(raw)
		}
		return nil
	}); err != nil {
		return err
	}
	if ledger.Generation < applied {
		return model.Fail(model.Stale)
	}
	for slot := uint16(0); slot < 64; slot++ {
		if err := e.trip("tombstone_slot"); err != nil {
			return err
		}
		for _, p := range tombstones {
			if _, err := e.RecordDeleteBarrier(ctx, slot, p); err != nil {
				return err
			}
		}
	}
	if err := e.db.Update(func(tx *bolt.Tx) error {
		var raw [8]byte
		binary.BigEndian.PutUint64(raw[:], ledger.Generation)
		return tx.Bucket([]byte("meta")).Put([]byte(deletionGenerationK), raw[:])
	}); err != nil {
		return err
	}
	if err := durablefs.Remove(filepath.Join(e.dir, deletionPendingFile)); err != nil {
		return err
	}
	e.tomb.gate.Store(false)
	return nil
}
