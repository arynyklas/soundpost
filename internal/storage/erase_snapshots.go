// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/durablefs"
	"soundpost/internal/model"
)

// DropSupersededSnapshots removes every snapshot directory older than the selected one in every
// group and reports how many it removed.
//
// A Raft snapshot store keeps the selected snapshot plus the newest previous one, as a fallback if
// the selected one is damaged. After a deletion the previous one is the routine snapshot taken
// before it, complete with the pinned copy of every segment and the whole pre-erasure command
// history. Once a post-erasure snapshot has been cut and verified, nothing may keep the older ones.
//
// Only directories that sort before the selected one are touched, and the selection itself is
// read again for every group, so a snapshot cut concurrently (always newer than anything this
// removes) is never at risk. The trade-off is explicit: until the next cut, a group has no
// previous snapshot to fall back on.
func (e *Engine) DropSupersededSnapshots(ctx context.Context) (uint64, error) {
	if e.repl == nil {
		return 0, model.Fail(model.Unavailable)
	}
	var removed uint64
	for _, group := range e.repl.groups {
		if err := ctx.Err(); err != nil {
			return removed, model.Fail(model.Cancelled)
		}
		current, ok := group.Snapshots().Current()
		if !ok {
			continue // nothing selected, nothing is superseded
		}
		selected := current.Dir()
		root, keep := filepath.Dir(selected), filepath.Base(selected)
		if !strings.HasPrefix(keep, "snap-") {
			return removed, model.Fail(model.Corrupt)
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			return removed, err
		}
		dropped := false
		for _, entry := range entries {
			name := entry.Name()
			if !entry.IsDir() || !strings.HasPrefix(name, "snap-") || name >= keep {
				continue
			}
			if err = os.RemoveAll(filepath.Join(root, name)); err != nil {
				return removed, err
			}
			removed++
			dropped = true
		}
		if dropped {
			if err = durablefs.SyncDir(root); err != nil {
				return removed, err
			}
		}
	}
	return removed, nil
}

// CheckpointErasure advances the applied index of every group after an erasure by re-committing
// the barrier of an already-fenced deletion as a no-op entry (the tombstone row of a slot is kept
// from the first commit; a duplicate only occupies a log position).
//
// Snapshot cuts and journal compaction are keyed by the applied index: a cut at an index the group
// already has returns the retained snapshot unchanged, and compacting the journal against a
// snapshot at an index it already holds keeps the old snapshot inside the journal. Without a new
// entry after the erasure, a snapshot taken between a deletion's barrier and its erasure (a backup
// run, a deletion held back by a legal hold) therefore keeps the erased bytes, and so does the
// journal built on it, for as long as the group sees no other write. The checkpoint makes the
// next cut a new snapshot and the next compaction re-anchor the journal on it.
//
// p must be a deletion whose barrier already exists in every slot (a completed deletion); no
// tombstone is added and nothing is replayed differently on any voter.
func (e *Engine) CheckpointErasure(ctx context.Context, p model.DeletePredicate) error {
	if err := p.Validate(); err != nil {
		return err
	}
	for slot := range uint16(64) {
		if err := e.checkpointSlot(ctx, slot, p); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) checkpointSlot(ctx context.Context, slot uint16, p model.DeletePredicate) error {
	e.proposalMu.Lock()
	defer e.proposalMu.Unlock()
	if e.repl == nil {
		return model.Fail(model.Unavailable)
	}
	if _, err := e.repl.groups[slot].ReadIndex(ctx); err != nil {
		return storageReplicaFault(err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return model.Fail(model.Unavailable)
	}
	if ctx.Err() != nil {
		return model.Fail(model.Cancelled)
	}
	var existing []model.DeleteBarrier
	if err := e.db.View(func(tx *bolt.Tx) error {
		var err error
		existing, err = tombstonesWithPrefix(tx, tombstoneKey(slot, p.Operation))
		return err
	}); err != nil {
		return err
	}
	if len(existing) != 1 {
		return model.Fail(model.NotFound) // only a fenced deletion can be checkpointed
	}
	if existing[0].Predicate.Digest() != p.Digest() {
		return model.Fail(model.Conflict)
	}
	cursor := model.Cursor{Group: e.group(slot), Index: model.Uint64(e.indexes[slot] + 1)}
	return e.commit(slot, uint64(cursor.Index), walEntry{Type: "delete_barrier", DeleteBarrier: &model.DeleteBarrier{Predicate: p, Cursor: cursor}})
}

// ResidualRaftCompletedEntries names the replication layer's idempotence cache: every group
// keeps each committed command, original payload included, so a retried proposal answers with
// its original outcome, and writes that cache into every snapshot (envelope.json) and into the
// journal it is compacted onto (ready.wal). Erasure rewrites the stored commands and the
// machine state a snapshot carries, but the cache belongs to the replication layer and has no
// redaction.
const ResidualRaftCompletedEntries = "raft_completed_entries"

// ResidualStores names the local stores that still hold copies of erased telemetry after every
// erasure step in this package has run, because nothing in this package can reach them. It is a
// declaration, held to account by tests and by the deletion smoke, which search those files for
// erased bytes and require them to be found exactly where this says and nowhere else.
func (e *Engine) ResidualStores() []string {
	if e.repl == nil {
		return nil
	}
	return []string{ResidualRaftCompletedEntries}
}
