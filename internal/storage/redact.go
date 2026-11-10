// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

// Physical erasure rewrites the stored command (a "batch_redacted" that keeps the original hash,
// the receipt and the kept records) and everything derived from it. The replication layer keeps
// its own copy of every committed command, payload included: the retry table that every snapshot
// serializes, the journal and the backup pin archives. Group.RedactCompleted replaces those by
// the same redacted command, so a deleted record's bytes exist nowhere in the node once the
// snapshot and journal that were cut before the erasure are replaced (see Residual* below).
//
// The stored redacted command is the durable authority. A slot is reconciled by reading every
// redacted command of the slot back out of replica_commands and handing them to the group, which
// is idempotent, so nothing about the redaction has to be remembered across a crash, a restart or
// a snapshot installation: the erase pass, every snapshot cut and every open repeat it.
//
//   - erase: after the erasing transaction committed, the slot is marked and reconciled at the
//     end of the pass;
//   - snapshot cut (CreateSnapshots): marked slots are reconciled first, so no snapshot is cut
//     with the retry table of a command the machine already redacted;
//   - open (EnableReplication): every slot is reconciled, which also covers an erasure whose
//     redaction was cut short by a crash and a node that applied or installed redacted commands
//     whose retry table came from an older cut.
type redactState struct {
	mu    sync.Mutex // serializes reconciliation: a stale replacement never overtakes a newer one
	dirty [64]atomic.Bool
	// epoch counts the erasures and installations that changed a slot's stored commands;
	// legacyClean[slot] is epoch+1 of the last time the slot's legacy WAL was seen to hold none
	// of the redacted commands' original bytes, so the (file-sized) check is not repeated.
	epoch       [64]atomic.Uint64
	legacyClean [64]atomic.Uint64
}

const redactFloorKey = "redact_floor"

// markRedact notes that slot's stored commands were redacted after the transaction committed.
func (e *Engine) markRedact(slot uint16) {
	e.redact.epoch[slot].Add(1)
	e.redact.dirty[slot].Store(true)
}

// stampRedactFloorTx records, atomically with an erasure, the physical index the slot had applied
// when its command was redacted. Snapshots and journal heads cut at or before it still carry the
// original payload (ResidualStores).
func stampRedactFloorTx(tx *bolt.Tx, slot uint16) error {
	meta := tx.Bucket([]byte("replica_data"))
	applied := getUint(meta, metaKey(slot, "physical"))
	if applied <= getUint(meta, metaKey(slot, redactFloorKey)) {
		return nil
	}
	return putUint(meta, metaKey(slot, redactFloorKey), applied)
}

// isRedactedCommand reports whether a stored command is a redacted one, without decoding it.
func isRedactedCommand(raw []byte) bool {
	return bytes.HasPrefix(raw, []byte(`{"type":"batch_redacted"`)) || bytes.HasPrefix(raw, []byte(`{"type":"artifact_redacted"`))
}

// redactReplica reconciles every marked slot's replication layer with its stored redacted
// commands. It never holds the engine mutex: Group.RedactCompleted takes the group lock, and the
// lock order is group lock before engine mutex.
func (e *Engine) redactReplica(ctx context.Context) error {
	if e.repl == nil {
		return nil
	}
	e.redact.mu.Lock()
	defer e.redact.mu.Unlock()
	for slot := range uint16(64) {
		if !e.redact.dirty[slot].Load() {
			continue
		}
		if err := ctx.Err(); err != nil {
			return model.Fail(model.Cancelled)
		}
		// Cleared before the scan: an erasure that commits after the scan marks the slot again.
		e.redact.dirty[slot].Store(false)
		if err := e.redactSlot(ctx, slot); err != nil {
			e.redact.dirty[slot].Store(true)
			return err
		}
	}
	return nil
}

func (e *Engine) redactSlot(ctx context.Context, slot uint16) error {
	requests, err := e.redactedCommands(slot)
	if err != nil {
		return err
	}
	if len(requests) == 0 {
		return nil
	}
	if err = e.trip("redact_replica"); err != nil {
		return err
	}
	if _, err = e.repl.groups[slot].RedactCompleted(ctx, requests); err != nil {
		return storageReplicaFault(err)
	}
	// The pre-replication WAL of an upgraded node holds the same commands: it is no longer an
	// authority once the history is imported, and must not keep the erased bytes either.
	return e.redactLegacyWAL(slot, requests)
}

// redactedCommands reads every redacted command of the slot back out of replica_commands: the
// durable authority every redaction is derived from.
func (e *Engine) redactedCommands(slot uint16) ([]replica.Redaction, error) {
	var requests []replica.Redaction
	err := e.db.View(func(tx *bolt.Tx) error {
		commands := tx.Bucket([]byte("replica_commands"))
		if commands == nil {
			return model.Fail(model.Corrupt)
		}
		cursor := commands.Cursor()
		for k, v := cursor.Seek(commandKey(slot, 0)); k != nil && len(k) == 10 && binary.BigEndian.Uint16(k[:2]) == slot; k, v = cursor.Next() {
			if isRedactedCommand(v) {
				requests = append(requests, replica.Redaction{ApplicationIndex: binary.BigEndian.Uint64(k[2:]), Replacement: bytes.Clone(v)})
			}
		}
		return nil
	})
	return requests, err
}

// Residual store names. ResidualStores reports a name only while the store can still hold a copy
// of an erased record.
const (
	// ResidualRaftCompletedEntries: a redaction is owed to the replication layer's retry table
	// (an erasure committed that the group has not yet been told about).
	ResidualRaftCompletedEntries = "raft_completed_entries"
	// ResidualRaftJournal: the Raft journal still begins at, or retains entries from, a cut
	// taken before the erasure.
	ResidualRaftJournal = replica.ResidueJournal
	// ResidualRaftSnapshots: a snapshot directory cut before the erasure still exists.
	ResidualRaftSnapshots = replica.ResidueSnapshots
)

// ResidualStores names the local stores that can still hold a copy of erased telemetry right now.
// It is measured, not declared: every erasure stamps the physical index its slot had applied, and
// a store is reported while it was cut at or before that index. The replication layer's journal
// head and every snapshot directory are sealed at their cut and are replaced only by a later cut
// followed by CompactJournals and DropSupersededSnapshots, so after a completed physical cleanup
// (checkpoint, cut, drop, compact) the answer is empty. It is empty, too, for an engine that was
// never erased from. A group that cannot be measured is reported as holding both. The
// pre-replication WAL of an upgraded node is measured directly: ResidualLegacyWAL while any of its
// entries differs from the redacted command stored for the same index.
func (e *Engine) ResidualStores() []string {
	if e.repl == nil {
		return nil
	}
	var floors, legacy [64]uint64
	if err := e.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		for slot := range uint16(64) {
			floors[slot] = getUint(meta, metaKey(slot, redactFloorKey))
			legacy[slot] = getUint(meta, metaKey(slot, "legacy"))
		}
		return nil
	}); err != nil {
		return []string{ResidualRaftJournal, ResidualRaftSnapshots, ResidualLegacyWAL}
	}
	set := map[string]bool{}
	for slot := range uint16(64) {
		if e.redact.dirty[slot].Load() {
			set[ResidualRaftCompletedEntries] = true
		}
		if legacy[slot] != 0 {
			// The pre-replication WAL is read, not trusted: it is reported while any of its
			// entries differs from the redacted command stored for the same index.
			if stale, err := e.legacyWALStale(slot, legacy[slot]); err != nil || stale {
				set[ResidualLegacyWAL] = true
			}
		}
		if floors[slot] == 0 {
			continue
		}
		residue, err := e.repl.groups[slot].Residue(floors[slot])
		if err != nil {
			set[ResidualRaftJournal], set[ResidualRaftSnapshots] = true, true
			continue
		}
		for _, name := range residue {
			set[name] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// JournalPinInfo is one durable journal pin of one group.
type JournalPinInfo struct {
	ID      string // the pin, unique across groups
	Group   string // the data group that holds it
	After   uint64 // application index the pin protects evidence beyond
	Created time.Time
	Expires time.Time
	// Orphaned: created by an earlier process; no backup in this process holds it.
	Orphaned bool
}

// JournalPins lists every durable journal pin of every group, after dropping those whose lease
// lapsed. A backup that dies between BeginBackup and Seal/Abort leaves such pins; this is how a
// backup driver finds them. internal/backup consumes it through its PinReaper interface; the
// adapter is wired where the engine and the backup service are both constructed:
//
//	type enginePins struct{ e *storage.Engine }
//	func (p enginePins) Pins() ([]backup.Pin, error) {
//		infos, err := p.e.JournalPins()
//		out := make([]backup.Pin, len(infos))
//		for i, in := range infos { out[i] = backup.Pin{ID: in.ID, Group: in.Group} }
//		return out, err
//	}
//	func (p enginePins) DropPin(id string) error { return p.e.DropJournalPin(id) }
func (e *Engine) JournalPins() ([]JournalPinInfo, error) {
	if e.repl == nil {
		return nil, model.Fail(model.Unavailable)
	}
	var out []JournalPinInfo
	for slot, group := range e.repl.groups {
		pins, err := group.Pins()
		if err != nil {
			return nil, storageReplicaFault(err)
		}
		for _, p := range pins {
			out = append(out, JournalPinInfo{ID: p.ID.String(), Group: e.group(uint16(slot)).String(), After: p.After, Created: p.Created, Expires: p.Expires, Orphaned: p.Orphaned})
		}
	}
	return out, nil
}

// DropJournalPin drops the pin with that ID from whichever group holds it. A pin that does not
// exist is not an error (a reaper retries). A backup that still holds the pin fails closed.
func (e *Engine) DropJournalPin(id string) error {
	if e.repl == nil {
		return model.Fail(model.Unavailable)
	}
	pin, err := model.ParseID(id)
	if err != nil {
		return model.Fail(model.Invalid)
	}
	for _, group := range e.repl.groups {
		if err = group.DropPin(pin); err != nil {
			return storageReplicaFault(err)
		}
	}
	return nil
}
