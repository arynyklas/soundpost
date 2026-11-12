// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"sort"
	"strconv"
	"strings"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/model"
)

// Physical erasure of a deletion is per voter: every voter holds its own apply.db, segments and
// Raft journal, and a voter erases the bytes only from its own copy (the tombstone every voter
// applied, plus the completed operation in the control state, tell its retention worker what
// to erase). The control state's PhysicalAt is one cluster-wide fact recorded by whichever
// voter finished first, so it cannot say that THIS voter, or any other, is clean. Two things
// close that:
//
//   - a durable node-local marker per operation, set after this voter erased, scrubbed and cut
//     its own journal and snapshots (MarkErased / ErasedLocally): a voter whose marker is missing
//     still owes the erasure and its worker runs it even though PhysicalAt is already set;
//   - a replicated acknowledgement (type "erase_ack", slot 0) each voter proposes once its marker
//     is set and its own stores measure clean (AckErasure). ErasureResidual names
//     ResidualApplyDB for an operation until this voter AND every member of the committed
//     configuration has an acknowledgement for it. A stopped or lagging voter has none, so the
//     receipt keeps naming the data store until it catches up, erases and acknowledges.
const (
	// ResidualApplyDB names the data stores (apply.db, its free pages, the segments) of a voter
	// that has not yet erased a completed deletion, or whose free pages still owe a scrub, as
	// seen from the answering node: it is also reported while any member of the group has not
	// acknowledged the operation.
	ResidualApplyDB = "data_apply_db"

	eraseAckSlot   uint16 = 0
	maxEraseAckOps        = 64
)

// eraseAck is the closed DTO of one voter's acknowledgement.
type eraseAck struct {
	Node       model.Uint64 `json:"node"`
	Identity   string       `json:"identity"`
	Operations []model.ID   `json:"operations"`
	Cursor     model.Cursor `json:"cursor"`
}

func (a *eraseAck) valid() bool {
	return a != nil && a.Node != 0 && a.Identity != "" && len(a.Operations) > 0 && len(a.Operations) <= maxEraseAckOps
}

func erasedKey(op model.ID) []byte { return metaKey(eraseAckSlot, "erased:"+op.String()) }
func eraseAckKey(op model.ID, node uint64, identity string) []byte {
	return metaKey(eraseAckSlot, "erase-ack:"+op.String()+":"+strconv.FormatUint(node, 10)+":"+identity)
}

// applyEraseAckTx records the acknowledgement. It is deterministic: the same entry on every
// voter writes the same keys.
func applyEraseAckTx(tx *bolt.Tx, slot uint16, entry walEntry) error {
	if slot != eraseAckSlot || !entry.EraseAck.valid() || entry.Batch != nil || entry.Receipt != nil {
		return model.Fail(model.Corrupt)
	}
	meta := tx.Bucket([]byte("replica_data"))
	if meta == nil {
		return model.Fail(model.Corrupt)
	}
	a := entry.EraseAck
	for _, op := range a.Operations {
		if err := meta.Put(eraseAckKey(op, uint64(a.Node), a.Identity), []byte{1}); err != nil {
			return err
		}
	}
	return nil
}

// ErasedLocally reports whether this voter finished erasing the operation from its own stores.
func (e *Engine) ErasedLocally(op model.ID) bool {
	found := false
	if err := e.db.View(func(tx *bolt.Tx) error {
		found = tx.Bucket([]byte("replica_data")).Get(erasedKey(op)) != nil
		return nil
	}); err != nil {
		return false
	}
	return found
}

// MarkErased records, durably and only on this voter, that it erased the operations from its
// own stores. The caller does so after the erase, the scrub and the journal cut succeeded.
func (e *Engine) MarkErased(ops []model.ID) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return model.Fail(model.Unavailable)
	}
	err := e.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		for _, op := range ops {
			if err := meta.Put(erasedKey(op), []byte{1}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return unavailableDB(err)
	}
	return nil
}

// selfMember names this voter in the committed configuration of the group that carries the
// acknowledgements.
func (e *Engine) selfMember() (node uint64, identity string, ok bool) {
	if e.repl == nil {
		return 0, "", false
	}
	st := e.repl.groups[eraseAckSlot].Status()
	for _, m := range st.Members.Nodes {
		if m.ID == st.ID {
			return m.ID, m.NodeIdentity, true
		}
	}
	return 0, "", false
}

// AckErasure proposes this voter's acknowledgement of every operation it has marked erased and
// has not yet acknowledged, provided its own stores measure clean right now (ResidualStores is
// empty: no owed scrub, no journal, snapshot or retry-table copy from before an erasure). It is
// a no-op when there is nothing to acknowledge, and returns the proposal's error otherwise (the
// retention worker retries on its next pass).
func (e *Engine) AckErasure(ctx context.Context) error {
	node, identity, ok := e.selfMember()
	if !ok {
		return nil
	}
	var owed []model.ID
	if err := e.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		prefix := metaKey(eraseAckSlot, "erased:")
		c := meta.Cursor()
		for k, _ := c.Seek(prefix); k != nil && strings.HasPrefix(string(k), string(prefix)); k, _ = c.Next() {
			op, err := model.ParseID(string(k[len(prefix):]))
			if err != nil {
				return model.Fail(model.Corrupt)
			}
			if meta.Get(eraseAckKey(op, node, identity)) == nil {
				owed = append(owed, op)
			}
		}
		return nil
	}); err != nil {
		return unavailableDB(err)
	}
	if len(owed) == 0 || len(e.ResidualStores()) > 0 {
		return nil
	}
	sort.Slice(owed, func(i, j int) bool { return owed[i].String() < owed[j].String() })
	if len(owed) > maxEraseAckOps {
		owed = owed[:maxEraseAckOps]
	}
	e.proposalMu.Lock()
	defer e.proposalMu.Unlock()
	if _, err := e.repl.groups[eraseAckSlot].ReadIndex(ctx); err != nil {
		return storageReplicaFault(err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return model.Fail(model.Unavailable)
	}
	cursor := model.Cursor{Group: e.group(eraseAckSlot), Index: model.Uint64(e.indexes[eraseAckSlot] + 1)}
	return e.commit(eraseAckSlot, uint64(cursor.Index), walEntry{Type: "erase_ack", EraseAck: &eraseAck{Node: model.Uint64(node), Identity: identity, Operations: owed, Cursor: cursor}})
}

// ErasureResidual is what a receipt for the operation must add to ResidualStores: ResidualApplyDB
// until this voter erased the operation itself and every member of the group's committed
// configuration acknowledged it. It reads local state only and never blocks on consensus; a
// configuration that cannot be read is reported as owed.
func (e *Engine) ErasureResidual(op model.ID) []string {
	if !e.ErasedLocally(op) {
		return []string{ResidualApplyDB}
	}
	if e.repl == nil {
		return nil
	}
	members := e.repl.groups[eraseAckSlot].Status().Members.Nodes
	if len(members) == 0 {
		return []string{ResidualApplyDB}
	}
	owed := false
	if err := e.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		for _, m := range members {
			if meta.Get(eraseAckKey(op, m.ID, m.NodeIdentity)) == nil {
				owed = true
			}
		}
		return nil
	}); err != nil || owed {
		return []string{ResidualApplyDB}
	}
	return nil
}
