// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"sort"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

// DeletionLedger lets the control group take and truncate to verified snapshots.
// Its tombstone-class facts are the source fences and operation history: both
// are permanent and both must survive any snapshot, or an old replica could
// restore a source that was already closed. Entries are numbered by their
// position in key order (never beyond the revision, since each is created by a
// committed command); the generation is the number of retained operations and
// only grows.
func (m *replicatedControl) DeletionLedger() (replica.Ledger, error) {
	var st State
	if err := m.store.db.View(func(tx *bolt.Tx) error {
		if json.Unmarshal(tx.Bucket([]byte("control")).Get([]byte("state")), &st) != nil {
			return model.Fail(model.Corrupt)
		}
		return nil
	}); err != nil {
		return replica.Ledger{}, err
	}
	ledger := replica.Ledger{Version: 1, Group: st.Installation, Generation: uint64(len(st.SourceOperations) + len(st.Deletions)), Entries: []replica.LedgerEntry{}}
	add := func(kind string, values map[string]model.SourceFence) error {
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			raw, err := json.Marshal(struct {
				Key   string            `json:"key"`
				Fence model.SourceFence `json:"fence"`
			}{key, values[key]})
			if err != nil {
				return err
			}
			ledger.Entries = append(ledger.Entries, replica.LedgerEntry{Index: uint64(len(ledger.Entries) + 1), Kind: kind, Hash: model.HashCanonical(raw)})
		}
		return nil
	}
	if err := add("source_fence", st.SourceFences); err != nil {
		return replica.Ledger{}, err
	}
	if err := add("source_operation", st.SourceOperations); err != nil {
		return replica.Ledger{}, err
	}
	// Deletion operations (any phase) are permanent tombstones as well.
	keys := make([]string, 0, len(st.Deletions))
	for key := range st.Deletions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		raw, err := json.Marshal(struct {
			Key       string                  `json:"key"`
			Operation model.DeletionOperation `json:"operation"`
		}{key, st.Deletions[key]})
		if err != nil {
			return replica.Ledger{}, err
		}
		ledger.Entries = append(ledger.Entries, replica.LedgerEntry{Index: uint64(len(ledger.Entries) + 1), Kind: "deletion_operation", Hash: model.HashCanonical(raw)})
	}
	if uint64(len(ledger.Entries)) > uint64(st.Revision) {
		return replica.Ledger{}, model.Fail(model.Corrupt)
	}
	return ledger, nil
}
