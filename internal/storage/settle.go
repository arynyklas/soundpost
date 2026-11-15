// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// SettleCandidates lists the sealed windows of every data group whose consumed reservations control
// may fold into a settled window (control.Store.SettleAdmissions): full windows that carry batches
// and no redacted batch, with the digest of the reservations their batches consumed. A window the
// engine has not derived yet is derived here and persisted (one pass over its commands, the same
// work the next snapshot cut would do).
func (e *Engine) SettleCandidates(ctx context.Context) ([]model.SettleCandidate, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.repl == nil || e.closed || e.failed {
		return nil, model.Fail(model.Unavailable)
	}
	var out []model.SettleCandidate
	for slot := range uint16(64) {
		if err := ctx.Err(); err != nil {
			return nil, model.Fail(model.Cancelled)
		}
		table, err := e.windowTableLocked(slot, true)
		if err != nil {
			return nil, err
		}
		for _, w := range table {
			if w.Count != snapshotWindow || w.Batches == 0 || w.Redacted != 0 {
				continue
			}
			out = append(out, model.SettleCandidate{Group: e.group(slot), N: w.N, Span: snapshotWindow, Batches: w.Batches, Charge: w.Charge})
		}
	}
	return out, nil
}

// AdmittedBatch reports whether the data holds the batch the reservation names and returns the
// receipt it stored for it. Control asks it for a retry whose reservation it settled (no row
// answers it any more); the answer is read after the slot's read fence, like a receipt lookup.
func (e *Engine) AdmittedBatch(ctx context.Context, r model.AdmissionReservation) (model.Receipt, bool, error) {
	if err := e.replicaBeforeWrite(ctx, r.Slot); err != nil {
		return model.Receipt{}, false, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return model.Receipt{}, false, model.Fail(model.Unavailable)
	}
	var out model.Receipt
	found := false
	err := e.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte("receipts")).Get(batchKey(r.Org, r.Project, r.Source, r.Producer, r.Slot, r.Batch))
		if raw == nil {
			return nil
		}
		if json.Unmarshal(raw, &out) != nil {
			return model.Fail(model.Corrupt)
		}
		found = true
		return nil
	})
	return out, found, err
}
