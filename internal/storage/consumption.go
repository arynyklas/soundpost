// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

func (e *Engine) VerifyFinalization(ctx context.Context, r model.FinalizeAdmission) error {
	if err := e.replicaBeforeCursor(ctx, r.Cursor); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if ctx.Err() != nil || e.closed || e.failed {
		return model.Fail(model.Unavailable)
	}
	return e.db.View(func(tx *bolt.Tx) error {
		var consumed model.AdmissionReservation
		raw, err := tableGet(tx, tblConsumed, []byte(r.ReservationID.String()))
		if err != nil {
			return err
		}
		if raw == nil || json.Unmarshal(raw, &consumed) != nil || consumed.Cursor == nil || *consumed.Cursor != r.Cursor {
			return model.Fail(model.Forbidden)
		}
		return nil
	})
}

// putConsumed records the consumed reservation id of an acknowledged batch in the row store (a re-applied batch replaces it).
func putConsumed(rows *rowStore, id model.ID, raw []byte) error {
	key := []byte(id.String())
	if rows.Get(tblConsumed, key) != nil {
		return rows.Set(tblConsumed, key, raw)
	}
	return rows.Insert(tblConsumed, key, raw)
}
