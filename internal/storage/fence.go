// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	bolt "go.etcd.io/bbolt"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"strconv"
)

func (e *Engine) FenceSource(ctx context.Context, f model.SourceFence) ([]model.Cursor, error) {
	e.proposalMu.Lock()
	defer e.proposalMu.Unlock()
	if _, _, err := e.replicaReadFence(ctx, nil, false); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed || e.closed || f.Operation == (model.ID{}) || f.Source == (model.ID{}) || f.Phase != "fencing" {
		return nil, model.Fail(model.Unavailable)
	}
	out := make([]model.Cursor, 0, 64)
	for slot := uint16(0); slot < 64; slot++ {
		if ctx.Err() != nil {
			return nil, model.Fail(model.Cancelled)
		}
		var previous model.SourceFence
		err := e.db.View(func(tx *bolt.Tx) error {
			raw := tx.Bucket([]byte("fences")).Get([]byte(f.Source.String() + ":" + strconv.Itoa(int(slot))))
			if raw == nil {
				return nil
			}
			return json.Unmarshal(raw, &previous)
		})
		if err != nil {
			return nil, err
		}
		if previous.Operation == f.Operation && len(previous.Barriers) == 1 {
			out = append(out, previous.Barriers[0])
			continue
		}
		if previous.Epoch > f.Epoch {
			return nil, model.Fail(model.Stale)
		}
		cursor := model.Cursor{Group: e.group(slot), Index: model.Uint64(e.indexes[slot] + 1)}
		entryFence := f
		entryFence.Barriers = []model.Cursor{cursor}
		if err = e.commit(slot, uint64(cursor.Index), walEntry{Type: "fence", Fence: &entryFence}); err != nil {
			return nil, err
		}
		out = append(out, cursor)
	}
	return out, nil
}

// Cancel first commits a permanent no-use fence while holding the same owner
// order lock as Append. Receipt absence is checked in that order, never by TTL.
func (e *Engine) Cancel(ctx context.Context, scope auth.Scope, requested model.AdmissionReservation) (model.CancelReservation, error) {
	e.proposalMu.Lock()
	defer e.proposalMu.Unlock()
	if _, err := scope.Reservation(ctx, requested.ID); err != nil {
		return model.CancelReservation{}, err
	}
	if err := e.replicaBeforeWrite(ctx, requested.Slot); err != nil {
		return model.CancelReservation{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed || requested.Slot >= 64 {
		return model.CancelReservation{}, model.Fail(model.Unavailable)
	}
	if err := e.validator.Revalidate(ctx, scope); err != nil {
		return model.CancelReservation{}, err
	}
	r, err := scope.Reservation(ctx, requested.ID)
	if err != nil {
		return model.CancelReservation{}, err
	}
	if r.Hash != requested.Hash || r.State == "consumed" {
		return model.CancelReservation{}, model.Fail(model.Conflict)
	}
	var old model.CancelReservation
	err = e.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte("receipts")).Get(batchKey(r.Org, r.Project, r.Source, r.Producer, r.Slot, r.Batch)) != nil {
			return model.Fail(model.Conflict)
		}
		raw := tx.Bucket([]byte("cancelled")).Get([]byte(r.ID.String()))
		if raw != nil {
			return json.Unmarshal(raw, &old)
		}
		return nil
	})
	if err != nil {
		return model.CancelReservation{}, err
	}
	if old.ReservationID != (model.ID{}) {
		if old.Hash != r.Hash {
			return model.CancelReservation{}, model.Fail(model.Conflict)
		}
		return old, nil
	}
	c := model.CancelReservation{ReservationID: r.ID, OwnerGroup: e.group(r.Slot), Fence: model.Cursor{Group: e.group(r.Slot), Index: model.Uint64(e.indexes[r.Slot] + 1)}, Hash: r.Hash}
	if err = e.commit(r.Slot, uint64(c.Fence.Index), walEntry{Type: "cancel", Cancel: &c}); err != nil {
		return model.CancelReservation{}, err
	}
	return c, nil
}
func (e *Engine) VerifyCancellation(ctx context.Context, c model.CancelReservation) error {
	if err := e.replicaBeforeCursor(ctx, c.Fence); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if ctx.Err() != nil || e.closed || e.failed {
		return model.Fail(model.Unavailable)
	}
	return e.db.View(func(tx *bolt.Tx) error {
		var old model.CancelReservation
		raw := tx.Bucket([]byte("cancelled")).Get([]byte(c.ReservationID.String()))
		if raw == nil || json.Unmarshal(raw, &old) != nil || old != c {
			return model.Fail(model.Forbidden)
		}
		if e.repl != nil {
			var proof struct {
				Group       model.ID     `json:"group"`
				Reservation model.ID     `json:"reservation"`
				Term        model.Uint64 `json:"term"`
			}
			var slot uint16
			found := false
			for i := range uint16(64) {
				if e.group(i) == c.OwnerGroup {
					slot = i
					found = true
					break
				}
			}
			if !found {
				return model.Fail(model.Forbidden)
			}
			meta := tx.Bucket([]byte("replica_data"))
			rawProof := meta.Get(metaKey(slot, "cancel-proof:"+c.ReservationID.String()))
			legacy := getUint(meta, metaKey(slot, "legacy"))
			if len(rawProof) == 0 && uint64(c.Fence.Index) <= legacy {
				// Only a fully imported immutable local prefix gets this proof:
				// inspect its entire committed history, never receipt absence.
				for index := uint64(1); index <= legacy; index++ {
					var entry walEntry
					if json.Unmarshal(tx.Bucket([]byte("replica_commands")).Get(commandKey(slot, index)), &entry) != nil {
						return model.Fail(model.Corrupt)
					}
					if entry.Batch != nil && entry.Batch.Reservation.ID == c.ReservationID {
						return model.Fail(model.Conflict)
					}
				}
			} else if json.Unmarshal(rawProof, &proof) != nil || proof.Group != c.OwnerGroup || proof.Reservation != c.ReservationID || proof.Term == 0 {
				return model.Fail(model.Forbidden)
			}
			physical := getUint(meta, metaKey(slot, "logical:"+strconv.FormatUint(uint64(c.Fence.Index), 10)))
			if physical == 0 || physical > getUint(meta, metaKey(slot, "physical")) {
				return model.Fail(model.Forbidden)
			}
		}
		return nil
	})
}
