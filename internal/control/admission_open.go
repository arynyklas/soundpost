// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The index of open reservations.
//
// A reservation is open from the moment control reserves a batch until the batch has an outcome (finalized
// with its cursor, or cancelled). The reconciliation of outcomes (ReconcileAdmissions) has one job: the
// batches whose outcome is in the data and whose finalize never reached control. It used to ask the data
// for every outcome it holds, a bucket that grows with every batch the installation ever took (150,000 rows
// four and a half minutes into the single-host load, decoded under the engine's lock every five seconds and
// then looked up one by one in control), so the work of each pass, and the time every append waited for the
// engine, grew with the history. The batches that can still be missing a finalize are the open ones, a few
// hundred at any moment, and the index lists exactly them.
//
// The index is a derived bucket of control.db, written in the transaction that writes the reservation row
// (ledgerTx.put, del, clear), so it is exactly as durable and as consistent as the row. It is not a member
// of the ledger: nothing digests, patches, snapshots or backs it up, and a file that has none, or whose
// ledger a build without it changed, rebuilds it from the table in one pass (ensureOpenIndex).

// reservationOpen says whether the stored JSON of a reservation row is one that is still reserved.
func reservationOpen(raw []byte) bool {
	var r struct {
		State string `json:"state"`
	}
	return json.Unmarshal(raw, &r) == nil && r.State == "reserved"
}

// openMark is the value of an index entry; the key is the reservation ID.
var openMark = []byte{1}

// noteOpen brings the index up to date with the write of the reservation row key: value is the new row, nil
// for a delete.
func (l *ledgerTx) noteOpen(key, value []byte) error {
	if l.open == nil {
		return nil
	}
	if value != nil && reservationOpen(value) {
		return l.open.Put(key, openMark)
	}
	if l.open.Get(key) == nil {
		return nil
	}
	return l.open.Delete(key)
}

// openIndexCurrent says whether the index of the file of ctrl belongs to its ledger.
func openIndexCurrent(ctrl *bolt.Bucket) bool {
	return bytes.Equal(ctrl.Get(ledgerOpenKey), ctrl.Get(ledgerAccKey))
}

// ensureOpenIndex makes the index of tx's file current: nothing when it is, a rebuild from the reservation
// table when the file has no index or the ledger moved without it.
func ensureOpenIndex(tx *bolt.Tx) error {
	ctrl := tx.Bucket([]byte("control"))
	if ctrl == nil {
		return model.Fail(model.Corrupt)
	}
	if tx.Bucket(openIndexBucket) != nil && openIndexCurrent(ctrl) {
		return nil
	}
	if tx.Bucket(openIndexBucket) != nil {
		if err := tx.DeleteBucket(openIndexBucket); err != nil {
			return err
		}
	}
	index, err := tx.CreateBucket(openIndexBucket)
	if err != nil {
		return err
	}
	l, err := openLedger(tx)
	if err != nil {
		return err
	}
	c := l.t[tableReservations].Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if reservationOpen(v) {
			if err = index.Put(bytes.Clone(k), openMark); err != nil {
				return err
			}
		}
	}
	if acc := ctrl.Get(ledgerAccKey); acc != nil {
		return ctrl.Put(ledgerOpenKey, bytes.Clone(acc))
	}
	return ctrl.Delete(ledgerOpenKey)
}

// eachOpen calls fn for every reservation that is still reserved, in the committed ledger of this
// transaction, until fn says stop. The index must be current (openIndexCurrent); a caller that finds it
// stale rebuilds it first.
func (l *ledgerTx) eachOpen(fn func(model.AdmissionReservation) bool) error {
	c := l.open.Cursor()
	for k, _ := c.First(); k != nil; k, _ = c.Next() {
		raw := l.t[tableReservations].Get(k)
		if raw == nil {
			return model.Fail(model.Corrupt)
		}
		var r model.AdmissionReservation
		if err := decodeValue(raw, &r); err != nil {
			return err
		}
		if !fn(r) {
			return nil
		}
	}
	return nil
}

// outcomesFor is the capability of an owner that answers for the reservations it is asked about.
type outcomesFor interface {
	AdmissionOutcomesFor(context.Context, []model.ID) ([]model.FinalizeAdmission, error)
}

// allOutcomes is the capability of an owner that can only give every outcome it holds.
type allOutcomes interface {
	AdmissionOutcomes(context.Context) ([]model.FinalizeAdmission, error)
}

// ownerOutcomes is the outcomes of the owner's data that reconciliation has to look at: those of the open
// reservations when the owner can answer for them, every outcome otherwise.
func (s *Store) ownerOutcomes(ctx context.Context, owner AdmissionProofs) ([]model.FinalizeAdmission, error) {
	if byID, ok := owner.(outcomesFor); ok {
		open, err := s.openReservations(ctx)
		if err != nil || len(open) == 0 {
			return nil, err
		}
		return byID.AdmissionOutcomesFor(ctx, open)
	}
	all, ok := owner.(allOutcomes)
	if !ok {
		return nil, model.Fail(model.Unavailable)
	}
	return all.AdmissionOutcomes(ctx)
}

// openReservations is the IDs of the reservations that are still reserved, after one linearizable read. A file
// whose index does not belong to its ledger has it rebuilt first (once).
func (s *Store) openReservations(ctx context.Context) ([]model.ID, error) {
	for attempt := 0; ; attempt++ {
		var ids []model.ID
		err := s.viewBooks(ctx, func(books admissionBooks) error {
			return books.eachOpen(func(r model.AdmissionReservation) bool {
				ids = append(ids, r.ID)
				return true
			})
		})
		if errors.Is(err, errOpenIndexStale) && attempt == 0 {
			if err = s.db.Update(ensureOpenIndex); err != nil {
				return nil, err
			}
			continue
		}
		return ids, err
	}
}
