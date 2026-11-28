// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

// A batch the machine rejects at apply (Apply answers replica.ErrConflict) is stored as a `rejected`
// stub (walEntry{Type: "rejected", Rejection: id}) at its index, while the pinned journal the replay
// certificate is built from still holds the original batch. The stored form and the journal form of the
// same command are different bytes, so the evidence digests must still agree or the seal of a
// perfectly good cut (a rejection inside (H, D]) answers `corrupt` the way the proposer attribution
// did (TestBackupSealsACutHoldingTheVotersOwnErasureStatements).
//
// The rejection is made at apply and not before: a cancellation marker for the batch's reservation
// is in the slot's store (what a cancellation ordered ahead of the batch leaves), which the apply
// checks and the proposal-time validation (validateOrdered) does not.
func TestBackupSealsACutHoldingARejectedBatchStub(t *testing.T) {
	store, a, c, d := fixture(t)
	engine := openDeleteEngine(t, t.TempDir(), a, store)
	ctx := context.Background()
	_, covered := metricBatchAt(t, store, a, c, d, 7)
	slot := covered.RouteSlot
	backup, err := engine.BeginBackup(ctx, controlCut(t, engine, store))
	if err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	logical := engine.indexes[slot] + 1
	marker, err := json.Marshal(model.CancelReservation{ReservationID: covered.Reservation.ID, OwnerGroup: engine.group(slot), Fence: model.Cursor{Group: engine.group(slot), Index: model.Uint64(logical)}, Hash: covered.Reservation.Hash})
	if err == nil {
		err = engine.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte("cancelled")).Put([]byte(covered.Reservation.ID.String()), marker)
		})
	}
	receipt := model.Receipt{Version: 1, BatchID: covered.ID, Hash: covered.Hash, Cursor: model.Cursor{Group: engine.group(slot), Index: model.Uint64(logical)}, SignalDeadlines: covered.Deadlines, DedupUntil: 100, RetainUntil: 100}
	payload, encodeErr := engine.encodeProposal(walEntry{Type: "batch", Batch: &covered, Receipt: &receipt})
	group := engine.repl.groups[slot]
	engine.mu.Unlock()
	if err != nil || encodeErr != nil {
		t.Fatal(err, encodeErr)
	}
	reservation := covered.Reservation.ID
	if _, err = group.Propose(ctx, replica.Entry{ID: model.NewID(), Kind: replica.Data, Payload: payload, ReservationID: &reservation, ApplicationIndex: logical}); !errors.Is(err, replica.ErrConflict) && faultCode(err) != model.Conflict {
		t.Fatalf("fixture invalid: the batch was not rejected at apply: %v", err)
	}
	engine.mu.Lock()
	var stored walEntry
	err = engine.db.View(func(tx *bolt.Tx) error {
		return json.Unmarshal(commandAt(tx.Bucket([]byte("replica_commands")), commandKey(slot, logical)), &stored)
	})
	engine.mu.Unlock()
	if err != nil || stored.Type != "rejected" || stored.Batch != nil {
		t.Fatalf("fixture invalid: the stored command %d is %+v (%v), want the rejected stub", logical, stored, err)
	}
	sealed, err := backup.Seal(ctx, nil)
	if err != nil {
		t.Fatalf("the seal of a cut that holds a rejected stub failed: %v", err)
	}
	var replayed uint64
	for _, in := range sealed.Bundle.Replay.Intervals {
		if in.Group == engine.group(slot) && in.Mode == "replay" {
			replayed += uint64(in.Count)
		}
	}
	if replayed == 0 {
		t.Fatal("fixture invalid: the certificate covers nothing of the rejected batch's slot after H")
	}
	if err = verifyReplayAgainstSnapshots(sealed.Bundle, sealed.Snapshots); err != nil {
		t.Fatalf("the sealed bundle does not verify against its own snapshots: %v", err)
	}
}
