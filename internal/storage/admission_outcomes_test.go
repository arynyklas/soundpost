// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// TestAdmissionOutcomesForAnswersOnlyWhatIsAsked: the durable outcome of a batch is looked up by its
// reservation, one read fence and a lookup per ID. The outcome is the cursor of the receipt the append
// returned; an ID the data holds no outcome for gets none.
func TestAdmissionOutcomesForAnswersOnlyWhatIsAsked(t *testing.T) {
	store, service, cred, desc := fixture(t)
	e, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindAdmissionOwner(e); err != nil {
		t.Fatal(err)
	}
	const batches = 6
	var ids []model.ID
	cursors := map[model.ID]model.Cursor{}
	for i := range batches {
		scope, b := settleBatch(t, store, service, cred, desc, model.NewID(), model.UnixNano(1+i), "outcomes_for_series")
		receipt, err := e.Append(context.Background(), scope, b)
		if err != nil {
			t.Fatal("append:", err)
		}
		ids = append(ids, b.Reservation.ID)
		cursors[b.Reservation.ID] = receipt.Cursor
	}
	asked := []model.ID{ids[1], model.NewID(), ids[4]}
	got, err := e.AdmissionOutcomesFor(context.Background(), asked)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("outcomes for 2 known reservations and an unknown one: %d, want 2", len(got))
	}
	for i, id := range []model.ID{ids[1], ids[4]} {
		if got[i].ReservationID != id || got[i].Cursor != cursors[id] {
			t.Errorf("outcome %d is %+v, want reservation %s at cursor %+v", i, got[i], id, cursors[id])
		}
	}
	if none, err := e.AdmissionOutcomesFor(context.Background(), nil); err != nil || len(none) != 0 {
		t.Errorf("outcomes for no reservation: %v, %v", none, err)
	}
	all, err := e.AdmissionOutcomes(context.Background())
	if err != nil || len(all) != batches {
		t.Errorf("AdmissionOutcomes held %d outcomes (%v), want %d", len(all), err, batches)
	}
}
