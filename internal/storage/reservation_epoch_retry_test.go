// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// A batch refused after its reservation was charged (capacity pressure) keeps a
// "reserved" row bound to the old policy epoch. Its legitimate retry, minted
// under the advanced epoch, must reuse that charge (no double charge, no refund)
// instead of a permanent 403.
func TestCapacityRefusedBatchRetriesAfterPolicyEpochChange(t *testing.T) {
	store, a, c, d := fixture(t)
	ctx := context.Background()
	_, first := normalized(t, store, a, c, d) // charged, never appended: refused for capacity
	var charged model.Uint64
	store.View(ctx, func(st control.State) error { charged = st.Quotas["org:"+d.Org.String()].Bytes; return nil })
	if err := store.Update(ctx, func(st *control.State) error {
		o := st.Orgs[d.Org.String()]
		o.Epoch++
		st.Orgs[d.Org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	scope, err := a.SourceScope(ctx, c, false)
	if err != nil {
		t.Fatal(err)
	}
	retry := first
	retry.PolicyEpoch = model.Uint64(scope.PolicyEpoch())
	retry.Reservation = model.AdmissionReservation{}
	if retry.PolicyEpoch == first.PolicyEpoch {
		t.Fatal("fixture must advance the epoch")
	}
	if retry.Reservation, err = store.ReserveAdmission(ctx, scope, retry); err != nil {
		t.Fatal(err)
	}
	engine, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	r, err := engine.Append(ctx, scope, retry)
	if err != nil {
		t.Fatalf("legitimate retry after epoch change refused: %v", err)
	}
	if retry.Reservation.ID != first.Reservation.ID {
		t.Fatal("retry must reuse the original charge")
	}
	store.View(ctx, func(st control.State) error {
		if got := st.Quotas["org:"+d.Org.String()].Bytes; got != charged {
			t.Fatalf("quota changed %d -> %d", charged, got)
		}
		return nil
	})
	// ACKed batch retried again is idempotent.
	again, err := engine.Append(ctx, scope, retry)
	if err != nil || again.Cursor != r.Cursor || again.Hash != r.Hash {
		t.Fatalf("idempotent retry: %v", err)
	}
}

// A retired project is still refused at reservation time.
func TestRetiredProjectStillRefusedAfterEpochChange(t *testing.T) {
	store, a, c, d := fixture(t)
	ctx := context.Background()
	scope, b := normalized(t, store, a, c, d)
	if err := store.Update(ctx, func(st *control.State) error {
		o := st.Orgs[d.Org.String()]
		o.Epoch++
		st.Orgs[d.Org.String()] = o
		if st.RetiredProjects == nil {
			st.RetiredProjects = map[string]model.ID{}
		}
		st.RetiredProjects[d.Project.String()] = d.Org
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b.Reservation = model.AdmissionReservation{}
	if _, err := store.ReserveAdmission(ctx, scope, b); err == nil {
		t.Fatal("retired project/old-epoch scope accepted")
	}
}
