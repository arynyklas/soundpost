// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// advanceEpoch bumps the organization's policy epoch (what a deletion does) and
// returns the source scope minted under the new epoch.
func advanceEpoch(t *testing.T, store *control.Store, a *auth.Service, c auth.SourceCredential, org model.ID) auth.Scope {
	t.Helper()
	if err := store.Update(context.Background(), func(st *control.State) error {
		o := st.Orgs[org.String()]
		o.Epoch++
		st.Orgs[org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	scope, err := a.SourceScope(context.Background(), c, false)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func reservationRow(t *testing.T, store *control.Store, id model.ID) model.AdmissionReservation {
	t.Helper()
	var row model.AdmissionReservation
	if err := store.View(context.Background(), func(st control.State) error { row = st.Reservations[id.String()]; return nil }); err != nil {
		t.Fatal(err)
	}
	return row
}

// The epoch re-bind of a refused batch's charge (ReserveAdmission) applies to a
// "reserved" row only. A CONSUMED row is the quota evidence that backup restore
// reconciles against the batch's ACKed cursor: a retry under a newer epoch gets
// the original row back, still bound to the epoch it was admitted under.
func TestEpochRebindNeverTouchesAConsumedReservation(t *testing.T) {
	store, a, c, d := fixture(t)
	ctx := context.Background()
	scope, b := normalized(t, store, a, c, d)
	engine, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	receipt, err := engine.Append(ctx, scope, b)
	if err != nil {
		t.Fatal(err)
	}
	// Append leaves the charge "reserved"; the control store finalizes it from the
	// owner group's durable outcome.
	if err = store.BindAdmissionOwner(engine); err != nil {
		t.Fatal(err)
	}
	if err = store.ReconcileAdmissions(ctx); err != nil {
		t.Fatal(err)
	}
	before := reservationRow(t, store, b.Reservation.ID)
	if before.State != "consumed" || before.Cursor == nil || *before.Cursor != receipt.Cursor {
		t.Fatalf("setup: the ACKed batch's reservation is not consumed at its receipt cursor: %+v", before)
	}

	newScope := advanceEpoch(t, store, a, c, d.Org)
	retry := b
	retry.PolicyEpoch = model.Uint64(newScope.PolicyEpoch())
	retry.Reservation = model.AdmissionReservation{}
	if retry.PolicyEpoch == before.PolicyEpoch {
		t.Fatal("fixture must advance the epoch")
	}
	got, err := store.ReserveAdmission(ctx, newScope, retry)
	if err != nil {
		t.Fatalf("retry of an ACKed batch under a newer epoch: %v", err)
	}
	if got.ID != before.ID || got.State != "consumed" || got.PolicyEpoch != before.PolicyEpoch {
		t.Fatalf("a consumed reservation was returned re-bound: %+v (was %+v)", got, before)
	}
	if after := reservationRow(t, store, b.Reservation.ID); after.PolicyEpoch != before.PolicyEpoch || after.State != "consumed" {
		t.Fatalf("a consumed reservation was re-bound in control state: %+v (was %+v)", after, before)
	}
}

// A CANCELLED reservation was refunded under an owner-group fence; a retry of
// the same batch is a Conflict and the row keeps the epoch it was cancelled at.
func TestEpochRebindNeverTouchesACancelledReservation(t *testing.T) {
	store, a, c, d := fixture(t)
	ctx := context.Background()
	scope, b := normalized(t, store, a, c, d)
	engine, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if err = store.BindAdmissionOwner(engine); err != nil {
		t.Fatal(err)
	}
	proof, err := engine.Cancel(ctx, scope, b.Reservation)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.CancelAdmission(ctx, scope, proof); err != nil {
		t.Fatal(err)
	}
	before := reservationRow(t, store, b.Reservation.ID)
	if before.State != "cancelled" {
		t.Fatalf("setup: the reservation is not cancelled: %+v", before)
	}

	newScope := advanceEpoch(t, store, a, c, d.Org)
	retry := b
	retry.PolicyEpoch = model.Uint64(newScope.PolicyEpoch())
	retry.Reservation = model.AdmissionReservation{}
	if _, err = store.ReserveAdmission(ctx, newScope, retry); err == nil {
		t.Fatal("a cancelled reservation was re-admitted under a newer epoch")
	} else {
		var fault *model.Fault
		if !errors.As(err, &fault) || fault.Code != model.Conflict {
			t.Fatalf("want Conflict, got %v", err)
		}
	}
	if after := reservationRow(t, store, b.Reservation.ID); after.PolicyEpoch != before.PolicyEpoch || after.State != "cancelled" {
		t.Fatalf("a cancelled reservation was changed: %+v (was %+v)", after, before)
	}
}
