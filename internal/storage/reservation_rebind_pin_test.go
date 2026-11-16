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

// chargedState is the canonical bytes of everything a reservation moves: the
// quota tiers, the reservation rows and the admission-key index.
func chargedState(t *testing.T, store *control.Store) string {
	t.Helper()
	var out []byte
	if err := store.View(context.Background(), func(st control.State) error {
		var err error
		out, err = model.CanonicalJSON(struct {
			Quotas       map[string]model.QuotaState
			Reservations map[string]model.AdmissionReservation
			Keys         map[string]string
		}{st.Quotas, st.Reservations, st.AdmissionKeys})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func wantFault(t *testing.T, err error, code model.Code) {
	t.Helper()
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != code {
		t.Fatalf("want a typed %s fault, got %v", code, err)
	}
}

// chargedRetry charges a batch that is never appended (a capacity-refused or
// ambiguous attempt), advances the epoch, and returns the retry minted under the
// new epoch. mutate then changes the source the way the case needs; the retry's
// scope is taken BEFORE it, so the scope's epoch is current and only the source
// authority (not the epoch check) can refuse the retry.
func chargedRetry(t *testing.T, mutate func(*control.State, model.ID)) (store *control.Store, scope auth.Scope, retry model.NormalizedBatch, first model.AdmissionReservation) {
	t.Helper()
	store, a, c, d := fixture(t)
	_, b := normalized(t, store, a, c, d)
	first = reservationRow(t, store, b.Reservation.ID)
	if first.State != "reserved" {
		t.Fatalf("setup: want a reserved row, got %+v", first)
	}
	scope = advanceEpoch(t, store, a, c, d.Org)
	if err := store.Update(context.Background(), func(st *control.State) error { mutate(st, d.Source); return nil }); err != nil {
		t.Fatal(err)
	}
	retry = b
	retry.PolicyEpoch = model.Uint64(scope.PolicyEpoch())
	retry.Reservation = model.AdmissionReservation{}
	if retry.PolicyEpoch == first.PolicyEpoch {
		t.Fatal("fixture must advance the epoch")
	}
	return store, scope, retry, first
}

// The epoch re-bind revalidates the retry against the CURRENT source. A source
// disabled since the charge (the retry's scope is on the current epoch, so only
// the source authority can refuse it) must get a typed Stale, and the reserved
// row stays bound to its old epoch with no charge moved.
//
// Kills: removing/relaxing scope.ValidateSourceState(..., admission=true) in
// ReserveAdmission (the re-bind would then run for a disabled source).
func TestEpochRebindRefusedForADisabledSource(t *testing.T) {
	store, scope, retry, first := chargedRetry(t, func(st *control.State, source model.ID) {
		src := st.Sources[source.String()]
		src.Policy.Enabled = false
		st.Sources[source.String()] = src
	})
	before := chargedState(t, store)
	_, err := store.ReserveAdmission(context.Background(), scope, retry)
	wantFault(t, err, model.Stale)
	if after := chargedState(t, store); after != before {
		t.Fatalf("a refused retry moved the charge or re-bound the row:\nbefore %s\nafter  %s", before, after)
	}
	if row := reservationRow(t, store, first.ID); row.PolicyEpoch != first.PolicyEpoch || row.State != "reserved" {
		t.Fatalf("the reserved row was re-bound for a disabled source: %+v (was %+v)", row, first)
	}
}

// A source whose policy REVISION moved on (ChangeSourcePolicy: revision+1 and an
// epoch bump) cannot have its old-revision batch re-bound to the new epoch: the
// retry carries the old revision and the old policy hash, so it can never be
// admitted, and re-binding its charge would only launder the stale batch into
// the current epoch. The retry is refused with a typed Stale, nothing is moved.
//
// Kills: removing the PolicyRevision guard in the re-bind branch of
// ReserveAdmission (internal/control/quota.go).
func TestEpochRebindRefusedAfterPolicyRevisionChange(t *testing.T) {
	store, scope, retry, first := chargedRetry(t, func(st *control.State, source model.ID) {
		src := st.Sources[source.String()]
		src.Policy.Revision++
		st.Sources[source.String()] = src
	})
	before := chargedState(t, store)
	_, err := store.ReserveAdmission(context.Background(), scope, retry)
	wantFault(t, err, model.Stale)
	if after := chargedState(t, store); after != before {
		t.Fatalf("a refused retry moved the charge or re-bound the row:\nbefore %s\nafter  %s", before, after)
	}
	if row := reservationRow(t, store, first.ID); row.PolicyEpoch != first.PolicyEpoch || row.State != "reserved" {
		t.Fatalf("the reserved row was re-bound across a policy revision change: %+v (was %+v)", row, first)
	}
}

// Control of the two refusals above: the same fixture with the source untouched
// (revision and enabled state unchanged) DOES re-bind, so the refusals are due to
// the source change and not to the retry shape.
func TestEpochRebindStillHappensForAnUnchangedSource(t *testing.T) {
	store, scope, retry, first := chargedRetry(t, func(*control.State, model.ID) {})
	got, err := store.ReserveAdmission(context.Background(), scope, retry)
	if err != nil {
		t.Fatalf("retry of an unchanged source: %v", err)
	}
	if got.ID != first.ID || got.PolicyEpoch != retry.PolicyEpoch || got.State != "reserved" {
		t.Fatalf("the reserved row was not re-bound to the current epoch: %+v (was %+v)", got, first)
	}
}
