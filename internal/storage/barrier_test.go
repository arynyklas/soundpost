// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"testing"
)

func TestLocalSourcePolicyBarrierAndHistoricalReceipt(t *testing.T) {
	store, a, c, d := fixture(t)
	scope, b := normalized(t, store, a, c, d)
	engine, e := openTestEngine(t, t.TempDir(), a, store)
	if e != nil {
		t.Fatal(e)
	}
	defer engine.Close()
	if e = a.BindSourceBarrier(engine); e != nil {
		t.Fatal(e)
	}
	original, e := engine.Append(context.Background(), scope, b)
	if e != nil {
		t.Fatal(e)
	}
	session, e := a.Login(context.Background(), "owner@example.test", "a long test password 2026", "")
	if e != nil {
		t.Fatal(e)
	}
	actor, e := a.Authenticate(context.Background(), session.Token)
	if e != nil {
		t.Fatal(e)
	}
	src, e := a.SourceAuthority(context.Background(), c, true)
	if e != nil {
		t.Fatal(e)
	}
	next := src.Policy
	next.Revision++
	next.Enabled = false
	request := auth.SourcePolicyChange{CommandID: model.NewID(), Source: d.Source, ExpectedRevision: src.Policy.Revision, Policy: next, Reason: "restrict capture"}
	operation, e := a.ChangeSourcePolicy(context.Background(), actor, request)
	if e != nil || operation.Phase != "fencing" {
		t.Fatalf("closing operation: %v", e)
	}
	if _, e = engine.Append(context.Background(), scope, b); e == nil {
		t.Fatal("closing source ACK")
	}
	if e = a.DrainSourceFences(context.Background()); e != nil {
		t.Fatal(e)
	}
	operation, e = a.SourceOperation(context.Background(), actor, operation.Operation)
	if e != nil || operation.Phase != "complete" || len(operation.Barriers) != 64 {
		t.Fatalf("barrier completion: %v", e)
	}
	repeated, e := a.ChangeSourcePolicy(context.Background(), actor, request)
	if e != nil || repeated.Operation != operation.Operation || repeated.Phase != "complete" {
		t.Fatal("policy command replay lost operation")
	}
	historical, e := a.SourceScope(context.Background(), c, true)
	if e != nil {
		t.Fatal(e)
	}
	q := model.ReceiptRequest{Source: d.Source, Producer: b.Producer, RouteSlot: b.RouteSlot, BatchID: b.ID, OriginalHash: b.Hash}
	got, e := engine.LookupReceipt(context.Background(), historical, q)
	if e != nil || !got.Historical {
		t.Fatal("restricted source lost historical receipt")
	}
	got.Historical = false
	if string(mustJSON(t, got)) != string(mustJSON(t, original)) {
		t.Fatal("barrier rewrote original receipt")
	}
	store.View(context.Background(), func(st control.State) error {
		if len(st.Reservations) != 1 {
			t.Fatal("historical receipt reserved again")
		}
		return nil
	})
	if e = a.RevokeSource(context.Background(), actor, d.Source, "retire credential"); e != nil {
		t.Fatal(e)
	}
	if _, e = engine.LookupReceipt(context.Background(), historical, q); e == nil {
		t.Fatal("revoked source obtained historical receipt")
	}
}
func TestCrashReplayCommitsUnappliedBatch(t *testing.T) {
	store, a, c, d := fixture(t)
	scope, b := normalized(t, store, a, c, d)
	dir := t.TempDir()
	engine, e := openTestEngine(t, dir, a, store)
	if e != nil {
		t.Fatal(e)
	}
	engine.fault = func(at string) error {
		if at == "before_apply" {
			return model.Fail(model.Unavailable)
		}
		return nil
	}
	if _, e = engine.Append(context.Background(), scope, b); e == nil {
		t.Fatal("unapplied ACK")
	}
	engine.Close()
	engine, e = openTestEngine(t, dir, a, store)
	if e != nil {
		t.Fatal(e)
	}
	defer engine.Close()
	historical, e := a.SourceScope(context.Background(), c, true)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := engine.LookupReceipt(context.Background(), historical, model.ReceiptRequest{Source: d.Source, Producer: b.Producer, RouteSlot: b.RouteSlot, BatchID: b.ID, OriginalHash: b.Hash})
	if e != nil || receipt.Cursor.Index != 1 {
		t.Fatalf("committed WAL replay missing: %v", e)
	}
	if e = engine.VerifyFinalization(context.Background(), model.FinalizeAdmission{ReservationID: b.Reservation.ID, Cursor: receipt.Cursor}); e != nil {
		t.Fatal(e)
	}
}
