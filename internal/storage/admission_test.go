// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"errors"
	bolt "go.etcd.io/bbolt"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"sync"
	"testing"
)

func TestHistoricalReceiptLookupAfterPolicyDeleteAndRevocation(t *testing.T) {
	store, a, c, d := fixture(t)
	scope, b := normalized(t, store, a, c, d)
	engine, e := Open(t.TempDir(), a)
	if e != nil {
		t.Fatal(e)
	}
	defer engine.Close()
	original, e := engine.Append(context.Background(), scope, b)
	if e != nil {
		t.Fatal(e)
	}
	// Historical deletion removes rows, never the receipt. A current source's
	// ownership credential remains valid independently of new-admission policy.
	e = engine.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("batches")).Delete(batchKey(b.Org, b.Project, b.Source, b.Producer, b.RouteSlot, b.ID))
	})
	if e != nil {
		t.Fatal(e)
	}
	e = store.Update(context.Background(), func(st *control.State) error {
		src := st.Sources[d.Source.String()]
		src.Policy.Enabled = false
		src.Closing = true
		st.Sources[d.Source.String()] = src
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	historical, e := a.SourceScope(context.Background(), c, true)
	if e != nil {
		t.Fatal(e)
	}
	q := model.ReceiptRequest{Source: b.Source, Producer: b.Producer, RouteSlot: b.RouteSlot, BatchID: b.ID, OriginalHash: original.Hash}
	got, e := engine.LookupReceipt(context.Background(), historical, q)
	if e != nil || !got.Historical {
		t.Fatalf("historical: %v", e)
	}
	got.Historical = false
	if string(mustJSON(t, got)) != string(mustJSON(t, original)) {
		t.Fatal("historical receipt changed")
	}
	if _, e = a.SourceScope(context.Background(), c, false); e == nil {
		t.Fatal("restriction bypass")
	}
	store.Update(context.Background(), func(st *control.State) error {
		src := st.Sources[d.Source.String()]
		src.Revoked = true
		st.Sources[d.Source.String()] = src
		return nil
	})
	if _, e = engine.LookupReceipt(context.Background(), historical, q); e == nil {
		t.Fatal("revoked historical credential accepted")
	}
}
func TestQuotaReservationIsAtomic(t *testing.T) {
	store, a, c, d := fixture(t)
	scope, b := normalized(t, store, a, c, d)
	cap := uint64(len(b.Canonical)) * 3
	store.Update(context.Background(), func(st *control.State) error {
		src := st.Sources[d.Source.String()]
		src.Policy.MaxBytes = cap
		st.Sources[d.Source.String()] = src
		return nil
	})
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := b
			n.ID = model.NewID()
			n.Producer = model.NewID()
			n.Canonical = mustJSON(t, n.Batch)
			n.Hash = model.HashCanonical(n.Canonical)
			if _, e := store.ReserveAdmission(context.Background(), scope, n); e == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if accepted != 2 {
		t.Fatalf("hard quota accepted %d extra batches, want 2", accepted)
	}
	store.View(context.Background(), func(st control.State) error {
		q := st.Quotas["project:"+d.Org.String()+":"+d.Project.String()]
		if q.Bytes != cap || len(q.Series) != 1 {
			t.Fatal("charge/cardinality mismatch")
		}
		return nil
	})
}
func TestReservationNotRefundedOnAmbiguousAppend(t *testing.T) {
	store, a, c, d := fixture(t)
	scope, b := normalized(t, store, a, c, d)
	engine, e := Open(t.TempDir(), a)
	if e != nil {
		t.Fatal(e)
	}
	defer engine.Close()
	engine.fault = func(at string) error {
		if at == "wal_sync" {
			return errors.New("sync fault")
		}
		return nil
	}
	if _, e = engine.Append(context.Background(), scope, b); e == nil {
		t.Fatal("fault ACK")
	}
	store.View(context.Background(), func(st control.State) error {
		if st.Reservations[b.Reservation.ID.String()].State != "reserved" || st.Quotas["org:"+d.Org.String()].Bytes == 0 {
			t.Fatal("ambiguous reservation refunded")
		}
		return nil
	})
}
func TestCancellationRequiresDurableOwnerFence(t *testing.T) {
	store, a, c, d := fixture(t)
	scope, b := normalized(t, store, a, c, d)
	engine, e := Open(t.TempDir(), a)
	if e != nil {
		t.Fatal(e)
	}
	defer engine.Close()
	if e = store.BindAdmissionOwner(engine); e != nil {
		t.Fatal(e)
	}
	forged := model.CancelReservation{ReservationID: b.Reservation.ID, Hash: b.Hash}
	if e = store.CancelAdmission(context.Background(), scope, forged); e == nil {
		t.Fatal("uncommitted cancellation refunded")
	}
	proof, e := engine.Cancel(context.Background(), scope, b.Reservation)
	if e != nil {
		t.Fatal(e)
	}
	if e = store.CancelAdmission(context.Background(), scope, proof); e != nil {
		t.Fatal(e)
	}
	if _, e = engine.Append(context.Background(), scope, b); e == nil {
		t.Fatal("cancelled token resurrected")
	}
}
func TestOrderedMetricConflictRejectsWholeBatch(t *testing.T) {
	store, a, c, d := fixture(t)
	scope, b := normalized(t, store, a, c, d)
	engine, e := Open(t.TempDir(), a)
	if e != nil {
		t.Fatal(e)
	}
	defer engine.Close()
	if _, e = engine.Append(context.Background(), scope, b); e != nil {
		t.Fatal(e)
	}
	next := b
	raw, _ := json.Marshal(b.Batch)
	json.Unmarshal(raw, &next.Batch)
	next.ID = model.NewID()
	next.Producer = model.NewID()
	next.Records[0].ID = model.NewID()
	next.Canonical = mustJSON(t, next.Batch)
	next.Hash = model.HashCanonical(next.Canonical)
	next.Reservation, e = store.ReserveAdmission(context.Background(), scope, next)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = engine.Append(context.Background(), scope, next); e != nil {
		t.Fatal(e)
	}
	rows := 0
	engine.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("batches")).ForEach(func(_, v []byte) error { var r []model.Record; json.Unmarshal(v, &r); rows += len(r); return nil })
	})
	if rows != 1 {
		t.Fatal("identical equal-time samples multiplied")
	}
	next.ID = model.NewID()
	next.Records[0].Payload.Metric.Value = ptrBits(0x4000000000000000)
	next.Canonical = mustJSON(t, next.Batch)
	next.Hash = model.HashCanonical(next.Canonical)
	next.Reservation, e = store.ReserveAdmission(context.Background(), scope, next)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = engine.Append(context.Background(), scope, next); e == nil {
		t.Fatal("equal-time conflict ACK")
	}
}
