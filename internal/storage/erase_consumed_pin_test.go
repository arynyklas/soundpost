// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// N5: erasing a batch keeps its `consumed` row. The row carries the reservation's charged series
// identities (hashes), byte charge and cursor, which quota reconciliation and the backup charge
// digests are computed from and which a quota charge that is not refunded needs. It must carry
// no payload of the erased record; docs/privacy/retention.md names it as retained by design.
func TestEraseKeepsTheConsumedRowOfAnErasedBatch(t *testing.T) {
	x := newEraseEnv(t)
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	readRow := func() (model.AdmissionReservation, []byte) {
		var row model.AdmissionReservation
		var raw []byte
		if err := x.e.db.View(func(tx *bolt.Tx) error {
			v, err := tableGet(tx, tblConsumed, []byte(hit.batch.Reservation.ID.String()))
			raw = append([]byte(nil), v...)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if len(raw) == 0 {
			t.Fatal("no consumed row")
		}
		if err := json.Unmarshal(raw, &row); err != nil {
			t.Fatal(err)
		}
		return row, raw
	}
	before, _ := readRow()
	if len(before.Series) == 0 || before.State != "consumed" || before.Cursor == nil {
		t.Fatalf("fixture invalid: %+v", before)
	}
	if _, err := x.e.EraseDeleted(context.Background(), []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}, nil); err != nil {
		t.Fatal(err)
	}
	after, raw := readRow()
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("the consumed row changed by the erasure:\n got %+v\nwant %+v", after, before)
	}
	if containsAny(raw, canaryForms(eraseCanary)) {
		t.Fatal("the consumed row holds the erased canary")
	}
}
