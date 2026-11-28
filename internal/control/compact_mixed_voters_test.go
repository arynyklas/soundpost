// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// lookupOwner is the owner of a group that settled windows: it also tells that a batch the books hold no row for is not in the data
// (the retries of settled batches ReserveAdmission asks about).
type lookupOwner struct{ reconcileOwner }

func (o *lookupOwner) AdmittedBatch(context.Context, model.AdmissionReservation) (model.Receipt, bool, error) {
	return model.Receipt{}, false, nil
}

// A group with a member at protocol 9 keeps the plain ops (D104: the compact gate reads false); once that member is replaced or upgraded
// to protocol 10 the gate opens and the same group starts proposing rsv, fin and stl, in the same group and on the same journal. Every
// voter holds the same ledger after each phase, the reservations the plain ops wrote are finalized and settled by the compact ops of the
// second, and what a settlement folds is the same whichever form wrote it.
func TestACompactAdmissionGroupWithAProtocolNineMemberKeepsPlainOpsUntilItIsUpgraded(t *testing.T) {
	v, _ := admissionVoters(t, 1, 2, 3)
	var gate atomic.Bool // false: a member of the group declared only protocol 9
	for _, s := range v.stores {
		s.SetCompactAdmissionGate(gate.Load)
		if err := s.BindAdmissionOwner(&lookupOwner{}); err != nil {
			t.Fatal(err)
		}
	}
	group := model.NewID()
	var next atomic.Uint64
	consumed := map[uint64]model.AdmissionReservation{} // by cursor index
	finalize := func(phase string, id uint64, r model.AdmissionReservation) {
		f := v.fx[id].fenceFx
		index := next.Add(1)
		cursor := model.Cursor{Group: group, Index: model.Uint64(index)}
		if err := f.store.FinalizeAdmission(f.ctx, sourceScopeOf(f), model.FinalizeAdmission{ReservationID: r.ID, Cursor: cursor}); err != nil {
			t.Fatalf("%s: voter %d finalize: %v", phase, id, err)
		}
		r.State, r.Cursor = "consumed", &cursor
		consumed[index] = r
	}
	run := func(phase string, per int) (open []model.AdmissionReservation) {
		for _, id := range []uint64{1, 2, 3} {
			f := v.fx[id].fenceFx
			for i := range per {
				r, err := reserveSeries(f, fmt.Sprintf("mixed_%s_v%d_%d", phase, id, i))
				if err != nil {
					t.Fatalf("%s: voter %d reserve: %v", phase, id, err)
				}
				if i%2 == 1 { // half of them stay reserved across the upgrade, to be finalized by the compact ops of the next phase
					open = append(open, r)
					continue
				}
				finalize(phase, id, r)
			}
		}
		v.converge()
		return open
	}
	identical := func(phase string) {
		want := v.fx[1].canonicalState()
		for _, id := range []uint64{2, 3} {
			if got := v.fx[id].canonicalState(); got != want {
				t.Fatalf("%s: voter %d holds other books than voter 1", phase, id)
			}
		}
	}
	// settle offers the windows of four cursors whose reservations are all consumed, and answers the rows it dropped.
	settle := func(phase string) int {
		const span = 4
		var candidates []model.SettleCandidate
		for n := uint64(0); ; n++ {
			var items []model.ChargeItem
			for i := n*span + 1; i <= n*span+span; i++ {
				r, ok := consumed[i]
				if !ok {
					break
				}
				items = append(items, model.ChargeOf(r))
			}
			if len(items) != span {
				break
			}
			candidates = append(candidates, model.SettleCandidate{Group: group, N: n, Span: span, Batches: span, Charge: model.ChargeDigest(items)})
		}
		f := v.fx[1].fenceFx
		rep, err := v.stores[1].SettleAdmissions(f.ctx, candidates)
		if err != nil {
			t.Fatalf("%s: settle: %v", phase, err)
		}
		v.converge()
		return rep.Reservations
	}
	held := run("nine", 6)
	identical("nine")
	if dropped := settle("nine"); dropped == 0 {
		t.Fatal("nine: the settlement dropped no rows")
	}
	identical("nine settled")
	for _, id := range []uint64{1, 2, 3} {
		if rsv, fin := v.stores[id].CompactAdmissionOps(); rsv != 0 || fin != 0 || v.stores[id].CompactSettleOps() != 0 {
			t.Fatalf("voter %d proposed %d rsv, %d fin and %d stl ops while a member was at protocol 9", id, rsv, fin, v.stores[id].CompactSettleOps())
		}
	}
	gate.Store(true) // the member was replaced by a build at protocol 10 and declared it
	for i, r := range held {
		finalize("ten", uint64(1+i%3), r)
	}
	run("ten", 6)
	identical("ten")
	if dropped := settle("ten"); dropped == 0 {
		t.Fatal("ten: the settlement dropped no rows")
	}
	identical("ten settled")
	var rsv, fin, stl uint64
	for _, id := range []uint64{1, 2, 3} {
		r, f := v.stores[id].CompactAdmissionOps()
		rsv, fin, stl = rsv+r, fin+f, stl+v.stores[id].CompactSettleOps()
	}
	if rsv < 18 || fin < uint64(len(held)) || stl == 0 {
		t.Fatalf("after the upgrade the group proposed %d rsv, %d fin and %d stl ops, want at least 18, %d and 1", rsv, fin, stl, len(held))
	}
}
