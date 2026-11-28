// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// The windows a follower's storage offers are settled by the leader, in its own rounds: a follower that ran the command itself lost
// the race for the revision to the leader's rounds nearly every time (78 % of the rounds of the two followers at 5,000 records/s,
// one item and 355 KB of patch each), and a command of theirs that did win moved the revision under the leader's round in flight.
func TestAFollowerHandsTheWindowsItsStorageOffersToTheLeader(t *testing.T) {
	v, _ := admissionVoters(t, 1, 2, 3)
	owner := &reconcileOwner{}
	for _, s := range v.stores {
		if err := s.BindAdmissionOwner(owner); err != nil {
			t.Fatal(err)
		}
	}
	f := v.fx[1].fenceFx
	scope := sourceScopeOf(f)
	group := model.NewID()
	var rows []model.AdmissionReservation
	for i := range 8 {
		r, err := reserveSeries(f, fmt.Sprintf("settle_leader_%d", i))
		if err != nil {
			t.Fatal("reserve:", err)
		}
		if err = v.stores[1].FinalizeAdmission(f.ctx, scope, model.FinalizeAdmission{ReservationID: r.ID, Cursor: model.Cursor{Group: group, Index: model.Uint64(i + 1)}}); err != nil {
			t.Fatal("finalize:", err)
		}
		r.State, r.Cursor = "consumed", &model.Cursor{Group: group, Index: model.Uint64(i + 1)}
		rows = append(rows, r)
	}
	var candidates []model.SettleCandidate
	for n := range 2 {
		var items []model.ChargeItem
		for _, r := range rows[n*4 : n*4+4] {
			items = append(items, model.ChargeOf(r))
		}
		candidates = append(candidates, model.SettleCandidate{Group: group, N: uint64(n), Span: 4, Batches: 4, Charge: model.ChargeDigest(items)})
	}
	v.converge()
	before := v.stores[2].AdmissionRoundsForTest()
	rep, err := v.stores[2].SettleAdmissions(f.ctx, candidates)
	if err != nil || rep.Windows != 2 || rep.Reservations != 8 {
		t.Fatalf("settle through a follower: %+v, %v", rep, err)
	}
	if rounds := v.stores[2].AdmissionRoundsForTest(); rounds != before {
		t.Fatalf("the follower proposed %d admission rounds of its own to settle", rounds-before)
	}
	if calls, _, _ := v.stores[2].RemoteAdmissionForTest(); calls == 0 {
		t.Fatal("the follower made no call to the leader")
	}
	v.converge()
	want := v.fx[1].canonicalState()
	for _, id := range []uint64{2, 3} {
		if got := v.fx[id].canonicalState(); got != want {
			t.Fatalf("voter %d holds other books than the leader's", id)
		}
	}
	var left int
	if err = v.stores[3].View(f.ctx, func(st control.State) error {
		left = len(st.Reservations)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("%d reservation rows are left after the eight consumed ones were settled", left)
	}
}
