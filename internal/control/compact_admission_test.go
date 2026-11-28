// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// TestAdmissionLifecycleIsTheSameWithCompactOps pins that a group that proposes the compact admission ops (D104) and one that
// replaces the whole state per command leave the same books through reserve, retry, finalize, cancel, reconcile and settle, and
// that the compact ops were the ones proposed.
func TestAdmissionLifecycleIsTheSameWithCompactOps(t *testing.T) {
	whole := lifecycle(t, newFenceFx(t))
	f := newFenceFxCompact(t)
	compact := lifecycle(t, f)
	if !reflect.DeepEqual(whole, compact) {
		t.Fatalf("whole-state commands left %+v, compact ops %+v", whole, compact)
	}
	rsv, fin := f.store.CompactAdmissionOps()
	if rsv == 0 || fin == 0 {
		t.Fatalf("the lifecycle proposed %d rsv and %d fin ops: the gate was open and the ledger holds the books", rsv, fin)
	}
}

// With the gate closed (a member that declared only protocol 9) the rounds write the plain ops, and the books are the same.
func TestAdmissionRoundsWritePlainOpsWhileAMemberDoesNotKnowTheCompactOnes(t *testing.T) {
	f := newFenceFxPatch(t) // the patch gate is open, the compact one is not installed
	closed := lifecycle(t, f)
	if rsv, fin := f.store.CompactAdmissionOps(); rsv != 0 || fin != 0 {
		t.Fatalf("%d rsv and %d fin ops were proposed with the compact gate closed", rsv, fin)
	}
	open := lifecycle(t, newFenceFxCompact(t))
	if !reflect.DeepEqual(closed, open) {
		t.Fatalf("plain ops left %+v, compact ops %+v", closed, open)
	}
}

// Every voter of a real group applies the compact ops the leader proposes for its own batches and for the followers' (judged by
// the leader), and holds the books the leader holds.
func TestCompactAdmissionOpsAreAppliedByEveryVoter(t *testing.T) {
	v, _ := admissionVoters(t, 1, 2, 3)
	for _, s := range v.stores {
		s.SetCompactAdmissionGate(func() bool { return true })
		if err := s.BindAdmissionOwner(&reconcileOwner{}); err != nil {
			t.Fatal(err)
		}
	}
	group := model.NewID()
	var wg sync.WaitGroup
	for _, id := range []uint64{1, 2, 3} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f := v.fx[id].fenceFx
			scope := sourceScopeOf(f)
			for w := range 3 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := range 8 {
						r, err := reserveSeries(f, fmt.Sprintf("compact_v%d_w%d_%d", id, w, i))
						if err != nil {
							t.Errorf("voter %d reserve: %v", id, err)
							return
						}
						if err = f.store.FinalizeAdmission(f.ctx, scope, model.FinalizeAdmission{ReservationID: r.ID, Cursor: model.Cursor{Group: group, Index: model.Uint64(1 + w*8 + i)}}); err != nil {
							t.Errorf("voter %d finalize: %v", id, err)
							return
						}
					}
				}()
			}
		}()
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	if rsv, fin := v.stores[1].CompactAdmissionOps(); rsv < 72 || fin == 0 {
		t.Fatalf("the leader proposed %d rsv and %d fin ops for 72 batches", rsv, fin)
	}
	v.converge()
	want := v.fx[1].canonicalState()
	for _, id := range []uint64{2, 3} {
		if got := v.fx[id].canonicalState(); got != want {
			t.Fatalf("voter %d holds other books than the leader's", id)
		}
	}
}
