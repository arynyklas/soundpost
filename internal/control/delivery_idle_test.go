// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// idle asks control.DeliveryClaimIdle the way the outbox does: a claim of up to five deliveries lasting 90 ns, from a read of the committed state.
func (f *eraseFx) idle(lease replica.FenceToken, now model.UnixNano) bool {
	f.t.Helper()
	scope := f.adminScope()
	var idle bool
	if err := f.store.View(f.ctx, func(st control.State) error {
		idle = control.DeliveryClaimIdle(scope, st, lease, control.DeliveryClaim{Project: f.project, Now: now, Expires: now + 90, Limit: 5, OwnerRevision: control.CutoverRevision(st, f.org, f.project)})
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	return idle
}

// The idleness check must agree with the handler: a claim it calls idle must leave the delivery books as they are, and a claim it does not call
// idle must change them or be refused. Each row runs the real claim after asking.
func TestDeliveryClaimIdleAgreesWithTheHandler(t *testing.T) {
	f := newEraseFx(t)
	lease := f.lease()
	agree := func(name string, want bool, l replica.FenceToken, now model.UnixNano) {
		t.Helper()
		if got := f.idle(l, now); got != want {
			t.Fatalf("%s: idle = %v, want %v", name, got, want)
		}
		before := f.delBooks()
		_, err := f.claim(l, now, 90, 5)
		changed := !reflect.DeepEqual(before, f.delBooks())
		switch {
		case want && (err != nil || changed):
			t.Fatalf("%s: the handler changed the delivery books (changed %v) or refused (%v) a claim called idle", name, changed, err)
		case !want && err == nil && !changed:
			t.Fatalf("%s: the handler changed nothing for a claim not called idle", name)
		}
	}

	// No fence stored yet: the claim raises it, so it is not idle.
	agree("fence not yet raised", false, lease, 50)
	// The fence equals the lease and nothing is open.
	agree("nothing open", true, lease, 60)
	// A newer or older lease must commit (the newer raises the fence; the older is refused).
	if f.idle(f.newer(lease), 61) {
		t.Fatal("a claim under a newer term was called idle: the fence it raises would never be recorded")
	}
	older := lease
	older.Term--
	if f.idle(older, 61) {
		t.Fatal("a deposed lease was called idle: the handler refuses it as stale")
	}

	// A delivery not due yet; then due; then leased (live); then lapsed.
	f.mustEnqueue(0, f.intent(1))
	agree("a delivery due later than the claim", true, lease, 99)
	if f.idle(lease, 100) {
		t.Fatal("a due delivery was called idle")
	}
	if ids := f.mustClaim(lease, 100, 90, 5); len(ids) != 1 {
		t.Fatalf("the due delivery was not leased: %v", ids)
	}
	agree("a live claim", true, lease, 150)
	if f.idle(lease, 190) {
		t.Fatal("a lapsed claim was called idle: the next claim closes it as unknown")
	}

	// A claim that names another cutover revision is refused by the handler, so it is not idle.
	scope := f.adminScope()
	var stale bool
	if err := f.store.View(f.ctx, func(st control.State) error {
		stale = control.DeliveryClaimIdle(scope, st, lease, control.DeliveryClaim{Project: f.project, Now: 150, Expires: 240, Limit: 5, OwnerRevision: 77})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if stale {
		t.Fatal("a claim at a stale cutover revision was called idle")
	}
}

// A delivery the claim would settle (its destination was disabled) or exhaust (older than the age horizon) is work: the claim is not idle.
func TestDeliveryClaimIdleIsNotIdleWhenTheClaimWouldSettleOrExhaustADelivery(t *testing.T) {
	t.Run("disabled destination", func(t *testing.T) {
		f := newEraseFx(t)
		lease := f.lease()
		f.mustClaim(lease, 50, 90, 5) // raises the fence
		f.mustEnqueue(0, f.intent(1))
		f.setDestination(f.dest, false)
		if f.idle(lease, 100) {
			t.Fatal("a delivery to a disabled destination was called idle: the claim settles it")
		}
		before := f.delBooks()
		if _, err := f.claim(lease, 100, 90, 5); err != nil || reflect.DeepEqual(before, f.delBooks()) {
			t.Fatalf("the claim did not settle it (err %v)", err)
		}
		if !f.idle(lease, 101) {
			t.Fatal("after the settle there is nothing open and the claim is idle")
		}
	})
	t.Run("age horizon", func(t *testing.T) {
		f := newEraseFx(t)
		lease := f.lease()
		f.mustClaim(lease, 50, 90, 5)
		f.mustEnqueue(0, f.intent(1, withAt(1000)))
		late := model.UnixNano(1000) + control.DeliveryMaxAge
		if f.idle(lease, late) {
			t.Fatal("a delivery past the age horizon was called idle: the claim exhausts it")
		}
	})
}

// A finished deletion that covers the project and still has a payload to drop makes the claim a change: the claim commits and erases it
// (eraseLateEffect), and the claim after that is idle again.
func TestDeliveryClaimIdleIsNotIdleWhileACompletedDeletionStillHasSomethingToErase(t *testing.T) {
	f := newEraseFx(t)
	lease := f.lease()
	f.mustClaim(lease, 50, 90, 5) // raises the fence
	f.saga(f.lateRange())
	if !f.idle(lease, 60) {
		t.Fatal("a completed deletion with nothing left to erase makes every claim of its project non-idle")
	}

	// A settled delivery of the erased range that kept its body (a state the erasure did not see).
	const canary = "CANARYIDLEc7de151f0aa93b86a"
	id := model.NewID()
	rec := control.DeliveryRecord{ID: id, Org: f.org, Project: f.project, Policy: f.policy, Subject: f.subject, Kind: "open", Route: control.DeliveryRouteImmediate, Recipient: &f.dest,
		Disposition: control.DeliveryDispositionDeliver, Phase: control.DeliveryAccepted, Provider: "msg", OriginFrom: 60, OriginTo: 70, Body: json.RawMessage(`{"title":"` + canary + `"}`)}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.Update(f.ctx, func(st *control.State) error {
		if st.DeliveryBooks == nil {
			st.DeliveryBooks = map[string]json.RawMessage{}
		}
		st.DeliveryBooks["delivery:"+id.String()] = raw
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !f.stateHolds(canary) {
		t.Fatal("fixture: the planted body is not in the state")
	}
	if f.idle(lease, 61) {
		t.Fatal("a claim was called idle while a completed deletion still had a covered body to erase")
	}
	if _, err = f.claim(lease, 61, 90, 5); err != nil {
		t.Fatal(err)
	}
	if f.stateHolds(canary) {
		t.Fatal("the claim did not erase the covered body")
	}
	if !f.idle(lease, 62) {
		t.Fatal("after the erasure the claim is idle again")
	}
}
