// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// reconcileOwner is an owner whose data holds an outcome for every reservation it was told of: the
// durable proof ReconcileAdmissions marks consumed.
type reconcileOwner struct{ outcomes []model.FinalizeAdmission }

func (o *reconcileOwner) VerifyCancellation(context.Context, model.CancelReservation) error {
	return nil
}
func (o *reconcileOwner) VerifyFinalization(context.Context, model.FinalizeAdmission) error {
	return nil
}
func (o *reconcileOwner) AdmissionOutcomes(context.Context) ([]model.FinalizeAdmission, error) {
	return o.outcomes, nil
}

// TestReconcileAfterOverloadCommitsInBatches is the red test of the restart failure after an overload
// (07.06 #11): a server that was stopped under load restarts with thousands of batches that are in the
// data but whose finalize never reached control, and the start-up reconciliation committed one control
// command per batch inside the 20 s start-up budget; at the cost of a command in the overloaded state
// that never fit and `soundpost serve` exited with reason=unavailable. The outcomes are committed a
// batch of commands at a time, so the number of commands is a small fraction of the number of batches.
func TestReconcileAfterOverloadCommitsInBatches(t *testing.T) {
	f := newFenceFxPatch(t)
	owner := &reconcileOwner{}
	if err := f.store.BindAdmissionOwner(owner); err != nil {
		t.Fatal(err)
	}
	const batches = 600
	group := model.NewID()
	for i := range batches {
		r, err := reserveSeries(f, fmt.Sprintf("reconcile_series_%04d", i))
		if err != nil {
			t.Fatal("reserve:", err)
		}
		owner.outcomes = append(owner.outcomes, model.FinalizeAdmission{ReservationID: r.ID, Cursor: model.Cursor{Group: group, Index: model.Uint64(i + 1)}})
	}
	before := f.revision()
	if err := f.store.ReconcileAdmissions(f.ctx); err != nil {
		t.Fatal("reconcile:", err)
	}
	commands := int(f.revision() - before)
	if commands > batches/50 {
		t.Errorf("reconciling %d outcomes took %d control commands", batches, commands)
	}
	consumed := 0
	if err := f.store.View(f.ctx, func(st control.State) error {
		for _, r := range st.Reservations {
			if r.State == "consumed" && r.Cursor != nil {
				consumed++
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if consumed != batches {
		t.Errorf("%d of %d reservations are consumed after the reconciliation", consumed, batches)
	}
}
