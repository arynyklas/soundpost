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

// historyOwner is an owner whose data holds an outcome for every reservation it was told of. It counts the
// outcome rows a reconciliation pass reads: every row of its history when it is asked for all of them
// (AdmissionOutcomes), the rows it is asked about when it is asked by ID (AdmissionOutcomesFor).
type historyOwner struct {
	order    []model.FinalizeAdmission
	outcomes map[model.ID]model.FinalizeAdmission
	read     int
}

func (o *historyOwner) VerifyCancellation(context.Context, model.CancelReservation) error { return nil }
func (o *historyOwner) VerifyFinalization(context.Context, model.FinalizeAdmission) error {
	return nil
}
func (o *historyOwner) AdmissionOutcomes(context.Context) ([]model.FinalizeAdmission, error) {
	o.read += len(o.order)
	return append([]model.FinalizeAdmission(nil), o.order...), nil
}
func (o *historyOwner) AdmissionOutcomesFor(_ context.Context, ids []model.ID) ([]model.FinalizeAdmission, error) {
	var out []model.FinalizeAdmission
	for _, id := range ids {
		o.read++
		if p, ok := o.outcomes[id]; ok {
			out = append(out, p)
		}
	}
	return out, nil
}

// TestReconcileWorkDoesNotGrowWithTheHistory is the red test of the history-dependent stall of the single-host
// load (L2w20Admission16): the reconciliation of outcomes ran every five seconds, read every outcome the data
// had ever stored (under the engine's lock) and looked each one up in control, so a pass cost what had been
// admitted before it: 1.1 s of CPU per 19 s window at the start of the load, 5.8 s four minutes in, with every
// append that needed the engine waiting out the read. A pass has to cost what is open: after a thousand
// batches are finalized, a pass over five new open reservations reads about five outcome rows.
func TestReconcileWorkDoesNotGrowWithTheHistory(t *testing.T) {
	f := newFenceFxPatch(t)
	owner := &historyOwner{outcomes: map[model.ID]model.FinalizeAdmission{}}
	if err := f.store.BindAdmissionOwner(owner); err != nil {
		t.Fatal(err)
	}
	group := model.NewID()
	var admitted int
	admit := func(n int) {
		t.Helper()
		for range n {
			admitted++
			r, err := reserveSeries(f, fmt.Sprintf("history_series_%03d", admitted%800)) // the source's quota is about 900 series
			if err != nil {
				t.Fatal("reserve:", err)
			}
			p := model.FinalizeAdmission{ReservationID: r.ID, Cursor: model.Cursor{Group: group, Index: model.Uint64(admitted)}}
			owner.order = append(owner.order, p)
			owner.outcomes[r.ID] = p
		}
	}
	pass := func() (read, commands int) {
		t.Helper()
		owner.read = 0
		before := f.revision()
		if err := f.store.ReconcileAdmissions(f.ctx); err != nil {
			t.Fatal("reconcile:", err)
		}
		return owner.read, int(f.revision() - before)
	}
	admit(1000)
	if _, commands := pass(); commands == 0 {
		t.Fatal("the first pass finalized nothing")
	}
	admit(5)
	read, commands := pass()
	if read > 50 {
		t.Errorf("a pass over 5 open reservations read %d outcome rows with %d batches finalized before it", read, admitted-5)
	}
	if commands != 1 {
		t.Errorf("the pass that finalizes 5 outcomes committed %d control commands, want 1", commands)
	}
	if read, commands = pass(); read > 50 || commands != 0 {
		t.Errorf("a pass with nothing open read %d outcome rows and committed %d commands", read, commands)
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
	if consumed != admitted {
		t.Errorf("%d of %d reservations are consumed after the reconciliations", consumed, admitted)
	}
}
