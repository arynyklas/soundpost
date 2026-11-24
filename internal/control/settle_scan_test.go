// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// A settle pass asks which consumed reservation rows the data proves, and the only way to find the rows of a
// window is to read the reservation table. Every settle command used to read it again under the lock every
// control writer shares, once more for each command of the pass: at the single-host gate that is a few thousand
// rows decoded per command, 45 ms of the lock for a command that drops a few dozen, every five seconds, and the
// acknowledgements that arrived meanwhile took 400 ms (L2w20Admission19). The table has to be read once per
// SettleAdmissions call, outside the lock; the commands only look up the rows they drop, and each of them drops a
// bounded number.
func TestSettleScansTheBooksOncePerCallHoweverManyCommandsItTakes(t *testing.T) {
	f := newFenceFxPatch(t)
	owner := &reconcileOwner{}
	if err := f.store.BindAdmissionOwner(owner); err != nil {
		t.Fatal(err)
	}
	const span, windows, unrelated = 4, 40, 300
	group := model.NewID()
	rows := make([]model.AdmissionReservation, 0, windows*span+unrelated)
	for i := range windows*span + unrelated {
		r, err := reserveSeries(f, fmt.Sprintf("settle_scan_%04d", i))
		if err != nil {
			t.Fatal("reserve:", err)
		}
		cursor := model.Cursor{Group: group, Index: model.Uint64(i + 1)}
		owner.outcomes = append(owner.outcomes, model.FinalizeAdmission{ReservationID: r.ID, Cursor: cursor})
		r.State, r.Cursor = "consumed", &cursor
		rows = append(rows, r)
	}
	if err := f.store.ReconcileAdmissions(f.ctx); err != nil {
		t.Fatal("reconcile:", err)
	}
	// The data offers the first forty windows; the 300 rows after them are consumed rows of windows it has not sealed.
	var candidates []model.SettleCandidate
	for n := range windows {
		var items []model.ChargeItem
		for _, r := range rows[n*span : n*span+span] {
			items = append(items, model.ChargeOf(r))
		}
		candidates = append(candidates, model.SettleCandidate{Group: group, N: uint64(n), Span: span, Batches: span, Charge: model.ChargeDigest(items)})
	}
	revision, scanned := f.revision(), f.store.SettleScanRowsForTest()
	dropped, calls := 0, 0
	productive := 0 // the calls that settled something: each reads the books once
	for {
		rep, err := f.store.SettleAdmissions(f.ctx, candidates)
		if err != nil {
			t.Fatal("settle:", err)
		}
		calls++
		if rep.Reservations == 0 {
			break
		}
		productive++
		dropped += rep.Reservations
	}
	commands, read := int(f.revision()-revision), int(f.store.SettleScanRowsForTest()-scanned)
	t.Logf("dropped %d rows in %d commands and %d calls, read %d reservation rows", dropped, commands, calls, read)
	if dropped != windows*span {
		t.Fatalf("the pass dropped %d rows, want the %d of the offered windows", dropped, windows*span)
	}
	// Sixty-four rows a command: 160 rows are three commands (a bound of 256 would take one).
	if commands != 3 {
		t.Errorf("the pass took %d commands for %d rows, want 3 of at most 64 rows", commands, dropped)
	}
	if limit := productive * (windows*span + unrelated); read > limit {
		t.Errorf("the pass read %d reservation rows in %d productive calls over %d rows: more than one scan of the books a call (%d)", read, productive, windows*span+unrelated, limit)
	}
}
