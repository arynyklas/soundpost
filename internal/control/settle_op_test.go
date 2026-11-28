// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// ControlLane round 3: a settlement command was 73-84 KB at 5,000 records/s (every series of every row spelled out under each of
// its quota tiers, 2,300 series records judged under the lock) and the record of a window settled in parts was written whole by every
// command that added a part, so the bytes of a command followed the series of its rows and the length of the run. What a command
// carries is the rows it drops and the parts it adds.

// settledBytes admits windows of span rows of perBatch series each, settles them in one call and answers the bytes of control commands
// per settled row.
func settledBytes(t *testing.T, span, windows, perBatch int) float64 {
	t.Helper()
	f := newFenceFxCompact(t)
	if err := f.store.BindAdmissionOwner(&reconcileOwner{}); err != nil {
		t.Fatal(err)
	}
	candidates := settleFixture(t, f, span, windows, perBatch, 900)
	_, before := f.store.StatePatchStatsForTest()
	rep, err := f.store.SettleAdmissions(f.ctx, candidates)
	if err != nil || rep.Reservations != span*windows {
		t.Fatalf("settle: %+v, %v", rep, err)
	}
	_, after := f.store.StatePatchStatsForTest()
	return float64(after-before) / float64(rep.Reservations)
}

func TestASettleCommandsBytesDoNotFollowTheSeriesOfItsRowsOrTheLengthOfTheRun(t *testing.T) {
	const budget = 400 // bytes per settled row: its id, and its window's statement
	one, twelve := settledBytes(t, 4, 24, 1), settledBytes(t, 4, 24, 12)
	t.Logf("bytes per settled row: %.0f with one series a row, %.0f with twelve", one, twelve)
	if twelve > budget || twelve > 1.25*one+50 {
		t.Errorf("a settled row costs %.0f bytes with twelve series and %.0f with one (budget %d): the bytes follow the series of the rows", twelve, one, budget)
	}

	// A window of 64 commands settled in parts of 4, one command for each part: the record of the window holds the parts settled so
	// far, and the command of the last part carries no more than the first.
	f := newFenceFxCompact(t)
	if err := f.store.BindAdmissionOwner(&reconcileOwner{}); err != nil {
		t.Fatal(err)
	}
	const span, part = 64, 4
	group := model.NewID()
	scope := sourceScopeOf(f)
	rows := make([]model.AdmissionReservation, 0, span)
	for i := range span {
		r, err := reserveBatchOf(f, []string{fmt.Sprintf("settle_run_series_%02d", i%7)})
		if err != nil {
			t.Fatal("reserve:", err)
		}
		cursor := model.Cursor{Group: group, Index: model.Uint64(i + 1)}
		if err = f.store.FinalizeAdmission(f.ctx, scope, model.FinalizeAdmission{ReservationID: r.ID, Cursor: cursor}); err != nil {
			t.Fatal("finalize:", err)
		}
		r.State, r.Cursor = "consumed", &cursor
		rows = append(rows, r)
	}
	var parts []model.SettlePart
	var first, last float64
	for j := range span / part {
		var items []model.ChargeItem
		for _, r := range rows[j*part : (j+1)*part] {
			items = append(items, model.ChargeOf(r))
		}
		parts = append(parts, model.SettlePart{J: uint32(j), Batches: part, Charge: model.ChargeDigest(items)})
		_, before := f.store.StatePatchStatsForTest()
		rep, err := f.store.SettleAdmissions(f.ctx, []model.SettleCandidate{{Group: group, N: 0, Span: span, Part: part, Parts: parts, Open: true}})
		if err != nil || rep.Parts != 1 || rep.Reservations != part {
			t.Fatalf("part %d: %+v, %v", j, rep, err)
		}
		_, after := f.store.StatePatchStatsForTest()
		if j == 0 {
			first = float64(after - before)
		}
		last = float64(after - before)
	}
	t.Logf("bytes of the command of the first part: %.0f, of the sixteenth: %.0f", first, last)
	if last > 1.3*first+100 {
		t.Errorf("the command of the sixteenth part carries %.0f bytes, the first %.0f: the bytes follow the length of the run", last, first)
	}
}
