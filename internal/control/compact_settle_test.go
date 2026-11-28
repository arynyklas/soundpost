// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// TestASettlementCommandCarriesALimitedNumberOfBytesPerRow is the red test of the settlement share of the control leader's time
// (admit report, round 5): at 5,000 records/s a quarter of the rounds carried a settlement command of 64 rows, 5.5 KB a row (an op
// of its own for each of the 18 series counts a row folds into the settlement, with the tier key and the series id spelled out),
// and those rounds took 107 ms to propose where the others took 32 ms. A settled row has to cost a function of what it says (its
// series, once under each tier), not of how often the paths repeat.
func TestASettlementCommandCarriesALimitedNumberOfBytesPerRow(t *testing.T) {
	const budget = 1500 // bytes per settled row of six series: the row's two deletes, the six series once with a count for each tier, the window's record (measured 5,500 with the plain ops)
	f := newFenceFxCompact(t)
	if err := f.store.BindAdmissionOwner(&reconcileOwner{}); err != nil {
		t.Fatal(err)
	}
	const span, windows, perBatch = 4, 24, 6
	group := model.NewID()
	scope := sourceScopeOf(f)
	rows := make([]model.AdmissionReservation, 0, span*windows)
	for i := range span * windows {
		names := make([]string, perBatch)
		for k := range names {
			names[k] = fmt.Sprintf("settle_bytes_series_%04d", (i*perBatch+k)%900)
		}
		r, err := reserveBatchOf(f, names)
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
	var candidates []model.SettleCandidate
	for n := range windows {
		var items []model.ChargeItem
		for _, r := range rows[n*span : n*span+span] {
			items = append(items, model.ChargeOf(r))
		}
		candidates = append(candidates, model.SettleCandidate{Group: group, N: uint64(n), Span: span, Batches: span, Charge: model.ChargeDigest(items)})
	}
	_, before := f.store.StatePatchStatsForTest()
	rep, err := f.store.SettleAdmissions(f.ctx, candidates)
	if err != nil || rep.Reservations != span*windows {
		t.Fatalf("settle: %+v, %v", rep, err)
	}
	_, after := f.store.StatePatchStatsForTest()
	per := float64(after-before) / float64(rep.Reservations)
	t.Logf("bytes of control commands per settled row: %.0f", per)
	if per > budget {
		t.Errorf("a settled row costs %.0f bytes of control commands, budget %d", per, budget)
	}
}
