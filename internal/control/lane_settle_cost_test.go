// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// settleFixture admits windows of span rows (batches of perBatch series out of pool) and answers their settle candidates.
func settleFixture(t *testing.T, f *fenceFx, span, windows, perBatch, pool int) []model.SettleCandidate {
	t.Helper()
	group := model.NewID()
	scope := sourceScopeOf(f)
	rng := rand.New(rand.NewPCG(5, 6))
	rows := make([]model.AdmissionReservation, 0, span*windows)
	for i := range span * windows {
		picked := map[int]bool{}
		names := make([]string, 0, perBatch)
		for len(names) < perBatch {
			if s := rng.IntN(pool); !picked[s] {
				picked[s] = true
				names = append(names, fmt.Sprintf("settle_cost_series_%05d", s))
			}
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
		candidates = append(candidates, model.SettleCandidate{Group: group, N: uint64(n), Span: uint64(span), Batches: uint64(span), Charge: model.ChargeDigest(items)})
	}
	return candidates
}

// TestMeasureSettleCommandCost is a measurement: what a settlement command of 64 rows of 12 series costs the lane to judge and to
// propose, and the bytes it carries.
func TestMeasureSettleCommandCost(t *testing.T) {
	f := newFenceFxCompact(t)
	if err := f.store.BindAdmissionOwner(&reconcileOwner{}); err != nil {
		t.Fatal(err)
	}
	const span, windows = 64, 12
	candidates := settleFixture(t, f, span, windows, 12, 900) // the source's quota is 1,000 series
	before := f.store.LaneCostForTest()
	rep, err := f.store.SettleAdmissions(f.ctx, candidates)
	if err != nil || rep.Reservations != span*windows {
		t.Fatalf("settle: %+v, %v", rep, err)
	}
	after := f.store.LaneCostForTest()
	rounds := float64(after.Rounds - before.Rounds)
	t.Logf("%.0f settlement commands of %d rows: build %.2f ms, propose %.2f ms, %.0f KB each", rounds, span,
		float64(after.Build-before.Build)/rounds/1e6, float64(after.Propose-before.Propose)/rounds/1e6, float64(after.PatchBytes-before.PatchBytes)/rounds/1024)
}
