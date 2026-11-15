// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup_test

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// appendSameSlot admits one metric batch of a fixed producer, so every batch of a test lands in
// one slot and fills its windows.
func (l *live) appendSameSlot(producer model.ID, at int64, name string) ack {
	l.t.Helper()
	b := l.batchAt(at, name)
	b.Producer = producer
	slot, err := model.OwnerSlot(l.desc.Org, b.Project, b.Source, b.Producer, b.Records[0])
	if err != nil {
		l.t.Fatal(err)
	}
	b.RouteSlot = slot
	n := l.normalize(b)
	scope, err := l.app.Auth.SourceScope(l.ctx, l.sourceC, false)
	if err != nil {
		l.t.Fatal(err)
	}
	if n.Reservation, err = l.app.Control.ReserveAdmission(l.ctx, scope, n); err != nil {
		l.t.Fatal(err)
	}
	receipt, err := l.app.Storage.Append(l.ctx, scope, n)
	if err != nil {
		l.t.Fatal(err)
	}
	a := ack{batch: b, at: at, receipt: receipt, bytes: uint64(n.Reservation.Bytes)}
	l.acked = append(l.acked, a)
	return a
}

// An installation whose control settled the consumed reservations of its sealed data windows
// backs up and restores with every charge exact, the settlement carried into the restored
// control state, and a client's retry of a settled batch answered from the data without a second
// charge.
func TestRestoreOfSettledReservationsKeepsTheQuotaAndTheRetries(t *testing.T) {
	old := storage.SetSnapshotWindow(2)
	t.Cleanup(func() { storage.SetSnapshotWindow(old) })
	l := newLive(t)
	producer := model.NewID()
	var acks []ack
	for i := range 7 { // three sealed windows of two commands and one command in the fourth
		acks = append(acks, l.appendSameSlot(producer, int64(100+i), "series_"+string(rune('a'+i%3))))
	}
	l.reconcile()
	candidates, err := l.app.Storage.SettleCandidates(l.ctx)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := l.app.Control.SettleAdmissions(l.ctx, candidates)
	if err != nil || rep.Windows != 3 || rep.Reservations != 6 {
		t.Fatalf("settle: %+v, %v", rep, err)
	}
	var liveState control.State
	if err = l.app.Control.View(l.ctx, func(st control.State) error { liveState = st; return nil }); err != nil {
		t.Fatal(err)
	}
	if len(liveState.Reservations) != 1 || liveState.Settlement == nil {
		t.Fatalf("control holds %d rows after settling", len(liveState.Reservations))
	}

	m := l.mustBackup()
	root := l.newRoot()
	if _, err = l.restoreTo(root, m, l.authority); err != nil {
		t.Fatal(err)
	}
	r := l.openRestored(root)
	if _, err = r.activate(l.authority); err != nil {
		t.Fatal(err)
	}
	var restored control.State
	if err = r.app.Control.View(l.ctx, func(st control.State) error { restored = st; return nil }); err != nil {
		t.Fatal(err)
	}
	if !sameJSON(t, liveState.Quotas, restored.Quotas) {
		t.Fatalf("restored quotas differ from the live ones:\nlive     %+v\nrestored %+v", liveState.Quotas, restored.Quotas)
	}
	if !sameJSON(t, liveState.Settlement, restored.Settlement) || len(restored.Reservations) != 1 {
		t.Fatalf("the settlement did not survive the restore: %d rows", len(restored.Reservations))
	}

	r.recoveryAdmin()
	issued := r.reconcile(auth.Reconciliation{Kind: auth.ReconcileSource, Source: l.source})
	sourceC, err := r.app.Auth.AuthenticateSource(l.ctx, issued.Credential, "", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{0, 3, 5} { // each inside a settled window
		sc, err := r.app.Auth.SourceScope(l.ctx, sourceC, false)
		if err != nil {
			t.Fatal(err)
		}
		n := l.normalizeWith(r.app, sourceC, acks[i].batch)
		if n.Reservation, err = r.app.Control.ReserveAdmission(l.ctx, sc, n); err != nil {
			t.Fatalf("retry %d: %v", i, err)
		}
		got, err := r.app.Storage.Append(l.ctx, sc, n)
		if err != nil || !sameJSON(t, got, acks[i].receipt) {
			t.Fatalf("retry %d: receipt changed or refused: %v", i, err)
		}
	}
	var after control.State
	if err = r.app.Control.View(l.ctx, func(st control.State) error { after = st; return nil }); err != nil {
		t.Fatal(err)
	}
	if !sameJSON(t, restored.Quotas, after.Quotas) || len(after.Reservations) != len(restored.Reservations) {
		t.Fatalf("retrying settled batches in the restored installation charged them again: %d rows (was %d)", len(after.Reservations), len(restored.Reservations))
	}
}
