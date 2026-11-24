// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/storage"
)

// The worker settles the consumed reservations of the sealed data windows on its expiry schedule,
// through the ResidualPlane the application wraps the engine in: control's rows drop, no quota moves
// and the status counts what was settled.
func TestWorkerSettlesConsumedReservationsOfSealedWindows(t *testing.T) {
	old := storage.SetSnapshotWindow(2)
	t.Cleanup(func() { storage.SetSnapshotWindow(old) })
	f := newFx(t, options{controlResiduals: true})
	for i := range 40 { // many slots, so some of them hold sealed windows of two commands
		if _, _, err := f.append(int64(100+i), "series"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.store.ReconcileAdmissions(f.ctx); err != nil {
		t.Fatal(err)
	}
	var before control.State
	if err := f.store.View(f.ctx, func(s control.State) error { before = s; return nil }); err != nil {
		t.Fatal(err)
	}
	if len(before.Reservations) != 40 || before.Settlement != nil {
		t.Fatalf("setup: %d rows", len(before.Reservations))
	}
	f.run()
	st := f.svc.Status()
	var after control.State
	if err := f.store.View(f.ctx, func(s control.State) error { after = s; return nil }); err != nil {
		t.Fatal(err)
	}
	if st.SettledWindows == 0 || st.SettledReservations != uint64(len(before.Reservations)-len(after.Reservations)) || after.Settlement == nil || uint64(len(after.Settlement.Windows)) != st.SettledWindows {
		t.Fatalf("worker pass: status %+v, %d rows before and %d after", st, len(before.Reservations), len(after.Reservations))
	}
	a, _ := json.Marshal(before.Quotas)
	b, _ := json.Marshal(after.Quotas)
	if string(a) != string(b) {
		t.Fatal("the settlement pass moved a quota")
	}
	f.advance(2 * time.Hour) // the next expiry pass is due; it finds nothing left that control can prove
	f.run()
	if again := f.svc.Status(); again.SettledWindows != st.SettledWindows {
		t.Fatalf("a second pass settled %d more windows", again.SettledWindows-st.SettledWindows)
	}
}

// Control state must stay bounded under sustained load: the consumed reservations of a sealed window are
// settled by the next pass of the worker (one minute), not by the hourly expiry pass. At the single-host
// gate (~300 batches per second) an hour of unsettled rows is ~1 GB of control state and every
// control snapshot cut rewrites it (L2w20Admission6: 2 KB per admitted batch, nothing ever settled).
func TestWorkerSettlesOnEveryPassNotOnlyOnTheExpirySchedule(t *testing.T) {
	old := storage.SetSnapshotWindow(2)
	t.Cleanup(func() { storage.SetSnapshotWindow(old) })
	f := newFx(t, options{controlResiduals: true})
	f.run() // the first pass runs the expiry schedule: nothing to settle yet
	for i := range 40 {
		if _, _, err := f.append(int64(100+i), "series"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.store.ReconcileAdmissions(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.advance(time.Minute) // far below the expiry interval
	f.run()
	if st := f.svc.Status(); st.SettledWindows == 0 || st.SettledReservations == 0 {
		t.Fatalf("a pass a minute after the last one settled nothing: %+v", st)
	}
}
