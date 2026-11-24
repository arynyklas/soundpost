// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"testing"
)

// A settle command is applied by the control group under the lock every control writer shares: it rewrites
// the charge rows of every reservation it drops (a row per quota key and series), so its cost grows with the
// reservations it carries. At the single-host gate a pass every five seconds carried about three thousand
// of them in one command, the control group was held for most of a second by each pass, and the p95 of the
// acknowledgements sat at 700 ms with a p50 of 35 ms; with commands of 256 rows each held it for 80 ms and
// the p95 sat at 400 ms (L2w20Admission18/19). One command must drop a bounded number of rows; the pass
// settles the rest with further commands, all of them in one SettleAdmissions call that reads the books once.
func TestSettleCommandDropsABoundedNumberOfRowsAndThePassSettlesAll(t *testing.T) {
	defer SetSnapshotWindow(SetSnapshotWindow(4096))
	w := newWindowEnv(t)
	ctx := context.Background()
	const acked, bound = 700, 64
	w.addNamed(acked)
	if err := w.store.ReconcileAdmissions(ctx); err != nil {
		t.Fatal(err)
	}
	candidates, err := w.e.SettleCandidates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before := controlState(t, w.store).Revision
	rep, err := w.store.SettleAdmissions(ctx, candidates)
	if err != nil {
		t.Fatal(err)
	}
	commands := int(controlState(t, w.store).Revision - before)
	complete := acked / 64 * 64 // only complete parts are offered
	if rep.Reservations != complete {
		t.Fatalf("the pass dropped %d rows (%d parts) of %d acknowledged batches, want every complete part: %d", rep.Reservations, rep.Parts, acked, complete)
	}
	if want := (rep.Reservations + bound - 1) / bound; commands < want {
		t.Fatalf("the pass dropped %d rows in %d commands, want at least %d: a command drops at most %d rows", rep.Reservations, commands, want, bound)
	}
	next, err := w.store.SettleAdmissions(ctx, candidates)
	if err != nil {
		t.Fatal(err)
	}
	if left := len(controlState(t, w.store).Reservations); next.Reservations != 0 || left != acked-complete {
		t.Fatalf("a second pass dropped %d rows and %d are left of %d acknowledged batches; want 0 dropped and %d left (the open part)", next.Reservations, left, acked, acked-complete)
	}
}
