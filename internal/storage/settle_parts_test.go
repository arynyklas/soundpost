// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// settlePass is one pass of the retention worker: the owner's outcomes are reconciled so the reservations of
// the appended batches are consumed rows, then the windows (and parts) the engine offers, leaving out what
// control settled, are settled.
func (w *windowEnv) settlePass() control.SettleReport {
	w.t.Helper()
	ctx := context.Background()
	if err := w.store.ReconcileAdmissions(ctx); err != nil {
		w.t.Fatal(err)
	}
	candidates, err := w.e.SettleCandidatesFor(ctx, w.store)
	if err != nil {
		w.t.Fatal(err)
	}
	rep, err := w.store.SettleAdmissions(ctx, candidates)
	if err != nil {
		w.t.Fatal(err)
	}
	return rep
}

// With the default window (4096 commands per group) a window is sealed after minutes of load, and until then every
// admitted batch stays a row of the control state: 64 groups hold a quarter of a million rows before the first
// window of any of them settles. Control must settle while the window is open, so that however long the
// acknowledgements go on the rows left stay within a couple of parts of each group.
func TestSettleKeepsUnsettledRowsBoundedUnderSustainedAcks(t *testing.T) {
	defer SetSnapshotWindow(SetSnapshotWindow(4096))
	w := newWindowEnv(t)
	ctx := context.Background()
	const total, step, bound = 300, 30, 2 * 64
	peak := 0
	for done := step; done <= total; done += step {
		w.addNamed(step)
		if err := w.store.ReconcileAdmissions(ctx); err != nil {
			t.Fatal(err)
		}
		candidates, err := w.e.SettleCandidates(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.store.SettleAdmissions(ctx, candidates); err != nil {
			t.Fatal(err)
		}
		rows := len(controlState(t, w.store).Reservations)
		peak = max(peak, rows)
		if rows > bound {
			t.Fatalf("%d consumed rows are unsettled after %d acknowledged batches of one group, bound %d: a window settles only when it is sealed", rows, done, bound)
		}
	}
	t.Logf("peak of unsettled rows over %d acknowledged batches: %d", total, peak)
}

// A window settled in parts is an incomplete record until the data seals it; its parts are proven the way a
// window is, a backup of it reconciles to the same certificate the rows gave and installs, and the sealed
// window replaces the record with a complete one.
func TestWindowSettledInPartsProvesRestoresAndCompletes(t *testing.T) {
	defer SetSnapshotWindow(SetSnapshotWindow(8))
	defer SetSettlePartSpan(SetSettlePartSpan(2))
	w := newWindowEnv(t)
	ctx := context.Background()
	w.addNamed(5) // window 0 holds five commands: parts 0 and 1 are complete, part 2 has one command
	if err := w.store.ReconcileAdmissions(ctx); err != nil {
		t.Fatal(err)
	}
	certRows := mustReconcile(t, sealBackup(t, w.e, w.store).Bundle)
	group := w.e.group(w.slot)

	candidates, err := w.e.SettleCandidates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || !candidates[0].Open || candidates[0].N != 0 || candidates[0].Part != 2 || len(candidates[0].Parts) != 2 {
		t.Fatalf("candidates %+v, want the two complete parts of the open window", candidates)
	}
	rep, err := w.store.SettleAdmissions(ctx, candidates)
	if err != nil || rep.Parts != 2 || rep.Windows != 0 || rep.Reservations != 4 {
		t.Fatalf("settle: %+v, %v; want 2 parts and 4 rows", rep, err)
	}
	state := controlState(t, w.store)
	rec, ok := state.Settlement.Lookup(model.SettledKey(group, 0))
	if !ok || rec.Complete() || rec.Part != 2 || len(rec.Parts) != 2 || rec.Count != 4 || len(state.Reservations) != 1 {
		t.Fatalf("after the first pass: record %+v (found %v), %d rows; want an incomplete record of 2 parts and 1 row", rec, ok, len(state.Reservations))
	}
	if again, err := w.store.SettleAdmissions(ctx, candidates); err != nil || again != (control.SettleReport{}) {
		t.Fatalf("settling the same parts again: %+v, %v", again, err)
	}

	sealed := sealBackup(t, w.e, w.store)
	cert := mustReconcile(t, sealed.Bundle)
	if !sameJSON(t, certRows.Charges, cert.Charges) || !sameDigests(certRows.SeriesDigest, cert.SeriesDigest) {
		t.Fatal("the certificate of a window settled in parts differs from the one the rows gave")
	}
	certMatchesQuotas(t, cert, state.Quotas)
	var evidence *WindowEvidence
	for i := range sealed.Bundle.Quota.Windows {
		if win := &sealed.Bundle.Quota.Windows[i]; win.Group == group && win.N == 0 {
			evidence = win
		}
	}
	if evidence == nil || evidence.Part != 2 || len(evidence.Parts) != 3 || evidence.Detail {
		t.Fatalf("window evidence %+v: want the three parts of the window the data holds, not a detail window", evidence)
	}
	restored, err := installInto(t, w, sealed, sealed.Bundle)
	if err != nil {
		t.Fatalf("a bundle with a window settled in parts did not install: %v", err)
	}
	if err = restored.CommitQuotaReconciliation(ctx, cert); err != nil {
		t.Fatalf("the restored index does not cross-check the certificate: %v", err)
	}

	w.addNamed(5) // ten commands: window 0 is sealed, window 1 holds two (one complete part)
	rep2 := w.settlePass()
	if rep2.Windows != 1 || rep2.Parts != 3 || rep2.Reservations != 6 {
		t.Fatalf("second pass %+v; want window 0 completed, 3 parts and 6 rows (parts 2 and 3 of window 0, part 0 of window 1)", rep2)
	}
	state = controlState(t, w.store)
	done, ok := state.Settlement.Lookup(model.SettledKey(group, 0))
	if !ok || !done.Complete() || done.Count != 8 || len(done.Parts) != 0 || len(state.Reservations) != 0 {
		t.Fatalf("after the window sealed: record %+v (found %v), %d rows; want a complete record of 8 and no rows", done, ok, len(state.Reservations))
	}
	open, ok := state.Settlement.Lookup(model.SettledKey(group, 1))
	if !ok || open.Complete() || open.Count != 2 || open.Part != 2 {
		t.Fatalf("window 1: record %+v (found %v); want an incomplete record of one part", open, ok)
	}
	sealed = sealBackup(t, w.e, w.store)
	cert = mustReconcile(t, sealed.Bundle)
	certMatchesQuotas(t, cert, state.Quotas)
	if restored, err = installInto(t, w, sealed, sealed.Bundle); err != nil {
		t.Fatalf("a bundle with a completed window and a window settled in parts did not install: %v", err)
	}
	if err = restored.CommitQuotaReconciliation(ctx, cert); err != nil {
		t.Fatal(err)
	}
	if spans := state.Settlement.Spans[group.String()]; spans != 8 {
		t.Fatalf("the persisted span of the group is %d, parts must leave it alone", spans)
	}
}

// Windows an earlier release settled whole (parts did not exist) stay valid beside the parts of the windows that
// follow them: the persisted span is not touched and nothing is re-derived.
func TestWindowsSettledWholeStayValidBesideParts(t *testing.T) {
	defer SetSnapshotWindow(SetSnapshotWindow(8))
	old := SetSettlePartSpan(0) // an earlier release: no parts
	defer SetSettlePartSpan(old)
	w := newWindowEnv(t)
	ctx := context.Background()
	w.addNamed(9) // window 0 sealed, one command in window 1
	if rep := w.settlePass(); rep.Windows != 1 || rep.Parts != 0 || rep.Reservations != 8 {
		t.Fatalf("whole-window pass %+v", rep)
	}
	group := w.e.group(w.slot)
	SetSettlePartSpan(2)
	w.addNamed(5) // fourteen commands: window 1 holds six, three complete parts
	rep := w.settlePass()
	if rep.Windows != 0 || rep.Parts != 3 || rep.Reservations != 6 {
		t.Fatalf("pass beside a whole window: %+v; want the 3 parts of window 1", rep)
	}
	state := controlState(t, w.store)
	if len(state.Reservations) != 0 {
		t.Fatalf("%d rows left", len(state.Reservations))
	}
	whole, ok := state.Settlement.Lookup(model.SettledKey(group, 0))
	if !ok || !whole.Complete() || whole.Count != 8 {
		t.Fatalf("window 0: %+v (found %v)", whole, ok)
	}
	sealed := sealBackup(t, w.e, w.store)
	cert := mustReconcile(t, sealed.Bundle)
	certMatchesQuotas(t, cert, state.Quotas)
	restored, err := installInto(t, w, sealed, sealed.Bundle)
	if err != nil {
		t.Fatalf("a bundle with a window settled whole and a window settled in parts did not install: %v", err)
	}
	if err = restored.CommitQuotaReconciliation(ctx, cert); err != nil {
		t.Fatal(err)
	}
}

// Whatever a bundle says about a window settled in parts is checked against the data.
func TestForgedPartSettlementIsRefused(t *testing.T) {
	defer SetSnapshotWindow(SetSnapshotWindow(8))
	defer SetSettlePartSpan(SetSettlePartSpan(2))
	w := newWindowEnv(t)
	w.addNamed(7) // three complete parts of window 0 and one command
	if rep := w.settlePass(); rep.Parts != 3 {
		t.Fatalf("pass %+v", rep)
	}
	sealed := sealBackup(t, w.e, w.store)
	clone := func() BackupBundle {
		raw, err := json.Marshal(sealed.Bundle)
		if err != nil {
			t.Fatal(err)
		}
		var b BackupBundle
		if err = json.Unmarshal(raw, &b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	reseal := func(b BackupBundle) BackupBundle { b.Digest = b.seal(); return b }
	partial := func(b BackupBundle) (string, model.SettledWindow) {
		for key, sw := range b.Cut.Settlement.Windows {
			if !sw.Complete() {
				return key, sw
			}
		}
		t.Fatal("no window settled in parts")
		return "", model.SettledWindow{}
	}
	if _, err := ReconcileQuota(sealed.Bundle); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	t.Run("a settled part's digest changed", func(t *testing.T) {
		b := clone()
		key, sw := partial(b)
		sw.Parts[0].Charge[0] ^= 1
		b.Cut.Settlement.Windows[key] = sw
		if _, err := ReconcileQuota(reseal(b)); err == nil {
			t.Fatal("a settled part digest the data does not carry was accepted")
		}
	})
	t.Run("a settled part dropped from the record", func(t *testing.T) {
		b := clone()
		key, sw := partial(b)
		sw.Parts = sw.Parts[1:]
		sw.Count -= 2
		b.Cut.Settlement.Windows[key] = sw
		if _, err := ReconcileQuota(reseal(b)); err == nil {
			t.Fatal("a part nobody holds rows or a settlement for was accepted")
		}
	})
	t.Run("a part claimed that the data does not state", func(t *testing.T) {
		b := clone()
		key, sw := partial(b)
		sw.Parts = append(sw.Parts, model.SettledPart{J: 3, Count: 1, Charge: sw.Parts[0].Charge})
		sw.Count++
		b.Cut.Settlement.Windows[key] = sw
		if _, err := ReconcileQuota(reseal(b)); err == nil {
			t.Fatal("a settled part the window does not hold was accepted")
		}
	})
	t.Run("an incomplete record that disagrees with itself", func(t *testing.T) {
		b := clone()
		key, sw := partial(b)
		sw.Count++
		b.Cut.Settlement.Windows[key] = sw
		if _, err := ReconcileQuota(reseal(b)); err == nil {
			t.Fatal("a record whose count is not the sum of its parts was accepted")
		}
	})
}
