// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// settleBatch is normalizedAs with a chosen metric name: batches that share a name share a series, so
// the series refcounts the quota keeps (and a settlement must fold) are not all one.
func settleBatch(t *testing.T, store *control.Store, a *auth.Service, c auth.SourceCredential, d model.SourceDescriptor, producer model.ID, at model.UnixNano, name string) (auth.Scope, model.NormalizedBatch) {
	t.Helper()
	scope, e := a.SourceScope(context.Background(), c, false)
	if e != nil {
		t.Fatal(e)
	}
	src, e := a.SourceAuthority(context.Background(), c, true)
	if e != nil {
		t.Fatal(e)
	}
	b := model.Batch{Version: 1, Project: d.Project, Source: d.Source, Producer: producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: at, Resource: model.Resource{Service: src.Policy.Resources.Services[0], Environment: src.Policy.Resources.Environments[0], Build: src.Policy.Resources.Builds[0], Instance: src.Policy.Resources.Instances[0]}, Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: ptrBits(0x3ff0000000000000), Type: "counter", Unit: "1"}}}}}
	slot, _ := model.OwnerSlot(d.Org, b.Project, b.Source, b.Producer, b.Records[0])
	b.RouteSlot = slot
	raw := mustJSON(t, b)
	policyBytes := mustJSON(t, src.Policy)
	n := model.NormalizedBatch{Batch: b, Org: d.Org, Hash: model.HashCanonical(raw), Canonical: raw, PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyHash: model.HashCanonical(policyBytes).String(), AdmissionAt: 10, Deadlines: []model.SignalDeadline{{Kind: model.Metric, RetainUntil: 100}}}
	n.Reservation, e = store.ReserveAdmission(context.Background(), scope, n)
	if e != nil {
		t.Fatal(e)
	}
	return scope, n
}

type settleItem struct {
	scope   auth.Scope
	batch   model.NormalizedBatch
	receipt model.Receipt
}

// sameSlotNames returns count metric names that all route to one slot for the producer, so a
// history of batches with different series still fills one slot's windows.
func sameSlotNames(t *testing.T, a *auth.Service, c auth.SourceCredential, d model.SourceDescriptor, producer model.ID, count int) []string {
	t.Helper()
	src, err := a.SourceAuthority(context.Background(), c, true)
	if err != nil {
		t.Fatal(err)
	}
	res := model.Resource{Service: src.Policy.Resources.Services[0], Environment: src.Policy.Resources.Environments[0], Build: src.Policy.Resources.Builds[0], Instance: src.Policy.Resources.Instances[0]}
	var names []string
	want := -1
	for salt := range 1 << 16 {
		name := fmt.Sprintf("series_%d", salt)
		rec := model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: 1, Resource: res, Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: ptrBits(0x3ff0000000000000), Type: "counter", Unit: "1"}}}
		slot, err := model.OwnerSlot(d.Org, d.Project, d.Source, producer, rec)
		if err != nil {
			t.Fatal(err)
		}
		if want < 0 {
			want = int(slot)
		}
		if int(slot) == want {
			names = append(names, name)
			if len(names) == count {
				return names
			}
		}
	}
	t.Fatal("not enough metric names route to one slot")
	return nil
}

// addNamed admits and appends n batches over three series of one slot and keeps what the retry
// tests need.
func (w *windowEnv) addNamed(n int) []settleItem {
	w.t.Helper()
	names := sameSlotNames(w.t, w.service, w.cred, w.desc, w.producer, 3)
	out := make([]settleItem, 0, n)
	for i := range n {
		scope, b := settleBatch(w.t, w.store, w.service, w.cred, w.desc, w.producer, w.next, names[i%3])
		w.next++
		w.slot = b.RouteSlot
		r, err := w.e.Append(context.Background(), scope, b)
		if err != nil {
			w.t.Fatal(err)
		}
		out = append(out, settleItem{scope, b, r})
	}
	return out
}

func controlState(t *testing.T, store *control.Store) control.State {
	t.Helper()
	var out control.State
	if err := store.View(context.Background(), func(st control.State) error { out = st; return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

func sameJSON(t *testing.T, a, b any) bool {
	t.Helper()
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	return bytes.Equal(x, y)
}

func sealBackup(t *testing.T, e *Engine, store *control.Store) SealedBackup {
	t.Helper()
	backup, err := e.BeginBackup(context.Background(), controlCut(t, e, store))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := backup.Seal(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func installInto(t *testing.T, w *windowEnv, sealed SealedBackup, bundle BackupBundle) (*Engine, error) {
	t.Helper()
	return openRestoredEngine(t, t.TempDir(), w.service, w.store, bundle.Identity, func(e *Engine, raft string) error {
		return e.InstallBackup(context.Background(), raft, bundle, func(slot uint16) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(snapshotStream(t, sealed.Snapshots[slot]))), nil
		})
	})
}

// Settling replaces the consumed reservation rows of the sealed data windows by their digest and
// folded charge: control state and the control cut of a backup stop growing with the batches ever
// admitted, no quota moves, and the certificate a backup yields is the one the full row list gave.
func TestSettlementBoundsControlRowsAndKeepsEveryChargeExact(t *testing.T) {
	w := newWindowEnv(t)
	ctx := context.Background()
	w.addNamed(21) // five sealed windows of four commands and one command in the sixth
	if err := w.store.ReconcileAdmissions(ctx); err != nil {
		t.Fatal(err)
	}
	before := controlState(t, w.store)
	if len(before.Reservations) != 21 || len(before.AdmissionKeys) != 21 || before.Settlement != nil {
		t.Fatalf("fixture: %d rows, %d keys, settlement %v", len(before.Reservations), len(before.AdmissionKeys), before.Settlement)
	}
	unsettled := sealBackup(t, w.e, w.store)
	certBefore := mustReconcile(t, unsettled.Bundle)

	candidates, err := w.e.SettleCandidates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 5 {
		t.Fatalf("%d candidate windows, want the 5 sealed ones", len(candidates))
	}
	rep, err := w.store.SettleAdmissions(ctx, candidates)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Windows != 5 || rep.Reservations != 20 {
		t.Fatalf("settled %+v, want 5 windows and 20 reservations", rep)
	}
	after := controlState(t, w.store)
	if len(after.Reservations) != 1 || len(after.AdmissionKeys) != 1 || len(after.Settlement.Windows) != 5 {
		t.Fatalf("after: %d rows, %d keys, %d settled windows; want 1, 1, 5", len(after.Reservations), len(after.AdmissionKeys), len(after.Settlement.Windows))
	}
	if !sameJSON(t, before.Quotas, after.Quotas) {
		t.Fatal("settling moved a quota")
	}
	again, err := w.store.SettleAdmissions(ctx, candidates)
	if err != nil || again != (control.SettleReport{}) {
		t.Fatalf("settling the same windows again: %+v, %v", again, err)
	}
	if err = w.store.ReconcileAdmissions(ctx); err != nil {
		t.Fatalf("the owner's outcomes of settled windows are not reconcilable: %v", err)
	}

	settled := sealBackup(t, w.e, w.store)
	if got := len(settled.Bundle.Cut.Reservations); got != 1 {
		t.Fatalf("the control cut still holds %d reservation rows, want 1", got)
	}
	certAfter := mustReconcile(t, settled.Bundle)
	if !sameJSON(t, certBefore.Charges, certAfter.Charges) || !sameDigests(certBefore.SeriesDigest, certAfter.SeriesDigest) {
		t.Fatal("the quota certificate of the settled control state differs from the one the full row list gave")
	}
	certMatchesQuotas(t, certAfter, after.Quotas)

	restored, err := installInto(t, w, settled, settled.Bundle)
	if err != nil {
		t.Fatalf("a bundle with settled windows did not install: %v", err)
	}
	if err = restored.CommitQuotaReconciliation(ctx, certAfter); err != nil {
		t.Fatalf("the restored index does not cross-check the settled certificate: %v", err)
	}
}

// A retry of a batch whose reservation was settled finds no row: control asks the owner, answers it
// as consumed at the receipt's cursor and charges nothing; the data's own duplicate check returns
// the stored receipt.
func TestRetryOfASettledBatchIsAnsweredConsumedAndNotChargedTwice(t *testing.T) {
	w := newWindowEnv(t)
	ctx := context.Background()
	items := w.addNamed(9)
	if err := w.store.ReconcileAdmissions(ctx); err != nil {
		t.Fatal(err)
	}
	candidates, err := w.e.SettleCandidates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := w.store.SettleAdmissions(ctx, candidates); err != nil || rep.Windows != 2 {
		t.Fatalf("settle: %+v, %v", rep, err)
	}
	before := controlState(t, w.store)
	for _, i := range []int{0, 3, 7} { // inside window 0, at its last command, inside window 1
		it := items[i]
		r, err := w.store.ReserveAdmission(ctx, it.scope, it.batch)
		if err != nil {
			t.Fatalf("retry of batch %d: %v", i, err)
		}
		if r.State != "consumed" || r.Cursor == nil || *r.Cursor != it.receipt.Cursor {
			t.Fatalf("retry of batch %d answered %s at %v, want consumed at %v", i, r.State, r.Cursor, it.receipt.Cursor)
		}
		retried := it.batch
		retried.Reservation = r
		got, err := w.e.Append(ctx, it.scope, retried)
		if err != nil || got.Cursor != it.receipt.Cursor || got.Hash != it.receipt.Hash {
			t.Fatalf("the data answered the retry of batch %d with %+v, %v", i, got, err)
		}
		// ingest.Admit finalizes nothing for a reservation that comes back consumed at the receipt's
		// cursor; a finalize of the settled reservation is nonetheless harmless.
		if err = w.store.FinalizeAdmission(ctx, it.scope, model.FinalizeAdmission{ReservationID: it.batch.Reservation.ID, Cursor: got.Cursor}); err != nil {
			t.Fatalf("finalizing the settled reservation of batch %d: %v", i, err)
		}
	}
	after := controlState(t, w.store)
	if !sameJSON(t, before.Quotas, after.Quotas) || len(after.Reservations) != len(before.Reservations) || len(after.AdmissionKeys) != len(before.AdmissionKeys) {
		t.Fatalf("retries of settled batches changed control: %d rows (was %d), quotas equal %v", len(after.Reservations), len(before.Reservations), sameJSON(t, before.Quotas, after.Quotas))
	}
	// A batch the data does not hold is still a new admission, settled windows or not.
	scope, fresh := settleBatch(t, w.store, w.service, w.cred, w.desc, w.producer, w.next, "series_new")
	if fresh.Reservation.State != "reserved" {
		t.Fatalf("a new batch was answered %s", fresh.Reservation.State)
	}
	if _, err = w.e.Append(ctx, scope, fresh); err != nil {
		t.Fatal(err)
	}
}

// Whatever a bundle says about settled windows is checked against the data: another digest is
// refused by the reconciliation; a folded charge the data windows do not add up to is refused by
// the install even when the bundle is re-sealed consistently.
func TestForgedSettlementIsRefused(t *testing.T) {
	w := newWindowEnv(t)
	ctx := context.Background()
	w.addNamed(13)
	if err := w.store.ReconcileAdmissions(ctx); err != nil {
		t.Fatal(err)
	}
	candidates, err := w.e.SettleCandidates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := w.store.SettleAdmissions(ctx, candidates); err != nil || rep.Windows != 3 {
		t.Fatalf("settle: %+v, %v", rep, err)
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
	orgKey := "org:" + w.desc.Org.String()
	t.Run("a settled window's digest changed", func(t *testing.T) {
		b := clone()
		for key, sw := range b.Cut.Settlement.Windows {
			sw.Charge[0] ^= 1
			b.Cut.Settlement.Windows[key] = sw
			break
		}
		if _, err := ReconcileQuota(reseal(b)); err == nil {
			t.Fatal("a settled digest the data window does not carry was accepted")
		}
	})
	t.Run("a settled window dropped from the cut", func(t *testing.T) {
		b := clone()
		for key := range b.Cut.Settlement.Windows {
			delete(b.Cut.Settlement.Windows, key)
			break
		}
		if _, err := ReconcileQuota(reseal(b)); err == nil {
			t.Fatal("a window nobody holds rows or a settlement for was accepted")
		}
	})
	t.Run("a folded byte count inflated", func(t *testing.T) {
		b := clone()
		c := b.Cut.Settlement.Charges[orgKey]
		c.Bytes++
		b.Cut.Settlement.Charges[orgKey] = c
		b = reseal(b)
		if _, err := ReconcileQuota(b); err != nil {
			t.Fatalf("fixture: the forged cut should be self-consistent: %v", err)
		}
		if _, err := installInto(t, w, sealed, b); err == nil {
			t.Fatal("a settled charge the installed windows do not add up to was installed")
		}
	})
	t.Run("a folded series refcount lowered", func(t *testing.T) {
		b := clone()
		for key, c := range b.Cut.Settlement.Charges {
			for id := range c.Series {
				c.Series[id]--
				break
			}
			b.Cut.Settlement.Charges[key] = c
			break
		}
		if _, err := installInto(t, w, sealed, reseal(b)); err == nil {
			t.Fatal("a settled series refcount the installed windows do not carry was installed")
		}
	})
	t.Run("the genuine bundle installs", func(t *testing.T) {
		restored, err := installInto(t, w, sealed, sealed.Bundle)
		if err != nil {
			t.Fatal(err)
		}
		if err = restored.CommitQuotaReconciliation(ctx, mustReconcile(t, sealed.Bundle)); err != nil {
			t.Fatal(err)
		}
	})
}

// A window settled and redacted afterwards lists its reservations as a detail window (the erased
// records' series are charged but no longer indexed); the certificate still cross-checks the
// restored index.
func TestSettledWindowRedactedLaterRestoresWithExactSeries(t *testing.T) {
	x := newEraseEnv(t)
	ctx := context.Background()
	if err := x.store.BindAdmissionOwner(x.e); err != nil {
		t.Fatal(err)
	}
	producer := model.NewID()
	for range 9 { // windows 0 and 1 sealed, one command open; every batch carries a canary series
		x.appendMixedAs(producer, eraseCanary, bothDeadlines)
	}
	if err := x.store.ReconcileAdmissions(ctx); err != nil {
		t.Fatal(err)
	}
	candidates, err := x.e.SettleCandidates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := x.store.SettleAdmissions(ctx, candidates); err != nil || rep.Windows != 2 {
		t.Fatalf("settle: %+v, %v", rep, err)
	}
	if _, err = x.e.EraseDeleted(ctx, []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}, nil); err != nil {
		t.Fatal(err)
	}
	backup, err := x.e.BeginBackup(ctx, controlCut(t, x.e, x.store))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := backup.Seal(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	detail := 0
	for _, win := range sealed.Bundle.Quota.Windows {
		if win.Detail && win.N < 2 {
			detail++
		}
	}
	if detail != 2 {
		t.Fatalf("%d settled windows listed as detail windows, want the 2 the erasure redacted", detail)
	}
	cert, err := ReconcileQuota(sealed.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	certMatchesQuotas(t, cert, controlState(t, x.store).Quotas)
	restored, err := openRestoredEngine(t, t.TempDir(), x.a, x.store, sealed.Bundle.Identity, func(e *Engine, raft string) error {
		return e.InstallBackup(ctx, raft, sealed.Bundle, func(slot uint16) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(snapshotStream(t, sealed.Snapshots[slot]))), nil
		})
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if err = restored.CommitQuotaReconciliation(ctx, cert); err != nil {
		t.Fatalf("the series of the erased records of settled windows are not reconciled with the restored index: %v", err)
	}
}

// Control proves a window equal to its own rows before it drops them: a digest it does not
// reproduce, a window with a reservation still unconsumed, and a span other than the group's leave the
// rows alone.
func TestSettlementRefusesWhatControlCannotProve(t *testing.T) {
	w := newWindowEnv(t)
	ctx := context.Background()
	w.addNamed(9)
	candidates, err := w.e.SettleCandidates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Fatalf("%d candidates, want 2", len(candidates))
	}
	// Nothing was finalized yet: every row is still reserved, so no window is provable.
	if rep, err := w.store.SettleAdmissions(ctx, candidates); err != nil || rep != (control.SettleReport{}) {
		t.Fatalf("settled windows whose reservations are not consumed: %+v, %v", rep, err)
	}
	if err = w.store.ReconcileAdmissions(ctx); err != nil {
		t.Fatal(err)
	}
	wrong := append([]model.SettleCandidate(nil), candidates...)
	wrong[0].Charge[0] ^= 1
	wrong[1].Span++
	if rep, err := w.store.SettleAdmissions(ctx, wrong); err != nil || rep != (control.SettleReport{}) {
		t.Fatalf("settled windows control cannot prove: %+v, %v", rep, err)
	}
	if st := controlState(t, w.store); len(st.Reservations) != 9 || st.Settlement != nil {
		t.Fatalf("rows dropped without proof: %d rows", len(st.Reservations))
	}
	if rep, err := w.store.SettleAdmissions(ctx, candidates); err != nil || rep.Windows != 2 {
		t.Fatalf("the genuine candidates: %+v, %v", rep, err)
	}
}

// certMatchesQuotas fails unless the certificate charges exactly what the control quotas hold:
// every key, its bytes and the refcount of every series.
func certMatchesQuotas(t *testing.T, cert QuotaReconciliation, quotas map[string]model.QuotaState) {
	t.Helper()
	for key, q := range quotas {
		c := cert.Charges[key]
		if q.Bytes != c.Bytes || len(q.Series) != len(c.Series) {
			t.Fatalf("certificate charge of %s is %d bytes / %d series, control holds %d / %d", key, c.Bytes, len(c.Series), q.Bytes, len(q.Series))
		}
		for id, n := range q.Series {
			if c.Series[id] != n {
				t.Fatalf("series %s of %s: certificate %d, control %d", id, key, c.Series[id], n)
			}
		}
	}
}
