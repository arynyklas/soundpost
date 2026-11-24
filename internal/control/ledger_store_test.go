// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// lifeShape is what an admission lifecycle leaves, without the identities that differ from one
// fixture to the next: reservations by state, per quota tier kind the bytes and the sorted reference
// counts of its series, and the settlement's windows and folded charge.
type lifeShape struct {
	States  map[string]int
	Tiers   map[string][]uint64
	Windows int
	Charges map[string][]uint64
}

func shapeOf(st control.State) lifeShape {
	s := lifeShape{States: map[string]int{}, Tiers: map[string][]uint64{}, Charges: map[string][]uint64{}}
	for _, r := range st.Reservations {
		s.States[r.State]++
	}
	kind := func(tier string) string { return tier[:strings.IndexByte(tier, ':')] }
	for tier, q := range st.Quotas {
		counts := []uint64{}
		for _, n := range q.Series {
			counts = append(counts, n)
		}
		slices.Sort(counts)
		s.Tiers[kind(tier)] = append([]uint64{uint64(q.Bytes), uint64(q.MaxSeries)}, counts...)
	}
	if st.Settlement != nil {
		s.Windows = len(st.Settlement.Windows)
		for tier, c := range st.Settlement.Charges {
			counts := []uint64{}
			for _, n := range c.Series {
				counts = append(counts, n)
			}
			slices.Sort(counts)
			s.Charges[kind(tier)] = append([]uint64{uint64(c.Bytes)}, counts...)
		}
	}
	return s
}

func sourceScopeOf(f *fenceFx) auth.Scope {
	f.t.Helper()
	src, err := f.svc.AuthenticateSource(f.ctx, f.sourceCredential, "", false)
	if err != nil {
		f.t.Fatal(err)
	}
	scope, err := f.svc.SourceScope(f.ctx, src, false)
	if err != nil {
		f.t.Fatal(err)
	}
	return scope
}

// lifecycle drives the whole life of reservations through the real store: reserve, retry, finalize,
// cancel, reconcile and settle. Everything it does is deterministic but for the identities.
func lifecycle(t *testing.T, f *fenceFx) lifeShape {
	t.Helper()
	owner := &reconcileOwner{}
	if err := f.store.BindAdmissionOwner(owner); err != nil {
		t.Fatal(err)
	}
	group := model.NewID()
	scope := sourceScopeOf(f)
	var rows []model.AdmissionReservation
	for i := range 14 {
		r, err := reserveSeries(f, fmt.Sprintf("life_%d", i%5))
		if err != nil {
			t.Fatal("reserve:", err)
		}
		rows = append(rows, r)
	}
	for i := range 8 {
		cursor := model.Cursor{Group: group, Index: model.Uint64(i + 1)}
		if err := f.store.FinalizeAdmission(f.ctx, scope, model.FinalizeAdmission{ReservationID: rows[i].ID, Cursor: cursor}); err != nil {
			t.Fatal("finalize:", err)
		}
		// A retry of the same finalize changes nothing.
		if err := f.store.FinalizeAdmission(f.ctx, scope, model.FinalizeAdmission{ReservationID: rows[i].ID, Cursor: cursor}); err != nil {
			t.Fatal("finalize again:", err)
		}
		rows[i].State, rows[i].Cursor = "consumed", &cursor
	}
	for _, i := range []int{8, 9} {
		if err := f.store.CancelAdmission(f.ctx, scope, model.CancelReservation{ReservationID: rows[i].ID, Hash: rows[i].Hash}); err != nil {
			t.Fatal("cancel:", err)
		}
	}
	for i := 10; i < 12; i++ {
		owner.outcomes = append(owner.outcomes, model.FinalizeAdmission{ReservationID: rows[i].ID, Cursor: model.Cursor{Group: group, Index: model.Uint64(i + 1)}})
		rows[i].State, rows[i].Cursor = "consumed", &model.Cursor{Group: group, Index: model.Uint64(i + 1)}
	}
	if err := f.store.ReconcileAdmissions(f.ctx); err != nil {
		t.Fatal("reconcile:", err)
	}
	// Windows of four commands: the first two hold cursors 1-4 and 5-8, all consumed.
	var candidates []model.SettleCandidate
	for n := range 2 {
		var items []model.ChargeItem
		for _, r := range rows[n*4 : n*4+4] {
			items = append(items, model.ChargeOf(r))
		}
		candidates = append(candidates, model.SettleCandidate{Group: group, N: uint64(n), Span: 4, Batches: 4, Charge: model.ChargeDigest(items)})
	}
	rep, err := f.store.SettleAdmissions(f.ctx, candidates)
	if err != nil || rep.Windows != 2 || rep.Reservations != 8 {
		t.Fatalf("settle: %+v, %v", rep, err)
	}
	var shape lifeShape
	if err = f.store.View(f.ctx, func(st control.State) error { shape = shapeOf(st); return nil }); err != nil {
		t.Fatal(err)
	}
	// The size of a batch depends on its identities (the route slot is a number of one or two digits), so
	// the bytes the books hold are compared with the bytes of the reservations they were charged for: a
	// tier holds every reservation that was not cancelled, the settlement the 8 consumed and settled.
	var live, settled uint64
	for i, r := range rows {
		if i == 8 || i == 9 {
			continue
		}
		live += uint64(r.Bytes)
		if i < 8 {
			settled += uint64(r.Bytes)
		}
	}
	for kind, tier := range shape.Tiers {
		tier[0] -= live
		shape.Tiers[kind] = tier
	}
	for kind, charge := range shape.Charges {
		charge[0] -= settled
		shape.Charges[kind] = charge
	}
	return shape
}

// TestAdmissionLifecycleIsTheSameOnBothPaths pins that a group that applies ledger commands and one
// that does not (a replacement of the whole state per command) leave the same books: the transitions
// are written once, over the books, and the two ways of committing them agree.
func TestAdmissionLifecycleIsTheSameOnBothPaths(t *testing.T) {
	whole := lifecycle(t, newFenceFx(t))
	ledger := lifecycle(t, newFenceFxPatch(t))
	if !reflect.DeepEqual(whole, ledger) {
		t.Fatalf("whole-state commands left %+v, ledger commands %+v", whole, ledger)
	}
	if whole.States["consumed"] != 2 || whole.States["cancelled"] != 2 || whole.States["reserved"] != 2 || whole.Windows != 2 || len(whole.Tiers) != 3 || len(whole.Charges) != 3 {
		t.Fatalf("the lifecycle did not leave what it should: %+v", whole)
	}
	for kind, tier := range whole.Tiers {
		if tier[0] != 0 || whole.Charges[kind][0] != 0 {
			t.Fatalf("the %s books do not hold the bytes of the reservations charged: %+v", kind, whole)
		}
	}
}

// TestSeedCarriesTheLedger pins that a snapshot of the control state (the seed a new voter and a
// backup start from) carries the books that live in the ledger, and that a store started from it holds
// the same state.
func TestSeedCarriesTheLedger(t *testing.T) {
	f := newFenceFxPatch(t)
	lifecycle(t, f)
	raw, _, err := f.store.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	other, err := control.OpenSeed(t.TempDir(), raw)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	var a, b control.State
	if err = f.store.View(f.ctx, func(st control.State) error { a = st; return nil }); err != nil {
		t.Fatal(err)
	}
	if err = other.View(f.ctx, func(st control.State) error { b = st; return nil }); err != nil {
		t.Fatal(err)
	}
	ca, _ := model.CanonicalJSON(a)
	cb, _ := model.CanonicalJSON(b)
	if string(ca) != string(cb) {
		t.Fatal("a store started from the seed does not hold the state the seed was taken from")
	}
	if len(a.Reservations) == 0 || len(a.Quotas) != 3 || a.Settlement == nil {
		t.Fatalf("the state the seed was taken from holds no books: %d reservations, %d quotas", len(a.Reservations), len(a.Quotas))
	}
}

// TestTheBooksStayInTheBlobUntilTheInstallationIsContracted pins the two layouts and their gates. An
// installation the previous release can still read (not contracted) keeps its admission books in the
// blob and commits as that release does: a patch once every member declared protocol 5, naming the digest
// of the blob, whatever the books hold. A contracted installation keeps them in the ledger and needs
// protocol 6 for a patch; with only 5 declared its commands are whole-state replacements.
func TestTheBooksStayInTheBlobUntilTheInstallationIsContracted(t *testing.T) {
	touch := func(f *fenceFx, label string) {
		t.Helper()
		f.admin("create_user", f.org, auth.AdminPayload{ID: model.NewID(), Email: label + "@example.test", Password: "a long test password 2026", Reason: label})
	}
	patches := func(f *fenceFx) uint64 { n, _ := f.store.StatePatchStatsForTest(); return n }

	expanded := newFenceFx(t)
	if err := expanded.store.ExpandForTest(); err != nil {
		t.Fatal(err)
	}
	expanded.store.SetLegacyStatePatchGate(func() bool { return true })
	before := patches(expanded)
	touch(expanded, "expanded")
	expanded.mustIntake()
	touch(expanded, "expanded-with-books")
	expanded.mustIntake()
	if patches(expanded) != before+4 {
		t.Fatalf("an installation that is not contracted did not commit as patches of protocol 5: %d -> %d", before, patches(expanded))
	}
	if expanded.store.LedgerLayoutForTest() {
		t.Fatal("the books of an installation that is not contracted left the blob")
	}
	var books int
	if err := expanded.store.View(expanded.ctx, func(st control.State) error { books = len(st.Reservations); return nil }); err != nil || books != 2 {
		t.Fatalf("the books of the expanded installation: %d reservations, %v", books, err)
	}

	contracted := newFenceFx(t)
	contracted.store.SetLegacyStatePatchGate(func() bool { return true })
	if !contracted.store.LedgerLayoutForTest() {
		t.Fatal("a fresh installation is born contracted and keeps its books in the ledger")
	}
	before = patches(contracted)
	touch(contracted, "contracted")
	contracted.mustIntake()
	if patches(contracted) != before {
		t.Fatalf("a contracted installation proposed patches with only protocol 5 declared: %d -> %d", before, patches(contracted))
	}
	contracted.store.SetStatePatchGate(func() bool { return true })
	touch(contracted, "contracted-all-declared")
	contracted.mustIntake()
	if patches(contracted) != before+2 {
		t.Fatalf("a contracted installation did not propose patches once every member declared protocol 6: %d -> %d", before, patches(contracted))
	}
}
