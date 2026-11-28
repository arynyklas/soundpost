// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// An erasure rewrites a stored commit and indexes the rows it keeps again: the chunks are cut anew, so rows
// of a later page move into a page the walk of the commit has already passed. A walk that follows the
// routes it read when the commit was published takes the next page by position and never sees those rows.
// The walk must hand every kept row exactly once, whether or not the subscription asked for catch-up and
// wherever in the walk the rewrite happens.

func rechunkRig(t *testing.T, catchUp bool) *catchUpRig {
	return newCatchUpRig(t, func(req *SubscribeRequest) { req.CatchUp = catchUp })
}

// eraseHead erases the first n rows of the rows (the oldest ones of one commit, nothing before them) and
// requires that exactly n went.
func (r *catchUpRig) eraseHead(ctx context.Context, rows []model.Record, n int) error {
	r.t.Helper()
	report, err := r.e.EraseDeleted(ctx, []model.DeletePredicate{r.rangePredicate(rows[0].ObservedAt-5, rows[n-1].ObservedAt+5, model.Metric)}, nil)
	if err == nil && int(report.Records) != n {
		r.t.Errorf("erase removed %d rows, want %d", report.Records, n)
	}
	return err
}

// drainUntilIdle takes pages until the wanted number of rows was handed or nothing comes for a while (an
// erasure that runs inside a Next is part of its wait), so a row that is never handed fails the test with the
// rows it lacks and not after the rig's long deadline.
func (r *catchUpRig) drainUntilIdle(got []model.ID, want int) []model.ID {
	r.t.Helper()
	for len(got) < want {
		ctx, cancel := context.WithTimeout(r.ctx, 45*time.Second)
		change, err := r.it.Next(ctx)
		cancel()
		if err != nil {
			return got
		}
		r.cursor.see(r.t, change)
		if change.Gap != nil {
			r.t.Fatalf("a gap was announced after %d of %d rows: %+v", len(got), want, change.Gap)
		}
		got = append(got, change.Page.IDs...)
	}
	return got
}

func (r *catchUpRig) requireRows(got, want []model.ID) {
	r.t.Helper()
	if reflect.DeepEqual(got, want) {
		return
	}
	seen := map[model.ID]int{}
	for _, id := range got {
		seen[id]++
	}
	missing, repeated := 0, 0
	for _, id := range want {
		if seen[id] == 0 {
			missing++
		}
	}
	for _, n := range seen {
		if n > 1 {
			repeated++
		}
	}
	r.t.Fatalf("rows handed over differ from the kept rows: %d vs %d, %d missing, %d repeated", len(got), len(want), missing, repeated)
}

// The consumer holds page one of three when the erasure removes the first 12 rows of the commit: the 288 kept
// rows are cut anew as 128, 128 and 32, and the 12 rows that follow page one's rows are now the end of page one.
func testRowsMovedIntoAPassedPage(t *testing.T, catchUp bool) {
	r := rechunkRig(t, catchUp)
	producer := model.NewID()
	slot := r.slotOf(producer)
	big, _ := r.commitOn(producer, slot, 300) // pages of 128, 128 and 44 rows
	first := r.next()
	if first.Page.Len() != pageRows || !reflect.DeepEqual(first.Page.IDs, idsOf(big[:pageRows])) {
		t.Fatalf("the first page of the commit: %d rows", first.Page.Len())
	}
	got := append([]model.ID(nil), first.Page.IDs...)
	if err := r.eraseHead(r.ctx, big, 12); err != nil {
		t.Fatal(err)
	}
	got = r.drainUntilIdle(got, 300)
	r.quiet()
	r.requireRows(got, idsOf(big))
}

func TestLiveWalkDeliversRowsAnErasureMovedIntoAPassedPage(t *testing.T) {
	testRowsMovedIntoAPassedPage(t, false)
}

func TestCatchUpWalkDeliversRowsAnErasureMovedIntoAPassedPage(t *testing.T) {
	testRowsMovedIntoAPassedPage(t, true)
}

// The same rewrite while the second page is being certified: the page the walk read before the rewrite is
// handed (its rows are kept), and what the rewrite moved into the passed pages is handed after it.
func testRewriteWhileAPageIsCertified(t *testing.T, catchUp bool) {
	r := rechunkRig(t, catchUp)
	producer := model.NewID()
	slot := r.slotOf(producer)
	big, _ := r.commitOn(producer, slot, 300)
	first := r.next()
	got := append([]model.ID(nil), first.Page.IDs...)
	armed := true
	r.e.duringReleaseFence = func() {
		if !armed {
			return
		}
		armed = false
		if err := r.eraseHead(context.Background(), big, 12); err != nil {
			t.Errorf("erase: %v", err)
		}
	}
	got = r.drainUntilIdle(got, 300)
	if armed {
		t.Fatal("the erasure never ran")
	}
	r.quiet()
	r.requireRows(got, idsOf(big))
}

func TestLiveWalkSurvivesARewriteWhileAPageIsCertified(t *testing.T) {
	testRewriteWhileAPageIsCertified(t, false)
}

func TestCatchUpWalkSurvivesARewriteWhileAPageIsCertified(t *testing.T) {
	testRewriteWhileAPageIsCertified(t, true)
}

// An expiry erasure is no deletion predicate, so the filters that run after the release fence cannot hide its
// rows: a page read before the rewrite must not be handed after it. Every metric row of the commit expires
// while page two is being certified; page two (read before) is dropped and the rewritten record names nothing.
func testExpiryErasureInTheCertifyWindow(t *testing.T, catchUp bool) {
	r := rechunkRig(t, catchUp)
	producer := model.NewID()
	slot := r.slotOf(producer)
	big, _ := r.commitOn(producer, slot, 300)
	first := r.next()
	got := append([]model.ID(nil), first.Page.IDs...)
	armed := true
	r.e.duringReleaseFence = func() {
		if !armed {
			return
		}
		armed = false
		if report, err := r.e.EraseExpired(context.Background(), metricDeadline, nil); err != nil || report.Records != 300 {
			t.Errorf("expire: %+v %v", report, err)
		}
	}
	got = r.drainUntilIdle(got, 300)
	if armed {
		t.Fatal("the expiry never ran")
	}
	r.requireRows(got, idsOf(big[:pageRows]))
}

func TestLiveWalkNeverHandsAnExpiredRowOfAPageReadBeforeTheRewrite(t *testing.T) {
	testExpiryErasureInTheCertifyWindow(t, false)
}

func TestCatchUpWalkNeverHandsAnExpiredRowOfAPageReadBeforeTheRewrite(t *testing.T) {
	testExpiryErasureInTheCertifyWindow(t, true)
}

// Two rewrites of one commit during a walk: one between pages, one inside the release fence of the page that
// follows. Rows 0..11 were handed before the first, rows 140..151 are erased by the second before they are handed.
func testTwoRewritesOfOneCommit(t *testing.T, catchUp bool) {
	r := rechunkRig(t, catchUp)
	producer := model.NewID()
	slot := r.slotOf(producer)
	big, _ := r.commitOn(producer, slot, 300)
	first := r.next()
	got := append([]model.ID(nil), first.Page.IDs...)
	if err := r.eraseHead(r.ctx, big, 12); err != nil {
		t.Fatal(err)
	}
	armed := true
	r.e.duringReleaseFence = func() {
		if !armed {
			return
		}
		armed = false
		pred := r.rangePredicate(big[140].ObservedAt-5, big[151].ObservedAt+5, model.Metric)
		if report, err := r.e.EraseDeleted(context.Background(), []model.DeletePredicate{pred}, nil); err != nil || report.Records != 12 {
			t.Errorf("second erase: %+v %v", report, err)
		}
	}
	want := append(idsOf(big[:140]), idsOf(big[152:])...)
	got = r.drainUntilIdle(got, len(want))
	if armed {
		t.Fatal("the second erasure never ran")
	}
	r.quiet()
	r.requireRows(got, want)
}

func TestLiveWalkSurvivesTwoRewritesOfOneCommit(t *testing.T) {
	testTwoRewritesOfOneCommit(t, false)
}

func TestCatchUpWalkSurvivesTwoRewritesOfOneCommit(t *testing.T) {
	testTwoRewritesOfOneCommit(t, true)
}

// recoverUntil takes pages, recovering every gap with a scan like a consumer does, until each wanted row was seen.
func (r *catchUpRig) recoverUntil(got deliveries, want int) {
	r.t.Helper()
	for len(got) < want {
		change := r.next()
		if change.Gap != nil {
			r.live.recoverGap(r.t, r.read, got, change.Gap)
			continue
		}
		got.add(change.Page.IDs...)
	}
}

// A rewrite of an unread commit while a snapshot installation turns the pending replay into a gap: the gap is
// recovered by a scan, which sees only kept rows, and nothing is handed twice.
func TestRewriteBeforeASnapshotGapLosesAndRepeatsNothing(t *testing.T) {
	r := rechunkRig(t, true)
	producer := model.NewID()
	slot := r.slotOf(producer)
	got := deliveries{}
	a, _ := r.commitOn(producer, slot, 1)
	want := idsOf(a)
	got.add(r.next().Page.IDs...)
	big, _ := r.commitOn(producer, slot, 300)
	want = append(want, idsOf(big[12:])...)
	for range liveCapacity + 6 {
		rows, _ := r.commitOn(producer, slot, 1)
		want = append(want, rows[0].ID)
	}
	if err := r.eraseHead(r.ctx, big, 12); err != nil {
		t.Fatal(err)
	}
	r.e.mu.Lock()
	r.e.snapshotGapLocked(slot)
	r.e.mu.Unlock()
	rows, _ := r.commitOn(producer, slot, 1)
	want = append(want, rows[0].ID)
	r.recoverUntil(got, len(want))
	r.quiet()
	got.requireExactlyOnce(t, want)
}

// A rewrite of a commit inside the replay window of a D99 lag cut: the commits older than the bound are a gap,
// the newest are read back, the rewritten one without its erased rows.
func TestRewriteInsideALagCutWindowLosesAndRepeatsNothing(t *testing.T) {
	r := newCatchUpRig(t, func(q *SubscribeRequest) { q.CatchUpLag = 40 })
	producer := model.NewID()
	slot := r.slotOf(producer)
	var want []model.ID
	small := func(n int) {
		for range n {
			rows, _ := r.commitOn(producer, slot, 1)
			want = append(want, rows[0].ID)
		}
	}
	small(150)
	big, _ := r.commitOn(producer, slot, 300)
	want = append(want, idsOf(big[12:])...)
	small(10)
	if err := r.eraseHead(r.ctx, big, 12); err != nil {
		t.Fatal(err)
	}
	got := deliveries{}
	r.recoverUntil(got, len(want))
	r.quiet()
	got.requireExactlyOnce(t, want)
}
