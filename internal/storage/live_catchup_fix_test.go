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

// catchUpRig is a real engine with one catch-up subscription of the project's metrics. Rows are admitted by
// the helpers below, which can pin a batch to one replica group (a row's group follows its series).
type catchUpRig struct {
	*eraseEnv
	live   liveEnv
	it     ChangeIterator
	ctx    context.Context
	clock  model.UnixNano
	cursor cursorLedger
}

func newCatchUpRig(t *testing.T, mutate func(*SubscribeRequest)) *catchUpRig {
	t.Helper()
	x := newEraseEnv(t)
	req := SubscribeRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric, CatchUp: true}
	if mutate != nil {
		mutate(&req)
	}
	it, err := x.e.Subscribe(context.Background(), x.read, req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { it.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	return &catchUpRig{eraseEnv: x, live: liveEnv{store: x.store, a: x.a, c: x.cred, d: x.d, e: x.e}, it: it, ctx: ctx, clock: 1000}
}

// cursorLedger enforces the rule that a page's Cursors is the consumer's resume position after the page:
// per group it never goes backwards, a gap's Through included.
type cursorLedger struct{ last map[model.ID]model.Uint64 }

func (l *cursorLedger) see(t *testing.T, change ChangePage) {
	t.Helper()
	if l.last == nil {
		l.last = map[model.ID]model.Uint64{}
	}
	for _, c := range change.Cursors {
		if c.Index < l.last[c.Group] {
			t.Fatalf("cursors went backwards in group %s: %d after %d (gap %+v, %d rows)", c.Group, c.Index, l.last[c.Group], change.Gap, change.Page.Len())
		}
		l.last[c.Group] = c.Index
	}
}

// slotOf is the replica slot a producer's row of a fresh series routes to.
func (r *catchUpRig) slotOf(producer model.ID) uint16 {
	r.t.Helper()
	slot, err := model.OwnerSlot(r.d.Org, r.d.Project, r.d.Source, producer, r.metric("d97_"+model.NewID().String(), 1))
	if err != nil {
		r.t.Fatal(err)
	}
	return slot
}

// rowsOn is n metric rows of new series that all route to slot, 10 ns apart and later than every earlier row.
func (r *catchUpRig) rowsOn(producer model.ID, slot uint16, n int) []model.Record {
	r.t.Helper()
	rows := make([]model.Record, 0, n)
	for len(rows) < n {
		row := r.metric("d97_"+model.NewID().String(), r.clock+10)
		got, err := model.OwnerSlot(r.d.Org, r.d.Project, r.d.Source, producer, row)
		if err != nil {
			r.t.Fatal(err)
		}
		if got != slot {
			continue
		}
		r.clock += 10
		rows = append(rows, row)
	}
	return rows
}

// commitOn admits n rows as one batch (one commit) on the slot.
func (r *catchUpRig) commitOn(producer model.ID, slot uint16, n int) ([]model.Record, model.Receipt) {
	r.t.Helper()
	rows := r.rowsOn(producer, slot, n)
	_, receipt, _ := r.appendRecords(producer, bothDeadlines, rows...)
	return rows, receipt
}

func idsOf(rows []model.Record) []model.ID {
	out := make([]model.ID, len(rows))
	for i := range rows {
		out[i] = rows[i].ID
	}
	return out
}

func (r *catchUpRig) next() ChangePage {
	r.t.Helper()
	change, err := r.it.Next(r.ctx)
	if err != nil {
		r.t.Fatalf("Next: %v", err)
	}
	r.cursor.see(r.t, change)
	return change
}

// drainRows takes pages until every wanted row was handed, failing on any gap, and returns them in order.
func (r *catchUpRig) drainRows(got []model.ID, want int) []model.ID {
	r.t.Helper()
	for len(got) < want {
		change := r.next()
		if change.Gap != nil {
			r.t.Fatalf("a gap was announced after %d of %d rows: %+v", len(got), want, change.Gap)
		}
		got = append(got, change.Page.IDs...)
	}
	return got
}

// quiet requires that nothing more is handed over: a duplicate would arrive before the wait ends.
func (r *catchUpRig) quiet() {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(r.ctx, 500*time.Millisecond)
	defer cancel()
	if change, err := r.it.Next(ctx); err == nil {
		r.t.Fatalf("more was handed over after every row: %d rows, gap %+v", change.Page.Len(), change.Gap)
	}
}

// F1: a snapshot installation that skips an interval while a catch-up replay is active gives the consumer a
// catch_up_required gap for everything up to the watermarks. The replay must be dropped with it: reading the
// window afterwards hands its rows twice and puts the page cursors behind the cut the gap advertised.
func TestSnapshotGapDuringAReplayCancelsTheReplay(t *testing.T) {
	r := newCatchUpRig(t, nil)
	producer := model.NewID()
	slot := r.slotOf(producer)
	var want []model.ID
	for range liveCapacity * 3 {
		rows, _ := r.commitOn(producer, slot, 1)
		want = append(want, rows[0].ID)
	}
	got := deliveries{}
	for range 5 {
		change := r.next()
		if change.Gap != nil {
			t.Fatalf("an overrun with catch-up announced a gap: %+v", change.Gap)
		}
		got.add(change.Page.IDs...)
	}
	r.e.mu.Lock()
	r.e.snapshotGapLocked(slot) // what a follower's snapshot install does to its subscribers
	r.e.mu.Unlock()
	rows, _ := r.commitOn(producer, slot, 1)
	want = append(want, rows[0].ID)
	sawGap := false
	for len(got) < len(want) {
		change := r.next()
		if change.Gap != nil {
			if change.Gap.Reason != "catch_up_required" {
				t.Fatalf("the snapshot gap: %+v", change.Gap)
			}
			sawGap = true
			r.live.recoverGap(t, r.read, got, change.Gap)
			continue
		}
		got.add(change.Page.IDs...)
	}
	if !sawGap {
		t.Fatal("the snapshot installation was not announced")
	}
	r.quiet()
	got.requireExactlyOnce(t, want)
}

// F2/F5: a commit of several pages that the consumer was handed part of when the queue overran is resumed
// at the rows it was not handed (a non-zero resume point), every row exactly once and in order.
func TestOverrunInTheMiddleOfAMultiPageCommitResumesAtTheUnhandedRows(t *testing.T) {
	r := newCatchUpRig(t, nil)
	producer := model.NewID()
	slot := r.slotOf(producer)
	big, receipt := r.commitOn(producer, slot, 3*pageRows-20) // pages of 128, 128 and 108 rows
	want := idsOf(big)
	first := r.next()
	if first.Page.Len() != pageRows || first.Cursors[0] != receipt.Cursor || !reflect.DeepEqual(first.Page.IDs, want[:pageRows]) {
		t.Fatalf("the first page of the commit: %d rows, cursors %v", first.Page.Len(), first.Cursors)
	}
	got := append([]model.ID(nil), first.Page.IDs...)
	for range liveCapacity + 6 { // the consumer is still holding page one: the queue overruns
		rows, _ := r.commitOn(producer, slot, 1)
		want = append(want, rows[0].ID)
	}
	got = r.drainRows(got, len(want))
	r.quiet()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rows handed over differ from rows committed (%d vs %d)", len(got), len(want))
	}
}

// F2: an erasure that removes pages of the interrupted commit between the overrun and the read-back rewrites
// the commit record, and the pages that are left shift down. The resume point is the rows the consumer was
// handed, not a position in the record: every kept row arrives once, no erased row does, nothing is corrupt.
func TestErasureInsideTheReplayWindowShiftsNeitherKeptNorErasedRows(t *testing.T) {
	r := newCatchUpRig(t, nil)
	producer := model.NewID()
	slot := r.slotOf(producer)
	big, _ := r.commitOn(producer, slot, 300) // pages of 128, 128 and 44 rows
	first := r.next()
	if first.Page.Len() != pageRows {
		t.Fatalf("the first page of the commit: %d rows", first.Page.Len())
	}
	got := append([]model.ID(nil), first.Page.IDs...)
	want := idsOf(big[:pageRows])
	var after []model.Record
	for range liveCapacity + 6 {
		rows, _ := r.commitOn(producer, slot, 1)
		after = append(after, rows...)
	}
	// Erase page one (handed) and the first 12 rows of page two (not handed): the 160 kept rows are left as
	// a page of 128 and a page of 32, so the record's list shrinks from three pages to two.
	end := big[139].ObservedAt + 5
	report, err := r.e.EraseDeleted(r.ctx, []model.DeletePredicate{r.rangePredicate(0, end, model.Metric)}, nil)
	if err != nil || report.Records != 140 {
		t.Fatalf("erase: %+v %v", report, err)
	}
	kept := append(idsOf(big[140:]), idsOf(after)...)
	got = r.drainRows(got, len(want)+len(kept))
	r.quiet()
	if !reflect.DeepEqual(got, append(want, kept...)) {
		erased := map[model.ID]bool{}
		for _, row := range big[pageRows:140] {
			erased[row.ID] = true
		}
		leaked := 0
		for _, id := range got {
			if erased[id] {
				leaked++
			}
		}
		t.Fatalf("rows handed over differ from the handed page and the kept rows (%d vs %d), %d erased rows among them", len(got), len(want)+len(kept), leaked)
	}
}

// F2: a page that an erasure removes after the commit was read back, before the consumer asks for it, is
// withheld: it is no longer named by the commit record, which is not corruption.
func TestErasureBetweenTheReadBackAndThePageLoadIsNotCorrupt(t *testing.T) {
	r := newCatchUpRig(t, nil)
	producer := model.NewID()
	slot := r.slotOf(producer)
	big, _ := r.commitOn(producer, slot, 300) // pages of 128, 128 and 44 rows
	var after []model.Record
	for range liveCapacity + 6 {
		rows, _ := r.commitOn(producer, slot, 1)
		after = append(after, rows...)
	}
	armed := true
	r.e.duringReleaseFence = func() { // page one is being certified, the commit's other pages are still to load
		if !armed {
			return
		}
		armed = false
		// Page two goes: page one stays, page three's rows are now page two, and the third id is gone.
		pred := r.rangePredicate(big[pageRows-1].ObservedAt+5, big[2*pageRows-1].ObservedAt+5, model.Metric)
		if report, err := r.e.EraseDeleted(context.Background(), []model.DeletePredicate{pred}, nil); err != nil || report.Records != pageRows {
			t.Errorf("erase: %+v %v", report, err)
		}
	}
	want := append(append(idsOf(big[:pageRows]), idsOf(big[2*pageRows:])...), idsOf(after)...)
	got := r.drainRows(nil, len(want))
	if armed {
		t.Fatal("the erasure never ran")
	}
	r.quiet()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rows handed over differ from the kept rows (%d vs %d)", len(got), len(want))
	}
}

// F5: commits of several replica groups in one window, each with its own position: every row once, and in
// commit order within each group.
func TestCatchUpOverSeveralGroupsHandsEveryRowOnceInGroupOrder(t *testing.T) {
	r := newCatchUpRig(t, nil)
	var slots []uint16
	seen := map[uint16]bool{}
	for range 12 {
		if slot := r.slotOf(model.NewID()); !seen[slot] {
			seen[slot] = true
			slots = append(slots, slot)
		}
	}
	producer := model.NewID()
	var want []model.ID
	origin := map[model.ID]model.Cursor{}
	groups := map[model.ID]bool{}
	for i := range liveCapacity*3 + 7 {
		rows, receipt := r.commitOn(producer, slots[i%len(slots)], 1+i%3)
		for _, row := range rows {
			want = append(want, row.ID)
			origin[row.ID] = receipt.Cursor
		}
		groups[receipt.Cursor.Group] = true
	}
	if len(groups) < 2 {
		t.Fatalf("the commits fell into %d group(s)", len(groups))
	}
	got := r.drainRows(nil, len(want))
	r.quiet()
	seenRow := deliveries{}
	seenRow.add(got...)
	seenRow.requireExactlyOnce(t, want)
	last := map[model.ID]model.Uint64{}
	for _, id := range got {
		c := origin[id]
		if c.Index < last[c.Group] {
			t.Fatalf("rows of group %s were handed out of commit order: %d after %d", c.Group, c.Index, last[c.Group])
		}
		last[c.Group] = c.Index
	}
}

// F5: a window opened by After is still announced as a gap, and a replay that starts while that gap has not
// been taken reads after it: the rows of the gap are recovered by the consumer, the rest arrive once.
func TestCatchUpWithAfterAnnouncesTheOpeningWindowAndReplaysOnlyWhatFollows(t *testing.T) {
	x := newEraseEnv(t)
	producer := model.NewID()
	r := &catchUpRig{eraseEnv: x, live: liveEnv{store: x.store, a: x.a, c: x.cred, d: x.d, e: x.e}, ctx: context.Background(), clock: 1000}
	probe, err := x.e.Subscribe(context.Background(), x.read, SubscribeRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric})
	if err != nil {
		t.Fatal(err)
	}
	start := probe.Watermarks()
	probe.Close()
	slot := r.slotOf(producer)
	var want []model.ID
	for range 5 { // before the subscription: inside the window After opens
		rows, _ := r.commitOn(producer, slot, 1)
		want = append(want, rows[0].ID)
	}
	it, err := x.e.Subscribe(context.Background(), x.read, SubscribeRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric, CatchUp: true, After: start})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	r.it = it
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r.ctx = ctx
	for range liveCapacity + 6 { // the queue overruns before the gap was taken
		rows, _ := r.commitOn(producer, slot, 1)
		want = append(want, rows[0].ID)
	}
	got := deliveries{}
	gaps := 0
	for len(got) < len(want) {
		change := r.next()
		if change.Gap != nil {
			gaps++
			if change.Gap.Reason != "catch_up_required" || !reflect.DeepEqual(change.Gap.After, start) {
				t.Fatalf("the opening gap: %+v, want catch_up_required after %v", change.Gap, start)
			}
			r.live.recoverGap(t, x.read, got, change.Gap)
			continue
		}
		got.add(change.Page.IDs...)
	}
	r.quiet()
	if gaps != 1 {
		t.Fatalf("%d gaps, want the one the After window opened", gaps)
	}
	got.requireExactlyOnce(t, want)
}

// F5: a credential that is revoked while a replay is active ends the stream before any further row, and the
// cursors it advertises resume exactly: the consumer recovers the window it names and loses nothing.
func TestRevocationDuringAReplayAdvertisesTheDeliveredCursorsAndLeaksNothing(t *testing.T) {
	r := newCatchUpRig(t, nil)
	producer := model.NewID()
	slot := r.slotOf(producer)
	var want []model.ID
	for range liveCapacity * 2 {
		rows, _ := r.commitOn(producer, slot, 1)
		want = append(want, rows[0].ID)
	}
	got := deliveries{}
	for range 3 {
		change := r.next()
		if change.Gap != nil {
			t.Fatalf("a gap during catch-up: %+v", change.Gap)
		}
		got.add(change.Page.IDs...)
	}
	r.live.revoke(t)
	change := r.next()
	if !change.Revoked || change.Page.Len() != 0 {
		t.Fatalf("the revoked stream handed over %d rows, revoked=%v", change.Page.Len(), change.Revoked)
	}
	if _, err := r.it.Next(r.ctx); err == nil {
		t.Fatal("a revoked stream stays open")
	}
	base := r.metric("d97_resume", 1)
	probe := r.live.resume(t, r.ctx, change.Cursors, got, base, int(r.clock)+10)
	want = append(want, probe)
	got.requireExactlyOnce(t, want)
}

// F5: the selectors of the subscription apply to replayed rows as they do to live ones: a selector that
// matches none of the window's rows hands over none of them.
func TestReplayAppliesTheSelectorsOfTheSubscription(t *testing.T) {
	r := newCatchUpRig(t, func(q *SubscribeRequest) {
		q.Selectors = []Matcher{{Target: MatchLabel, Name: "zone", Op: MatchEqual, Literal: Literal{Kind: LiteralString, String: "b"}}}
	})
	producer := model.NewID()
	slot := r.slotOf(producer)
	for range liveCapacity + 6 {
		r.commitOn(producer, slot, 1)
	}
	ctx, cancel := context.WithTimeout(r.ctx, 2*time.Second)
	defer cancel()
	if change, err := r.it.Next(ctx); err == nil {
		t.Fatalf("a row that the selector excludes was handed over: %d rows, gap %+v", change.Page.Len(), change.Gap)
	}
}
