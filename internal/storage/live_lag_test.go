// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

type lagReporter interface{ Lag() uint64 }

// D99: a consumer that stays slower than ingest does not fall ever further behind unseen. Past the lag bound
// the part it can no longer be handed is announced as an exact slow_consumer gap (and recovered by a scan of
// exactly that window), the newest commits are still read back, every row reaches the consumer or is inside
// an announced gap exactly once, and Lag says how far behind it is at every step.
func TestCatchUpLagIsBoundedAndTheGapBeyondItIsExact(t *testing.T) {
	const bound, total = 40, 240 // the bound is below the 64-event queue, so the first overrun already exceeds it
	r := newCatchUpRig(t, func(q *SubscribeRequest) { q.CatchUpLag = bound })
	lagger := r.it.(lagReporter)
	producer := model.NewID()
	slot := r.slotOf(producer)
	var want []model.ID
	commit := func() {
		rows, _ := r.commitOn(producer, slot, 1)
		want = append(want, rows[0].ID)
	}
	for range 150 {
		commit()
	}
	if lag := lagger.Lag(); lag == 0 || lag > bound+liveCapacity+2 {
		t.Fatalf("lag %d after 150 unread commits: want 1..%d", lag, bound+liveCapacity+2)
	}
	got := deliveries{}
	gaps, handedAfterGap := 0, 0
	for len(got) < total || len(want) < total {
		for range 2 { // ingest keeps going while the consumer reads: sustained overload
			if len(want) < total {
				commit()
			}
		}
		change := r.next()
		if lag := lagger.Lag(); lag > bound+liveCapacity+2 {
			t.Fatalf("lag %d exceeds the bound %d plus the queue %d", lag, bound, liveCapacity)
		}
		if change.Gap != nil {
			gaps++
			if change.Gap.Reason != "slow_consumer" {
				t.Fatalf("the gap beyond the lag bound: %+v", change.Gap)
			}
			r.live.recoverGap(t, r.read, got, change.Gap)
			continue
		}
		if gaps > 0 {
			handedAfterGap += change.Page.Len()
		}
		got.add(change.Page.IDs...)
	}
	if lag := lagger.Lag(); lag != 0 {
		t.Fatalf("a consumer that holds nothing reports lag %d", lag)
	}
	r.quiet()
	if gaps == 0 {
		t.Fatal("the consumer fell further behind than the bound and was never told")
	}
	if handedAfterGap < bound {
		t.Fatalf("only %d rows were read back after the gap, want at least the bound %d", handedAfterGap, bound)
	}
	got.requireExactlyOnce(t, want)
}

// F4: the replay does not hold the engine lock across any number of commits it has to step over: after a
// bounded batch it releases it (the hook runs with the lock free, which a goroutine proves by taking it) and
// carries on, and no row is lost or repeated by the pauses.
func TestReplayScanStepsOverIrrelevantCommitsInBoundedBatches(t *testing.T) {
	defer func(old int) { replayScanBatch = old }(replayScanBatch)
	replayScanBatch = 3
	r := newCatchUpRig(t, nil)
	producer := model.NewID()
	slot := r.slotOf(producer)
	yields := 0
	r.e.replayYield = func() {
		yields++
		free := make(chan struct{})
		go func() {
			r.e.mu.Lock()
			r.e.mu.Unlock()
			close(free)
		}()
		select {
		case <-free:
		case <-time.After(10 * time.Second):
			t.Error("the engine lock is held across a replay pause")
		}
	}
	var rows []model.Record
	for range liveCapacity + 16 {
		one, _ := r.commitOn(producer, slot, 1)
		rows = append(rows, one...)
	}
	// Erase the middle 50 commits entirely: their records are empty and the replay steps over them.
	report, err := r.e.EraseDeleted(r.ctx, []model.DeletePredicate{r.rangePredicate(rows[10].ObservedAt-5, rows[59].ObservedAt+5, model.Metric)}, nil)
	if err != nil || report.Records != 50 {
		t.Fatalf("erase: %+v %v", report, err)
	}
	want := append(idsOf(rows[:10]), idsOf(rows[60:])...)
	got := r.drainRows(nil, len(want))
	r.quiet()
	got2 := deliveries{}
	got2.add(got...)
	got2.requireExactlyOnce(t, want)
	if yields < 10 {
		t.Fatalf("50 commits stepped over in batches of 3 gave %d pauses, want at least 10", yields)
	}
}
