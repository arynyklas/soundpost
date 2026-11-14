// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
)

// Every intake admission (ReserveAdmission) is a control transition, so it moves the one global
// control Revision. A deletion's Begin carries the Revision its caller read from a View: under
// saturating intake that view is stale by the time Begin commits, and before AuthorityRevision
// every Begin conflicted (the 07.07 drill saw 60/60 and 20/20). An owner's erase request must not
// starve: Begin must commit on its first try while nothing that could change authority happened.
//
// Two phases against a real replicated control store and four goroutines that reserve admissions
// without pause: a natural race (view, then Delete at once) and a forced one (view, wait until
// intake has provably moved the global Revision past the view, then Delete with the old view).
func TestDeleteBeginDoesNotStarveUnderSaturatingIntake(t *testing.T) {
	f := newFx(t, options{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var stop atomic.Bool
	var admitted atomic.Int64
	var wg sync.WaitGroup
	var firstFailure atomic.Value
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() && ctx.Err() == nil {
				if _, err := f.batch(1_000, "saturate"); err != nil {
					firstFailure.CompareAndSwap(nil, err)
					return
				}
				admitted.Add(1)
			}
		}()
	}
	stopIntake := func() {
		stop.Store(true)
		wg.Wait()
	}
	defer stopIntake()

	begin := func(view model.Revision) (retention.DeleteReceipt, error) {
		return f.svc.Delete(ctx, f.adminScope(), retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: view, Mode: model.DeleteHistoricalRange, OrgID: f.org, ProjectIDs: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 0, End: 100, Reason: "owner erase request"})
	}
	// Wait for the intake goroutines to be in full flow.
	for admitted.Load() < 20 {
		if err, _ := firstFailure.Load().(error); err != nil {
			t.Fatalf("intake failed before the deletions: %v", err)
		}
		if ctx.Err() != nil {
			t.Fatal("intake never started")
		}
		time.Sleep(time.Millisecond)
	}

	const iterations = 8
	natural, forced := 0, 0
	for range iterations {
		view := f.revision()
		receipt, err := begin(view)
		if code(err) == model.Conflict {
			natural++
			continue
		}
		if err != nil || receipt.Phase != model.DeletePhaseFencing {
			t.Fatalf("natural Begin: %+v %v", receipt, err)
		}
	}
	for range iterations {
		view := f.revision()
		for f.revision() == view { // intake moves the global revision past the caller's view
			if ctx.Err() != nil {
				t.Fatal("intake stopped moving the revision")
			}
			time.Sleep(time.Millisecond)
		}
		receipt, err := begin(view)
		if code(err) == model.Conflict {
			forced++
			continue
		}
		if err != nil || receipt.Phase != model.DeletePhaseFencing {
			t.Fatalf("forced Begin: %+v %v", receipt, err)
		}
	}
	stopIntake()
	if err, _ := firstFailure.Load().(error); err != nil {
		t.Fatalf("intake failed: %v", err)
	}
	t.Logf("%d admissions committed while %d deletions began; Begin conflicts: natural race %d/%d, stale view %d/%d", admitted.Load(), 2*iterations, natural, iterations, forced, iterations)
	if natural != 0 || forced != 0 {
		t.Fatalf("deletion Begin starved by intake: %d/%d natural and %d/%d stale-view Begins conflicted", natural, iterations, forced, iterations)
	}
}
