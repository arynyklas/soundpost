// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"soundpost/internal/model"
	"soundpost/internal/retention"
)

// Same question as TestDeleteBeginDoesNotStarveUnderSaturatingIntake for the other hot path: busy
// logins. Every login commits a control transition (it adds a session), so before the session
// writer was classified each one moved AuthorityRevision and a deletion Begin whose view predated
// it conflicted. Four goroutines log in without pause while a deletion begins on a view that the
// logins have provably moved the global Revision past. A login adds a session for an existing
// user and changes no right, so Begin must commit on its first try.
func TestDeleteBeginDoesNotStarveUnderSaturatingLogins(t *testing.T) {
	f := newFx(t, options{})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var stop atomic.Bool
	var logins atomic.Int64
	var wg sync.WaitGroup
	var firstFailure atomic.Value
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() && ctx.Err() == nil {
				if _, err := f.auth.Login(ctx, "owner@example.test", "a long test password 2026", ""); err != nil {
					firstFailure.CompareAndSwap(nil, err)
					return
				}
				logins.Add(1)
			}
		}()
	}
	stopLogins := func() {
		stop.Store(true)
		wg.Wait()
	}
	defer stopLogins()

	begin := func(view model.Revision) (retention.DeleteReceipt, error) {
		return f.svc.Delete(ctx, f.adminScope(), retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: view, Mode: model.DeleteHistoricalRange, OrgID: f.org, ProjectIDs: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 0, End: 100, Reason: "owner erase request"})
	}
	for logins.Load() < 5 {
		if err, _ := firstFailure.Load().(error); err != nil {
			t.Fatalf("login failed before the deletions: %v", err)
		}
		if ctx.Err() != nil {
			t.Fatal("logins never started")
		}
		time.Sleep(time.Millisecond)
	}

	const iterations = 6
	forced := 0
	for range iterations {
		view := f.revision()
		for f.revision() == view { // logins move the global revision past the caller's view
			if ctx.Err() != nil {
				t.Fatal("logins stopped moving the revision")
			}
			time.Sleep(time.Millisecond)
		}
		receipt, err := begin(view)
		if code(err) == model.Conflict {
			forced++
			continue
		}
		if err != nil || receipt.Phase != model.DeletePhaseFencing {
			t.Fatalf("stale-view Begin: %+v %v", receipt, err)
		}
	}
	stopLogins()
	if err, _ := firstFailure.Load().(error); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	t.Logf("%d logins committed while %d deletions began; stale-view Begin conflicts %d/%d", logins.Load(), iterations, forced, iterations)
	if forced != 0 {
		t.Fatalf("deletion Begin starved by logins: %d/%d stale-view Begins conflicted", forced, iterations)
	}
}
