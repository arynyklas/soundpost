// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/retention"
)

// The three hot writers of a running installation at once: intake admissions
// (ReserveAdmission), logins (a session record) and replay-index writes (the
// checkpoint index in an organization's settings). Each has its own test that a
// deletion Begin on a stale view still commits; this is the measurement the
// open "Begin starvation under saturating intake" item asked for, with all of
// them running together so any interaction between the exemptions shows. A Begin
// must conflict only when something that changes authority committed after the
// caller's view, and none of these does.
func TestDeleteBeginDoesNotStarveUnderMixedWriters(t *testing.T) {
	f := newFx(t, options{})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	var stop atomic.Bool
	var intake, logins, index atomic.Int64
	var wg sync.WaitGroup
	var firstFailure atomic.Value
	run := func(n int, counter *atomic.Int64, step func(i int64) error) {
		for range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for !stop.Load() && ctx.Err() == nil {
					if err := step(counter.Load()); err != nil {
						firstFailure.CompareAndSwap(nil, err)
						return
					}
					counter.Add(1)
				}
			}()
		}
	}
	run(3, &intake, func(int64) error { _, err := f.batch(1_000, "saturate"); return err })
	run(2, &logins, func(int64) error {
		_, err := f.auth.Login(ctx, "owner@example.test", "a long test password 2026", "")
		return err
	})
	run(2, &index, func(i int64) error {
		return f.store.UpdateReplayIndex(ctx, func(st *control.State) error {
			o := st.Orgs[f.org.String()]
			settings := make(map[string]json.RawMessage, len(o.Settings)+1)
			for k, v := range o.Settings {
				settings[k] = v
			}
			settings[model.ReplayIndexKeyPrefix+strconv.FormatInt(i%64, 10)] = json.RawMessage(strconv.FormatInt(i, 10))
			o.Settings = settings
			st.Orgs[f.org.String()] = o
			return nil
		})
	})
	stopAll := func() {
		stop.Store(true)
		wg.Wait()
	}
	defer stopAll()

	for intake.Load() < 10 || logins.Load() < 3 || index.Load() < 10 {
		if err, _ := firstFailure.Load().(error); err != nil {
			t.Fatalf("a writer failed before the deletions: %v", err)
		}
		if ctx.Err() != nil {
			t.Fatalf("writers never got going: intake %d logins %d index %d", intake.Load(), logins.Load(), index.Load())
		}
		time.Sleep(time.Millisecond)
	}

	begin := func(view model.Revision) (retention.DeleteReceipt, error) {
		return f.svc.Delete(ctx, f.adminScope(), retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: view, Mode: model.DeleteHistoricalRange, OrgID: f.org, ProjectIDs: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 0, End: 100, Reason: "owner erase request"})
	}
	const iterations = 10
	conflicts := 0
	for range iterations {
		view := f.revision()
		for f.revision() == view {
			if ctx.Err() != nil {
				t.Fatal("the writers stopped moving the revision")
			}
			time.Sleep(time.Millisecond)
		}
		receipt, err := begin(view)
		if code(err) == model.Conflict {
			conflicts++
			continue
		}
		if err != nil || receipt.Phase != model.DeletePhaseFencing {
			t.Fatalf("stale-view Begin: %+v %v", receipt, err)
		}
	}
	stopAll()
	if err, _ := firstFailure.Load().(error); err != nil {
		t.Fatalf("a writer failed: %v", err)
	}
	t.Logf("%d admissions, %d logins and %d replay-index writes committed while %d deletions began; stale-view Begin conflicts %d/%d", intake.Load(), logins.Load(), index.Load(), iterations, conflicts, iterations)
	if conflicts != 0 {
		t.Fatalf("deletion Begin starved by concurrent writers: %d/%d stale-view Begins conflicted", conflicts, iterations)
	}
}
