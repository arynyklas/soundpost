// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"soundpost/internal/artifacts"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/retention"
)

// Artifact reference traffic (Reference extends a retained map's ledger on every error occurrence
// or profile that uses it) is a control transition per call. It writes only the reference ledger
// and its index entry, so it must not move AuthorityRevision: a deletion Begin whose view the
// traffic has provably moved the global Revision past must still commit on its first try. Real
// application, real lifecycle, real deletion service; three goroutines reference one map
// continuously (each extends its own origin's retention, so the ledger keeps changing without
// growing) while a deletion begins on stale views.
func TestDeleteBeginDoesNotStarveUnderArtifactReferenceTraffic(t *testing.T) {
	r := newWLRig(t)
	life := r.lifecycleOf(true)
	a := r.upload("beginstarve", false, 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var stop atomic.Bool
	var refs atomic.Int64
	var wg sync.WaitGroup
	var firstFailure atomic.Value
	for range 3 {
		scope := r.scope(auth.ArtifactWrite)
		origin := r.origin("error", 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			until := time.Now().Add(time.Hour)
			for i := 0; !stop.Load() && ctx.Err() == nil; i++ {
				until = until.Add(time.Second) // strictly longer: every call changes the ledger
				if err := life.Reference(ctx, scope, a.ID, origin, model.UnixNano(until.UnixNano())); err != nil {
					firstFailure.CompareAndSwap(nil, err)
					return
				}
				refs.Add(1)
			}
		}()
	}
	stopRefs := func() {
		stop.Store(true)
		wg.Wait()
	}
	defer stopRefs()

	revision := func() model.Revision {
		var rev model.Revision
		if err := r.app.Control.View(ctx, func(st model.ControlState) error { rev = st.Revision; return nil }); err != nil {
			t.Fatal(err)
		}
		return rev
	}
	for refs.Load() < 5 {
		if err, _ := firstFailure.Load().(error); err != nil {
			t.Fatalf("Reference failed before the deletions: %v", err)
		}
		if ctx.Err() != nil {
			t.Fatal("reference traffic never started")
		}
		time.Sleep(time.Millisecond)
	}
	const iterations = 6
	conflicts := 0
	for range iterations {
		view := revision()
		for revision() == view {
			if ctx.Err() != nil {
				t.Fatal("reference traffic stopped moving the revision")
			}
			time.Sleep(time.Millisecond)
		}
		receipt, err := r.app.Retention.Delete(ctx, r.adminScope(), retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: view, Mode: model.DeleteHistoricalRange, OrgID: r.org, ProjectIDs: []model.ID{r.project}, Signals: []model.Kind{model.Metric}, Start: 0, End: 100, Reason: "owner erase request"})
		if wlCode(err) == model.Conflict {
			conflicts++
			continue
		}
		if err != nil || receipt.Phase != model.DeletePhaseFencing {
			t.Fatalf("stale-view Begin: %+v %v", receipt, err)
		}
	}
	stopRefs()
	if err, _ := firstFailure.Load().(error); err != nil {
		t.Fatalf("Reference failed: %v", err)
	}
	t.Logf("%d references committed while %d deletions began; stale-view Begin conflicts %d/%d", refs.Load(), iterations, conflicts, iterations)
	if conflicts != 0 {
		t.Fatalf("deletion Begin starved by artifact reference traffic: %d/%d conflicted", conflicts, iterations)
	}
}

// Reference and Unreference are ledger bookkeeping and leave AuthorityRevision alone; the GC
// fence that retires the map is the transition that bumps it (and the org delete generation).
func TestArtifactLedgerWritesKeepAuthorityAndGCFenceBumps(t *testing.T) {
	r := newWLRig(t)
	life := r.lifecycleOf(true)
	a := r.upload("authorityledger", false, 1500*time.Millisecond)
	authority := func() (rev, auth model.Revision) {
		t.Helper()
		if err := r.app.Control.View(r.ctx, func(st model.ControlState) error { rev, auth = st.Revision, st.AuthorityRevision; return nil }); err != nil {
			t.Fatal(err)
		}
		return
	}
	origin := r.origin(artifacts.ReferenceError, 1)
	rev0, auth0 := authority()
	r.reference(life, a, origin, time.Now().Add(time.Hour))
	rev1, auth1 := authority()
	if rev1 <= rev0 || auth1 != auth0 {
		t.Fatalf("Reference: revision %d -> %d, authority %d -> %d (want the revision to move, authority not)", rev0, rev1, auth0, auth1)
	}
	if err := life.Unreference(r.ctx, r.scope(auth.ArtifactWrite), a.ID, origin, 0); err != nil {
		t.Fatal(err)
	}
	rev2, auth2 := authority()
	if rev2 <= rev1 || auth2 != auth1 {
		t.Fatalf("Unreference: revision %d -> %d, authority %d -> %d (want the revision to move, authority not)", rev1, rev2, auth1, auth2)
	}
	time.Sleep(2 * time.Second) // the upload's own retention is over; the only reference is released
	if _, err := life.GC(r.ctx, r.scope(auth.ArtifactWrite), a.ID); err != nil {
		t.Fatalf("GC: %v (a loaded host that overran the retention window is not a defect)", err)
	}
	rev3, auth3 := authority()
	if rev3 <= rev2 || auth3 != rev3 {
		t.Fatalf("GC fence: revision %d -> %d, authority %d -> %d (want a bump)", rev2, rev3, auth2, auth3)
	}
}
