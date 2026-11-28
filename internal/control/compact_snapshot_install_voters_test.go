// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// A voter that was cut off while the group wrote its ledger with the compact ops (rsv, fin, chs: D104, the gate open) catches up by
// installing a snapshot, the journals having been compacted past it. The snapshot holds the rows those ops wrote (reservations,
// finalized cursors, the settlement a chs folded), and the voter has to end with the ledger the others hold, and then keep applying
// compact ops over it and propose against it (m4 review of round 5, coverage gap 1).
func TestAVoterThatInstallsASnapshotWhileTheCompactGateIsOpenEndsWithTheLedgerOfTheOthers(t *testing.T) {
	const lagging = 3
	v := newControlVotersCadence(t, replica.Cadence{Commands: 16})
	for _, s := range v.stores {
		s.SetStatePatchGate(func() bool { return true })
		s.SetCompactAdmissionGate(func() bool { return true })
		if err := s.BindAdmissionOwner(&lookupOwner{}); err != nil {
			t.Fatal(err)
		}
	}
	if !v.stores[1].LedgerLayoutForTest() {
		t.Fatal("the fixture's installation keeps its books in the state, not the ledger: the admission rounds do not run")
	}
	v.leaderIs(1)
	group := model.NewID()
	consumed := map[uint64]model.AdmissionReservation{} // by cursor index
	var next uint64
	admit := func(id uint64, phase string, n int) {
		t.Helper()
		f := v.fx[id].fenceFx
		for i := range n {
			r, err := reserveSeries(f, fmt.Sprintf("snapshot_install_%s_v%d_%d", phase, id, i))
			if err != nil {
				t.Fatalf("%s: voter %d reserve: %v", phase, id, err)
			}
			if i%4 == 3 {
				continue // stays reserved: a row the snapshot carries as reserved
			}
			next++
			cursor := model.Cursor{Group: group, Index: model.Uint64(next)}
			if err := f.store.FinalizeAdmission(f.ctx, sourceScopeOf(f), model.FinalizeAdmission{ReservationID: r.ID, Cursor: cursor}); err != nil {
				t.Fatalf("%s: voter %d finalize: %v", phase, id, err)
			}
			r.State, r.Cursor = "consumed", &cursor
			consumed[next] = r
		}
	}
	settle := func(phase string) {
		t.Helper()
		const span = 4
		var candidates []model.SettleCandidate
		for n := uint64(0); ; n++ {
			var items []model.ChargeItem
			for i := n*span + 1; i <= n*span+span; i++ {
				r, ok := consumed[i]
				if !ok {
					break
				}
				items = append(items, model.ChargeOf(r))
			}
			if len(items) != span {
				break
			}
			candidates = append(candidates, model.SettleCandidate{Group: group, N: n, Span: span, Batches: span, Charge: model.ChargeDigest(items)})
		}
		rep, err := v.stores[1].SettleAdmissions(v.fx[1].ctx, candidates)
		if err != nil || rep.Reservations == 0 {
			t.Fatalf("%s: settle: %+v, %v", phase, rep, err)
		}
	}
	identical := func(phase string) {
		t.Helper()
		v.converge()
		want := v.fx[1].canonicalState()
		for _, id := range []uint64{2, 3} {
			if got := v.fx[id].canonicalState(); got != want {
				t.Fatalf("%s: voter %d holds other books than voter 1", phase, id)
			}
		}
	}
	admit(1, "before", 8) // every voter has these
	identical("before")
	v.mesh.cut(lagging, true)
	admit(1, "cut", 40)
	settle("cut")
	admit(1, "cut2", 24)
	rsv, fin := v.stores[1].CompactAdmissionOps()
	if rsv == 0 || fin == 0 || v.stores[1].CompactSettleOps() == 0 {
		t.Fatalf("the group proposed %d rsv, %d fin and %d chs ops while the voter was cut off: the premise (compact ops in the snapshot) does not hold", rsv, fin, v.stores[1].CompactSettleOps())
	}
	for _, id := range []uint64{1, 2} {
		g := v.stores[id].ReplicaGroup()
		v.eventually(fmt.Sprintf("voter %d cut a snapshot and compacted its journal past voter %d", id, lagging), func() bool {
			_, behind := v.stores[lagging].ReplicaGroup().JournalRange()
			if first, _ := g.JournalRange(); first > behind+1 {
				return true
			}
			if _, err := g.CreateSnapshot(context.Background(), g.Status().ApplicationCursor); err != nil {
				return false
			}
			if _, err := g.CompactJournal(context.Background()); err != nil {
				return false
			}
			first, _ := g.JournalRange()
			return first > behind+1
		})
	}
	v.mesh.mu.Lock()
	handed := v.mesh.snaps[lagging]
	v.mesh.mu.Unlock()
	if handed != 0 {
		t.Fatalf("voter %d was handed %d snapshots while it was cut off", lagging, handed)
	}
	v.mesh.cut(lagging, false)
	v.await(lagging, v.mustRevision(1))
	v.mesh.mu.Lock()
	handed = v.mesh.snaps[lagging]
	v.mesh.mu.Unlock()
	if handed < 1 {
		t.Fatalf("voter %d caught up without installing a snapshot: the compacted journals left it no other way", lagging)
	}
	identical("installed")
	// The installed voter applies compact ops over the installed rows and proposes against them.
	admit(lagging, "after_own", 8)
	admit(1, "after", 12)
	settle("after")
	identical("after")
}
