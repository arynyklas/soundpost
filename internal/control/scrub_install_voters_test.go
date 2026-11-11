// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"testing"

	"soundpost/internal/control"
	"soundpost/internal/model"
)

// A voter that was cut off holds a payload in its own control.db. The leader erases it, scrubs
// ITS file (the scrubbed audit is replicated), compacts its journal past the voter, and the
// voter catches up by installing the leader's snapshot: the installed log says the scrub is
// done, but this voter's file still holds the payload in the pages the install freed. Its
// receipt must name control_state until a ScrubErased ran on its own file, and nothing the
// leader commits afterwards may change that or what any voter computes.
func TestAVoterThatInstalledTheLeadersSnapshotScrubsItsOwnFile(t *testing.T) {
	v := newControlVoters(t)
	const before, during = "CANARYINSTALLBEFORE0d2b86a7c41e", "CANARYINSTALLDURING0d2b86a7c41e"
	leader := v.fx[1]
	leader.seedAll(leader.newSeed(leader.project, before), 50) // on all three voters
	v.await(2, v.mustRevision(1))
	v.await(3, v.mustRevision(1))
	v.mesh.cut(3, true)
	leader.seedAll(leader.newSeed(leader.project, during), 60) // voter 3 never receives these commands
	leader.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{leader.project}})
	v.await(2, v.mustRevision(1))
	leader.pass() // the leader's journal no longer holds what voter 3 needs: it will be sent a snapshot
	if leader.auditsOf("delete.control_scrubbed") == 0 {
		t.Fatal("fixture invalid: the leader's log carries no scrubbed audit")
	}
	if hits := controlDBHits(t, v.dirs[3], before); len(hits) == 0 {
		t.Fatal("fixture invalid: the voter that was cut off does not hold the payload in its control.db")
	}

	v.mesh.cut(3, false)
	v.await(3, v.mustRevision(1))
	voter := v.fx[3]
	if voter.auditsOf("delete.control_scrubbed") == 0 {
		t.Fatal("fixture invalid: the voter did not receive the leader's log")
	}
	if voter.stateHolds(before) {
		t.Fatal("fixture invalid: the voter's live state still holds the erased payload")
	}
	held := controlDBHits(t, v.dirs[3], before)
	if len(held) == 0 {
		t.Fatal("fixture invalid: the install left no copy of the replaced state in the voter's control.db")
	}
	if got := v.stores[3].ResidualStores(); !contains(got, control.ResidualControlState) {
		t.Fatalf("FALSE CLEAN: voter 3's own %v holds the erased payload after the install, and the leader's scrubbed audit settled its receipt: %v", held, got)
	}

	// A commit of the leader changes neither the voter's debt nor what the voters compute.
	if err := v.stores[1].Update(leader.ctx, func(st *control.State) error {
		st.Quotas = map[string]model.QuotaState{"after:install": {MaxBytes: 1}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint64{2, 3} {
		v.await(id, v.mustRevision(1))
	}
	if v.fx[1].canonicalState() != v.fx[2].canonicalState() || v.fx[1].canonicalState() != voter.canonicalState() {
		t.Fatal("the voters diverged after the install")
	}
	if got := v.stores[3].ResidualStores(); !contains(got, control.ResidualControlState) {
		t.Fatalf("a replicated commit settled the voter's own scrub debt: %v", got)
	}

	// The voter's own pass: the scrub of its file, then the journal.
	if err := v.stores[3].ScrubErased(voter.ctx); err != nil {
		t.Fatal(err)
	}
	if hits := controlDBHits(t, v.dirs[3], before); len(hits) != 0 {
		t.Fatalf("voter 3's control.db still holds the erased payload after its own scrub: %v", hits)
	}
	if got := v.stores[3].ResidualStores(); contains(got, control.ResidualControlState) {
		t.Fatalf("voter 3 ran its scrub and still names control_state: %v", got)
	}
	voter.pass()
	v.await(1, v.mustRevision(3))
	if got := v.stores[3].ResidualStores(); len(got) != 0 {
		t.Fatalf("voter 3 after its own scrub and pass: %v", got)
	}
	if got := v.stores[1].ResidualStores(); len(got) != 0 {
		t.Fatalf("the leader installed nothing and ran its own pass: %v", got)
	}

	// The settled debt survives a restart of the file.
	dir := v.dirs[3]
	if err := v.stores[3].Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := control.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := reopened.ResidualStores(); contains(got, control.ResidualControlState) {
		t.Fatalf("a restart of voter 3 after its scrub names control_state again: %v", got)
	}
	if hits := controlDBHits(t, dir, before); len(hits) != 0 {
		t.Fatalf("a restart of voter 3 brought the erased payload back: %v", hits)
	}
}

// A follower that applied the erasure by replaying the log never installed anything, yet the
// leader's replicated delete.control_scrubbed arrives in the same log: it says the LEADER's
// file was scrubbed. The follower's own file still holds the erased payload in the pages the
// erasing commit freed, so its receipt must name control_state until a ScrubErased ran on its
// file, the marker must survive a restart, and the scrub it runs commits nothing replicated.
func TestAFollowerThatReplayedTheErasureScrubsItsOwnFile(t *testing.T) {
	v := newControlVoters(t)
	const gone = "CANARYREPLAYFOLLOWER0d2b86a7c41e"
	leader := v.fx[1]
	for range 40 { // the replaced state spans freed pages that later writes do not all reuse
		leader.seedAll(leader.newSeed(leader.project, gone), 50)
	}
	for _, id := range []uint64{2, 3} {
		v.await(id, v.mustRevision(1))
		if hits := controlDBHits(t, v.dirs[id], gone); len(hits) == 0 {
			t.Fatalf("fixture invalid: voter %d does not hold the payload in its control.db before the erasure", id)
		}
	}
	leader.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{leader.project}})
	scrubbed := leader.auditsOf("delete.control_scrubbed")
	if scrubbed == 0 {
		t.Fatal("fixture invalid: the leader's log carries no scrubbed audit")
	}
	for _, id := range []uint64{2, 3} {
		v.await(id, v.mustRevision(1))
		fx := v.fx[id]
		if fx.auditsOf("delete.control_scrubbed") != scrubbed || fx.stateHolds(gone) {
			t.Fatalf("fixture invalid: voter %d did not replay the leader's erasure and scrubbed audit", id)
		}
		held := controlDBHits(t, v.dirs[id], gone)
		if len(held) == 0 {
			t.Fatalf("fixture invalid: voter %d's control.db holds no copy of the replaced state", id)
		}
		if got := v.stores[id].ResidualStores(); !contains(got, control.ResidualControlState) {
			t.Fatalf("FALSE CLEAN: voter %d's own %v holds the erased payload, it applied the erasure and was never scrubbed, and the leader's scrubbed audit settled its receipt: %v", id, held, got)
		}
	}
	revision := v.mustRevision(1)

	// Voter 2: the debt is a fact about its file and survives a restart.
	dir := v.dirs[2]
	if err := v.stores[2].Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := control.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.ResidualStores(); !contains(got, control.ResidualControlState) {
		t.Fatalf("a restart of voter 2 forgot the scrub it owes: %v", got)
	}
	if hits := controlDBHits(t, dir, gone); len(hits) == 0 {
		t.Fatal("fixture invalid: the restart changed the payload bytes")
	}
	if err = reopened.ScrubErased(leader.ctx); err != nil {
		t.Fatal(err)
	}
	if hits := controlDBHits(t, dir, gone); len(hits) != 0 {
		t.Fatalf("voter 2's control.db still holds the erased payload after its own scrub: %v", hits)
	}
	if got := reopened.ResidualStores(); contains(got, control.ResidualControlState) {
		t.Fatalf("voter 2 ran its scrub and still names control_state: %v", got)
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := control.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if got := again.ResidualStores(); contains(got, control.ResidualControlState) {
		t.Fatalf("a restart after the scrub names control_state again: %v", got)
	}

	// Voter 3: the scrub of its live file commits nothing replicated and settles its receipt.
	if err = v.stores[3].ScrubErased(leader.ctx); err != nil {
		t.Fatal(err)
	}
	if hits := controlDBHits(t, v.dirs[3], gone); len(hits) != 0 {
		t.Fatalf("voter 3's control.db still holds the erased payload after its own scrub: %v", hits)
	}
	if got := v.stores[3].ResidualStores(); contains(got, control.ResidualControlState) {
		t.Fatalf("voter 3 ran its scrub and still names control_state: %v", got)
	}
	if v.mustRevision(1) != revision || v.mustRevision(3) != revision || v.fx[3].auditsOf("delete.control_scrubbed") != scrubbed {
		t.Fatal("a follower's local scrub committed a replicated command")
	}
	v.fx[3].pass()
	v.await(1, v.mustRevision(3))
	if got := v.stores[3].ResidualStores(); len(got) != 0 {
		t.Fatalf("voter 3 after its own scrub and pass: %v", got)
	}
}
