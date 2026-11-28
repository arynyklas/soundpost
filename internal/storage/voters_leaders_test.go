// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"testing"
	"time"
)

// leaderHoldWindow is longer than the replica balancer's settle time (10 s: a leader that has led a group that long
// hands it to the group's preferred voter, replica/balance.go) with margin for its per-group stagger.
const leaderHoldWindow = 16 * time.Second

// The voters fixture places every group's leader by hand (voters.lead) and the tests after it depend on that
// placement: a voter that sends a snapshot commits a notice in slot 0 first and the test mesh has no proposal
// forwarder, so the sender of every group must lead slot 0 as well. The balancer of the replica package, which hands
// a group to its preferred member once its leader has led for 10 s, took the groups of the preferred voters 2 and 3
// away from voter 1 whenever a test ran longer than that after its last lead (always under -race with other test
// processes on the machine): the snapshots of those groups to a voter that lagged were then never sent, and
// TestASnapshotWithNoNoticeNeverInstallsOnAVoterThatDeclaredItsDisk and its sibling waited 60 s for voters that could
// not converge.
func TestTheVotersFixtureKeepsTheLeadersItPlaced(t *testing.T) {
	store, service, _, _ := fixture(t)
	v := openVoters(t, service, store)
	v.lead(t, func(int) uint64 { return 1 })
	time.Sleep(leaderHoldWindow)
	moved := map[int]uint64{}
	for slot := range 64 {
		for node := uint64(1); node <= 3; node++ {
			if leader := v.groups[node][slot].Status().Leader; leader != 1 {
				moved[slot] = leader
			}
		}
	}
	if len(moved) != 0 {
		t.Fatalf("the leaders of %d groups moved off voter 1 although the fixture placed them there (slot: leader): %v", len(moved), moved)
	}
}
