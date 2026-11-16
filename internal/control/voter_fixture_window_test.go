// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"testing"
	"time"
)

// The three-voter erasure fixture writes through voter 1 (a leader-bound write answers
// `replica unavailable` while no voter leads), so a host that starves the voters for a moment
// (a 4-vCPU CI runner running two test packages at once) can fail a fixture step with an error
// that has nothing to do with the test: TestARestartedVoterKeepsItsAttestationOnlyWithItsDurableProof
// failed once in CI at attest_voters_test.go:584, inside erasedWithVoter3Idle, which confirmed
// the leadership every tenth round only. Here the disturbance is made on purpose: voter 1 is cut
// off from the group before round 3 (it loses the lead; the others elect one) and rejoins 800 ms
// later. The fixture has to wait the window out and finish with the same preconditions.
func TestTheErasureFixtureWaitsOutAnElectionWindowBetweenRounds(t *testing.T) {
	v := newControlVoters(t)
	v.beforeRound = func(round int) {
		if round != 3 {
			return
		}
		v.mesh.cut(1, true)
		time.AfterFunc(800*time.Millisecond, func() { v.mesh.cut(1, false) })
	}
	v.erasedWithVoter3Idle("CANARYFIXTUREWINDOW5e0a91b7c4d2")
	for _, id := range []uint64{1, 2} {
		if got := v.stores[id].ResidualStores(); len(got) != 0 {
			t.Fatalf("voter %d holds %v after its own pass and scrub", id, got)
		}
	}
}
