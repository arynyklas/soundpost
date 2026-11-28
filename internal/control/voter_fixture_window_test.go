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

// The lead also moves inside a step: a round is four commits, each taking a lease from the leader
// and sending a command under it, and a host that starves the voters for an election timeout (the
// leader hears no follower for ten ticks and steps down: CheckQuorum) does it between any two of
// them. TestAnAttestationIsSupersededByASnapshotInstall failed that way in CI (run 43884816070): the
// leader of term 4 stepped down 2 s after it was elected, and the fixture's next lease (Fence)
// answered `replica unavailable` at attest_voters_test.go:287, inside erasedWithVoter3Idle,
// although voter 1 had been confirmed as the leader a few milliseconds earlier. Here voter 1 is cut
// off right after that confirmation, in each kind of step, for three election timeouts (it steps
// down, the others elect a leader, and voter 1 rejoins as a follower): the write that follows must
// be retried once voter 1 leads again, and the fixture must finish with the same preconditions.
func TestTheErasureFixtureWaitsOutAnElectionWindowInsideAStep(t *testing.T) {
	for _, stage := range []string{"round 0", "round 5", "saga", "voter 1 pass", "voter 2 pass"} {
		t.Run(stage, func(t *testing.T) {
			v := newControlVoters(t)
			window := 30 * voterTick()
			fired := false
			v.afterLead = func(at string) {
				if at != stage || fired {
					return
				}
				fired = true
				v.mesh.cut(1, true)
				time.AfterFunc(window, func() { v.mesh.cut(1, false) })
			}
			v.erasedWithVoter3Idle("CANARYFIXTUREINSTEP5e0a91b7c4d2")
			if !fired {
				t.Fatalf("the fixture never reached the step %q", stage)
			}
			for _, id := range []uint64{1, 2} {
				if got := v.stores[id].ResidualStores(); len(got) != 0 {
					t.Fatalf("voter %d holds %v after its own pass and scrub", id, got)
				}
			}
		})
	}
}

// The fixture absorbs a transient lead move with a retry, which would also absorb a leadership that
// moves all the time. retryWrite counts the retried attempts and every three-voter test fails when
// they exceed maxFixtureRetries (measured, wave 17: 0 retries in the natural runs of the voter tests,
// 1 in a step that is disturbed on purpose, so the bound is ten times the observed worst case).
func TestTheFixtureRetryBoundReportsAnUnstableLead(t *testing.T) {
	if err := retryVerdict(maxFixtureRetries, maxFixtureRetries); err != nil {
		t.Fatalf("the bound itself is not an excess: %v", err)
	}
	if err := retryVerdict(maxFixtureRetries+1, maxFixtureRetries); err == nil {
		t.Fatal("more retries than the bound passed")
	}
	if err := retryVerdict(0, maxFixtureRetries); err != nil {
		t.Fatalf("no retry reported: %v", err)
	}
}
