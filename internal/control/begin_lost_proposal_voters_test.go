// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// A deletion Begin carries the caller's view as a range, so unrelated writes do not conflict it
// (TestAuthorityRevision*). In a three-voter group the commit is still one application-index
// compare-and-swap per proposal: with intake running on every voter, a Begin submitted through a
// voter that does not lead lost that race on most attempts and answered Stale (HTTP 409) although
// nothing authority-relevant had moved (independent review of 10.05, finding F-10.05-1: 30/40 and
// 35/40 refused from a follower, 0/40 on one voter). The retention commands re-judge the state and
// propose again when their proposal lost the race, so every Begin is answered, from every voter.
func TestBeginIsNotRefusedByLostProposalsFromAnyVoterUnderSaturatingIntake(t *testing.T) {
	beginUnderSaturatingIntake(t, false)
}

// The same in the mode production runs in once every member declared protocol 5: every command is a state
// patch, and a retention command of an organization is verified and moves the organization's own
// authority revision (authority_org.go). A first version of that verification encoded the whole state twice
// more per attempt in a replacement; each attempt was then several times as long, lost the race more often
// and refused 7 to 9 of 12 Begins (wave 26, reverted; cause measured in wave 28). Both modes must answer every
// Begin.
func TestBeginIsNotRefusedByLostProposalsFromAnyVoterUnderSaturatingIntakeAsAPatch(t *testing.T) {
	beginUnderSaturatingIntake(t, true)
}

func beginUnderSaturatingIntake(t *testing.T, patch bool) {
	v := newControlVoters(t)
	if patch {
		for _, s := range v.stores {
			s.SetStatePatchGate(func() bool { return true })
		}
	}
	if raceEnabled {
		// A Begin attempt under the race detector takes several times as long between its read and its proposal, so the window in which the
		// leader holds admission back for a writer that lost (admission_yield.go, sized for a plain build) closes before the loser proposes
		// again: the window of eight times the length is the one this build's attempts need. The product is the same code in both builds.
		for _, s := range v.stores {
			s.SetAdmissionYieldScaleForTest(8)
		}
	}
	for id := uint64(2); id <= 3; id++ {
		f := v.fx[id]
		sess, err := f.svc.Login(f.ctx, "owner@example.test", "a long test password 2026", "")
		if err != nil {
			t.Fatal(err)
		}
		if f.cred, err = f.svc.Authenticate(f.ctx, sess.Token); err != nil {
			t.Fatal(err)
		}
	}
	v.leaderIs(1)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var admitted atomic.Int64
	for id := uint64(1); id <= 3; id++ {
		for range 2 {
			wg.Add(1)
			go func(f *fenceFx) {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					if intake(f) == nil {
						admitted.Add(1)
					}
				}
			}(v.fx[id].fenceFx)
		}
	}
	defer func() { close(stop); wg.Wait() }()
	time.Sleep(2 * time.Second) // intake is saturating on every voter before the first Begin
	const begins = 12
	// No voter's Begin needs more attempts than attemptBound (D107 condition 3), a quarter of the budget of 64. The plain build's bound is
	// the measured one: under eight CPU burners, 1560 Begins per voter (both modes), at most 7 attempts from a follower and 12 from the
	// leader, whose attempts are short and partly spent in the rest between turns. Under the race detector every attempt is several times as
	// long as the turn (sized for a plain build), so the tail is longer: raceAttemptScale is that factor, measured over the race runs of
	// both modes under 8 and 16 burners (72 runs, 216 voter tails; the report of the final run has them): at most 32 attempts from any
	// voter (a follower; the leader's at most 28), 2 times the plain bound, so 3 times it (48) is a bound with room that is still below
	// the budget. In neither build may a Begin reach the budget itself: that is the refusal (stale, not retryable) this test rules out.
	const attemptBound = 16
	const raceAttemptScale = 3
	bound := attemptBound
	if raceEnabled {
		bound *= raceAttemptScale
	}
	ran := time.Now()
	for _, node := range []uint64{3, 2, 1} {
		before := v.fx[node].store.AttemptCountsForTest()
		defer func() {
			after := v.fx[node].store.AttemptCountsForTest()
			var dist []string
			bounds := control.AttemptBoundsForTest()
			for i, n := range after {
				if n -= before[i]; n > 0 {
					bucket := "33+"
					if i < len(bounds) {
						bucket = fmt.Sprintf("<=%d", bounds[i])
					}
					dist = append(dist, fmt.Sprintf("%s=%d", bucket, n))
				}
			}
			most := v.fx[node].store.MostAttemptsForTest()
			t.Logf("ATTEMPTS voter %d (leader: %v): most %d (bound %d, budget %d), %v", node, node == 1, most, bound, control.MaxLostProposalsForTest, dist)
			if most > bound {
				t.Errorf("voter %d (leader: %v): a Begin needed %d attempts, more than %d", node, node == 1, most, bound)
			}
			if most >= control.MaxLostProposalsForTest {
				t.Errorf("voter %d (leader: %v): a Begin used up the budget of %d attempts", node, node == 1, control.MaxLostProposalsForTest)
			}
			if node == 1 {
				granted, refused, stale, held, maxHold := v.fx[1].store.TurnStatsForTest()
				t.Logf("TURNS granted %d refused-in-rest %d stale-answers %d held %v (%.1f%% of %v) max-hold %v", granted, refused, stale, held, 100*float64(held)/float64(time.Since(ran)), time.Since(ran).Round(time.Millisecond), maxHold)
			}
		}()
	}
	for _, node := range []uint64{3, 2, 1} {
		f := v.fx[node]
		refused := map[string]int{}
		for range begins {
			var view model.Revision
			if err := f.store.View(f.ctx, func(st control.State) error { view = st.Revision; return nil }); err != nil {
				t.Fatal(err)
			}
			began := time.Now()
			if err := f.beginAt(view); err != nil {
				var fault *model.Fault
				if errors.As(err, &fault) {
					// retryable says which stale it is: a fence no quorum answered in time (retryable), or a
					// proposal that lost the application-index race 64 times in a row (not).
					refused[fmt.Sprintf("%s retryable=%t after %s", fault.Code, fault.Retryable, time.Since(began).Round(100*time.Millisecond))]++
				} else {
					refused["other:"+err.Error()]++
				}
			}
		}
		if len(refused) != 0 {
			t.Errorf("voter %d (leader: %v): %d of %d Begin attempts refused under saturating intake: %v", node, node == 1, sumInts(refused), begins, refused)
		}
	}
	if admitted.Load() == 0 {
		t.Fatal("no intake was admitted: the Begins did not run under load")
	}
}

func sumInts(m map[string]int) int {
	n := 0
	for _, c := range m {
		n += c
	}
	return n
}
