// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// admissionVoters is three control voters over the production transport whose admission transitions are
// proposed as ledger patches (the state patch gate is open on every voter).
func admissionVoters(t *testing.T, bind ...uint64) (*controlVoters, *mtlsVoterNetwork) {
	t.Helper()
	mesh := newMTLSVoterNetwork(t)
	v := newControlVotersOn(t, mesh, replica.Cadence{})
	for id, s := range v.stores {
		s.SetStatePatchGate(func() bool { return true })
		for _, b := range bind {
			if b == id {
				if err := s.BindAdmissionScopes(v.fx[id].svc); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if !v.stores[1].LedgerLayoutForTest() {
		t.Fatal("the fixture's installation keeps its books in the state, not the ledger: the admission rounds do not run")
	}
	v.leaderIs(1)
	return v, mesh
}

// admitFrom admits workers x each batches of distinct series through voter id.
func admitFrom(t *testing.T, v *controlVoters, id uint64, workers, each int) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make(chan error, workers*each)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				if _, err := reserveSeries(v.fx[id].fenceFx, fmt.Sprintf("remote_admission_v%d_w%d_%d", id, w, i)); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("voter %d: %v", id, err)
	}
}

// The voters that are not the leader of the control group do not run admission rounds of their own: they ask the
// leader to judge their reserve and finalize transitions, and it does so in its own rounds beside its own. Measured
// on the cluster at 1750 records/s before this, 83 % and 90 % of the rounds the two followers proposed lost the
// race for the revision to the leader's (and every one of them had carried its whole patch to the leader to be
// refused), so the requests that entered at a follower waited out their budget.
func TestFollowersAdmissionsAreJudgedByTheLeader(t *testing.T) {
	v, _ := admissionVoters(t, 1, 2, 3)
	const workers, each = 6, 12
	var wg sync.WaitGroup
	for _, id := range []uint64{1, 2, 3} {
		wg.Add(1)
		go func() { defer wg.Done(); admitFrom(t, v, id, workers, each) }()
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	leaderRounds := v.stores[1].AdmissionRoundsForTest()
	if leaderRounds == 0 {
		t.Fatal("the leader proposed no admission round")
	}
	for _, id := range []uint64{2, 3} {
		if rounds := v.stores[id].AdmissionRoundsForTest(); rounds != 0 {
			t.Errorf("voter %d proposed %d admission rounds of its own: its transitions were not judged by the leader", id, rounds)
		}
		calls, fallbacks, _ := v.stores[id].RemoteAdmissionForTest()
		if calls < workers*each || fallbacks != 0 {
			t.Errorf("voter %d made %d calls to the leader (want at least %d) and judged %d itself", id, calls, workers*each, fallbacks)
		}
	}
	if _, _, served := v.stores[1].RemoteAdmissionForTest(); served < 2*workers*each {
		t.Errorf("the leader served %d calls, want at least %d (%d batches from each of the two followers)", served, 2*workers*each, workers*each)
	}
	// Every voter holds the same books.
	v.converge()
	want := v.fx[1].canonicalState()
	for _, id := range []uint64{2, 3} {
		if got := v.fx[id].canonicalState(); got != want {
			t.Fatalf("voter %d holds other books than the leader's", id)
		}
	}
}

// A leader that does not serve the call (a release that does not know it, a store without the authority that
// makes the scope of a claim) is not an error for the voter that called: it judges its transitions itself, as it
// did before there were calls, and the books come out the same.
func TestAFollowerJudgesItsOwnAdmissionsWhenTheLeaderDoesNotServeTheCall(t *testing.T) {
	v, _ := admissionVoters(t, 2, 3) // voter 1, the leader, has no claim scopes bound: it answers every call unavailable
	admitFrom(t, v, 2, 4, 6)
	if t.Failed() {
		return
	}
	calls, fallbacks, _ := v.stores[2].RemoteAdmissionForTest()
	if calls == 0 || fallbacks == 0 {
		t.Fatalf("voter 2 made %d calls and fell back %d times: the leader's refusal to serve was not met by judging the transitions itself", calls, fallbacks)
	}
	if rounds := v.stores[2].AdmissionRoundsForTest(); rounds == 0 {
		t.Fatal("voter 2 admitted without proposing a round")
	}
	v.converge()
	if v.fx[1].canonicalState() != v.fx[2].canonicalState() {
		t.Fatal("the voters hold different books")
	}
}

// What the leader judges for a follower is what the leader's own books say about the claim, not what the follower
// says: a claim that names an organization the source is not of is refused, nothing is committed, and the refusal
// reaches the caller as the leader's own (Forbidden), not as an unavailable leader.
func TestTheLeaderRefusesAClaimThatNamesAnotherOrganization(t *testing.T) {
	v, _ := admissionVoters(t, 1, 2, 3)
	f := v.fx[2].fenceFx
	src, err := f.svc.AuthenticateSource(f.ctx, f.sourceCredential, "", false)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := f.svc.SourceScope(f.ctx, src, false)
	if err != nil {
		t.Fatal(err)
	}
	claim, ok := scope.SourceClaim()
	if !ok {
		t.Fatal("a source scope has no claim")
	}
	claim.Org = model.NewID()
	body, err := json.Marshal(map[string]any{"claim": claim, "finalize": model.FinalizeAdmission{ReservationID: model.NewID(), Cursor: model.Cursor{Group: model.NewID(), Index: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	before := v.mustRevision(1)
	_, err = v.stores[2].ReplicaGroup().CallLeader(ctx, "admission.v1", body)
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Forbidden {
		t.Fatalf("the forged claim was answered %v, want the leader's refusal (forbidden)", err)
	}
	if after := v.mustRevision(1); after != before {
		t.Fatalf("the refused claim moved the revision %d -> %d", before, after)
	}
}

// A call that fails for any reason but the leader's not serving it is answered to the caller as unavailable: the voter does not
// judge the transition itself (it would lose the round at the leader nearly every time and carry its patch there to be
// refused: the followers' lost rounds of the 1750 records/s run), and its sender retries.
func TestAFailedCallIsNotJudgedByTheVoterThatCalled(t *testing.T) {
	v, _ := admissionVoters(t, 1, 2, 3)
	v.stores[1].ReplicaGroup().HandleCall("admission.v1", func(context.Context, uint64, []byte) ([]byte, error) {
		return nil, model.Fail(model.Unavailable)
	})
	_, err := reserveSeries(v.fx[2].fenceFx, "failed_call_v2")
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Unavailable {
		t.Fatalf("a transition whose call failed was answered %v, want unavailable", err)
	}
	calls, fallbacks, _ := v.stores[2].RemoteAdmissionForTest()
	if calls == 0 || fallbacks != 0 {
		t.Fatalf("voter 2 made %d calls and judged %d transitions itself after a failed call", calls, fallbacks)
	}
	if rounds := v.stores[2].AdmissionRoundsForTest(); rounds != 0 {
		t.Fatalf("voter 2 proposed %d admission rounds of its own after a failed call", rounds)
	}
}
