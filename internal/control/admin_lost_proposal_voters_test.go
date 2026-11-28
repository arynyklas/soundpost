// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// An admin command of an organization (a project's retention policy written through POST /api/v1/policies, an admin save of
// a team, a membership, a source policy) is one application-index compare-and-swap per proposal like every control write. The
// retention commands re-judge the state and propose again when their proposal lost that race (retryLostProposals); the admin
// commands, committed through Store.UpdateOrgAuthority, did not: a proposal that lost to ANY other control commit (every
// voter runs background writers) was answered with the plain, not retryable `stale`, HTTP 409 code=stale, although the
// caller's view (its expected epoch) still held and nothing had been committed. A real-binary run of TestMixedBinaryVoters
// (candidate voter 3) failed once with `save_failed: policy-write retention ... code=stale 409`: the organization's epoch was
// the same before and after the refused save, and a moved expected epoch answers `conflict`, not `stale`.
//
// adminOrgSave is the judgment adminCommand makes in its transition (the object compare on the epoch the caller read, then the
// write that tracks the change), for a setting of the organization.
func adminOrgSave(st *control.State, org model.ID, key string, expected model.Revision, value string) error {
	o, ok := st.Orgs[org.String()]
	if !ok {
		return model.Fail(model.NotFound)
	}
	if o.ObjectChangedAfter(key, uint64(expected)) {
		return model.Fail(model.Conflict)
	}
	if o.Settings == nil {
		o.Settings = map[string]json.RawMessage{}
	}
	o.Settings[key] = json.RawMessage(value)
	o.TrackChange(key)
	st.Orgs[org.String()] = o
	return nil
}

func orgEpochOn(t *testing.T, f *eraseFx) model.Revision {
	t.Helper()
	var epoch uint64
	if err := f.store.View(f.ctx, func(st control.State) error { epoch = st.Orgs[f.org.String()].Epoch; return nil }); err != nil {
		t.Fatal(err)
	}
	return model.Revision(epoch)
}

func orgSettingOn(t *testing.T, s *control.Store, f *eraseFx, key string) string {
	t.Helper()
	var value string
	if err := s.View(f.ctx, func(st control.State) error { value = string(st.Orgs[f.org.String()].Settings[key]); return nil }); err != nil {
		t.Fatal(err)
	}
	return value
}

// A save that loses the application-index race with its expected epoch still valid is judged again on a fresh read and
// committed, whichever voter it is made through and however many times a racing writer wins before it.
func TestAnAdminCommandThatLostTheApplicationIndexRaceIsJudgedAgainAndCommitted(t *testing.T) {
	for _, c := range []struct {
		name          string
		writer, racer uint64 // the voter the command is made through, and the voter whose writer commits in its window
		races         int    // how many attempts of the command a racing commit lands in
	}{{"follower, one lost proposal", 3, 1, 1}, {"follower, three", 3, 1, 3}, {"leader, one lost proposal", 1, 2, 1}, {"leader, three", 1, 2, 3}} {
		t.Run(c.name, func(t *testing.T) {
			v := newControlVoters(t)
			v.leaderIs(1)
			f := v.fx[c.writer]
			writer, racer := v.stores[c.writer], v.stores[c.racer]
			key := "retention:" + model.NewID().String()
			expected := orgEpochOn(t, f)
			attempts, raced := 0, 0
			err := writer.UpdateOrgAuthority(f.ctx, f.org, func(st *control.State) error {
				attempts++
				if attempts <= c.races {
					// the racing writer commits between this run's read of the state and its proposal; a writer that has been given
					// the turn finds the racer held (stale), which is the turn doing its work and not a failure of the test
					switch e := racer.PlainUpdateForTest(f.ctx); {
					case e == nil:
						raced++
					case isFault(e, model.Stale):
					default:
						t.Errorf("the racing writer: %v", e)
					}
				}
				return adminOrgSave(st, f.org, key, expected, `{"days":7}`)
			})
			if err != nil {
				t.Fatalf("after %d attempts (the racing writer committed %d times): %v (the organization's epoch is still the one the save was based on: %t)", attempts, raced, err, orgEpochOn(t, f) == expected)
			}
			if raced < 1 || attempts < 2 {
				t.Fatalf("attempts %d, racing commits %d: the save was to lose the race at least once and still commit", attempts, raced)
			}
			v.converge()
			for id, s := range v.stores {
				if got := orgSettingOn(t, s, v.fx[id], key); got != `{"days":7}` {
					t.Errorf("voter %d holds %q for the saved setting", id, got)
				}
			}
		})
	}
}

// What stays a refusal is the caller's own view: a save whose object was changed after the epoch it was based on is a
// conflict (409 code=conflict), answered after one more judgment, never retried against the new state and never `stale`.
func TestAnAdminCommandOfAnObjectThatChangedMeanwhileIsAConflictNotAStaleAndNotRetriedForever(t *testing.T) {
	for _, c := range []struct {
		name          string
		writer, racer uint64
	}{{"follower", 3, 1}, {"leader", 1, 2}} {
		t.Run(c.name, func(t *testing.T) {
			v := newControlVoters(t)
			v.leaderIs(1)
			f := v.fx[c.writer]
			writer, racer := v.stores[c.writer], v.stores[c.racer]
			key := "retention:" + model.NewID().String()
			expected := orgEpochOn(t, f)
			attempts := 0
			err := writer.UpdateOrgAuthority(f.ctx, f.org, func(st *control.State) error {
				attempts++
				if attempts == 1 {
					// another administrator saves the same object after the epoch this save was based on, in the window of its proposal
					if e := racer.UpdateOrgAuthority(f.ctx, f.org, func(st *control.State) error {
						return adminOrgSave(st, f.org, key, expected, `{"days":1}`)
					}); e != nil {
						t.Errorf("the other administrator's save: %v", e)
					}
				}
				return adminOrgSave(st, f.org, key, expected, `{"days":2}`)
			})
			if !isFault(err, model.Conflict) {
				t.Fatalf("a save of an object that changed after its epoch: %v, want conflict", err)
			}
			if attempts != 2 {
				t.Fatalf("%d attempts: the save is judged again once on the state that includes the other save, and refused", attempts)
			}
			v.converge()
			for id, s := range v.stores {
				if got := orgSettingOn(t, s, v.fx[id], key); got != `{"days":1}` {
					t.Errorf("voter %d holds %q: the other administrator's save is the one that stands", id, got)
				}
			}
		})
	}
}

// The policy write of the project settings page, through the real service, from every voter while intake saturates every voter
// (the load of TestBeginIsNotRefusedByLostProposalsFromAnyVoterUnderSaturatingIntake): every write is answered, none is refused
// as stale.
func TestAPolicyWriteIsNotRefusedByLostProposalsFromAnyVoterUnderSaturatingIntake(t *testing.T) {
	policyWritesUnderSaturatingIntake(t, false)
}

func TestAPolicyWriteIsNotRefusedByLostProposalsFromAnyVoterUnderSaturatingIntakeAsAPatch(t *testing.T) {
	policyWritesUnderSaturatingIntake(t, true)
}

func policyWritesUnderSaturatingIntake(t *testing.T, patch bool) {
	v := newControlVoters(t)
	if patch {
		for _, s := range v.stores {
			s.SetStatePatchGate(func() bool { return true })
		}
	}
	if raceEnabled {
		for _, s := range v.stores {
			s.SetAdmissionYieldScaleForTest(8) // see beginUnderSaturatingIntake
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
	time.Sleep(2 * time.Second) // intake is saturating on every voter before the first write
	const writes = 12
	setting := model.NewID()
	days := uint32(0)
	for _, node := range []uint64{3, 2, 1} {
		f := v.fx[node]
		refused := map[string]int{}
		for range writes {
			days++
			if err := policyWrite(t, f, setting, days); err != nil {
				code, retryable := "other", false
				var fault *model.Fault
				if errors.As(err, &fault) {
					code, retryable = string(fault.Code), fault.Retryable
				}
				refused[fmt.Sprintf("%s retryable=%t: %v", code, retryable, err)]++
			}
		}
		if len(refused) != 0 {
			t.Errorf("voter %d (leader: %v): %d of %d policy writes refused under saturating intake: %v", node, node == 1, sumInts(refused), writes, refused)
		}
	}
	if admitted.Load() == 0 {
		t.Fatal("no intake was admitted: the writes did not run under load")
	}
}

// policyWrite is POST /api/v1/policies (write, retention) as the handler commits it: the organization's epoch read just before,
// the scope derived for the project, the command committed through auth.Service.PolicyCommand.
func policyWrite(t *testing.T, f *eraseFx, setting model.ID, days uint32) error {
	t.Helper()
	epoch := orgEpochOn(t, f)
	scope, err := f.svc.AuthorizeWrite(f.ctx, f.cred, f.org, f.project, auth.PolicyWrite)
	if err != nil {
		return err
	}
	config, err := json.Marshal(auth.RetentionConfig{ProjectID: f.project, Signal: "metrics", Days: days})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(auth.AdminPayload{ID: setting, ProjectID: f.project, Reason: "policy write under intake", Config: config})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.PolicyCommand(f.ctx, f.cred, scope, f.project, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: epoch, OrgID: f.org, Kind: auth.PolicyKindRetention, Payload: payload})
	return err
}
