// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// callMode is how the leader calls of the in-process voters fail (voterMesh.calls).
type callMode int32

const (
	callWorks      callMode = iota
	callRefused             // the connection is refused: nothing is sent
	callAnswerLost          // the leader runs the call and the connection drops before the answer comes back
)

// callVoters is three control voters over the in-process wires, with state patches, the claim scopes and an owner bound on every
// voter, so that a voter that is not the leader hands its admission transitions to the leader (admissionVoters, in-process).
func callVoters(t *testing.T) *controlVoters {
	t.Helper()
	v := newControlVotersOn(t, nil, replica.Cadence{})
	owner := &reconcileOwner{}
	for id, s := range v.stores {
		s.SetStatePatchGate(func() bool { return true })
		if err := s.BindAdmissionScopes(v.fx[id].svc); err != nil {
			t.Fatal(err)
		}
		if err := s.BindAdmissionOwner(owner); err != nil {
			t.Fatal(err)
		}
	}
	if !v.stores[1].LedgerLayoutForTest() {
		t.Fatal("the fixture's installation keeps its books in the state, not the ledger: no call is made")
	}
	v.leaderIs(1)
	return v
}

// seriesBatch is the normalized batch of one point of the series name, the one batch a sender sends again after a failure.
func seriesBatch(f *fenceFx, name string) (auth.Scope, model.NormalizedBatch, error) {
	var none model.NormalizedBatch
	src, err := f.svc.AuthenticateSource(f.ctx, f.sourceCredential, "", false)
	if err != nil {
		return auth.Scope{}, none, err
	}
	scope, err := f.svc.SourceScope(f.ctx, src, false)
	if err != nil {
		return auth.Scope{}, none, err
	}
	authority, err := f.svc.SourceAuthority(f.ctx, src, true)
	if err != nil {
		return auth.Scope{}, none, err
	}
	v := model.FloatBits(0x3ff0000000000000)
	policy := authority.Policy
	resource := model.Resource{Service: policy.Resources.Services[0], Environment: policy.Resources.Environments[0], Build: policy.Resources.Builds[0], Instance: policy.Resources.Instances[0]}
	point := model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &v, Type: "counter", Unit: "1"}}
	b := model.Batch{Version: 1, Project: f.project, Source: f.source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: 1000, Resource: resource, Payload: point}}}
	slot, _ := model.OwnerSlot(f.org, b.Project, b.Source, b.Producer, b.Records[0])
	b.RouteSlot = slot
	raw, err := model.CanonicalJSON(b)
	if err != nil {
		return auth.Scope{}, none, err
	}
	canonical, _ := model.CanonicalJSON(policy)
	return scope, model.NormalizedBatch{Batch: b, Org: f.org, Hash: model.HashCanonical(raw), Canonical: raw, PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyHash: model.HashCanonical(canonical).String(), AdmissionAt: model.UnixNano(f.now.UnixNano())}, nil
}

// requireRetryableUnavailable fails unless err is the retryable unavailable that the HTTP layer answers 503 with a Retry-After of 1 to 3
// seconds (httpapi TestReplyMapsOnlyALeaderGapToRetryable503).
func requireRetryableUnavailable(t *testing.T, what string, err error) {
	t.Helper()
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Unavailable || !fault.Retryable {
		t.Fatalf("%s: answered %v, want unavailable with retryable true", what, err)
	}
}

// The reserve a follower hands to the leader fails in the transport before the request leaves (the leader's connection is refused):
// the leader ran nothing, and the answer is the retryable unavailable, not the plain one a sender gives up on.
func TestAFollowersCallThatNeverLeftIsAnsweredRetryableUnavailable(t *testing.T) {
	v := callVoters(t)
	f := v.fx[2].fenceFx
	scope, b, err := seriesBatch(f, "refused_call")
	if err != nil {
		t.Fatal(err)
	}
	v.mesh.calls.Store(int32(callRefused))
	before := v.fx[1].canonicalState()
	_, err = v.stores[2].ReserveAdmission(f.ctx, scope, b)
	requireRetryableUnavailable(t, "a reserve whose call was refused", err)
	if v.fx[1].canonicalState() != before {
		t.Fatal("a call that was never sent changed the leader's books")
	}
	if calls, fallbacks, _ := v.stores[2].RemoteAdmissionForTest(); calls == 0 || fallbacks != 0 {
		t.Fatalf("voter 2 made %d calls and judged %d itself", calls, fallbacks)
	}
	v.mesh.calls.Store(int32(callWorks))
	if _, err = v.stores[2].ReserveAdmission(f.ctx, scope, b); err != nil {
		t.Fatalf("the sender's retry: %v", err)
	}
}

// A reserve whose request reached the leader and whose answer was lost was committed: the retry with the same batch finds the
// reservation of its key and charges nothing again (quota heads, series counts and the ledger are as the first run left them).
func TestAReserveWhoseAnswerWasLostIsFoundByItsRetry(t *testing.T) {
	v := callVoters(t)
	f := v.fx[2].fenceFx
	scope, b, err := seriesBatch(f, "lost_answer_reserve")
	if err != nil {
		t.Fatal(err)
	}
	v.mesh.calls.Store(int32(callAnswerLost))
	first, err := v.stores[2].ReserveAdmission(f.ctx, scope, b)
	requireRetryableUnavailable(t, "a reserve whose answer was lost", err)
	afterFirst := v.fx[1].canonicalState()
	if got := reservationsOf(t, v.fx[1]); got != 1 {
		t.Fatalf("the leader holds %d reservations after the call it ran, want 1", got)
	}
	v.mesh.calls.Store(int32(callWorks))
	second, err := v.stores[2].ReserveAdmission(f.ctx, scope, b)
	if err != nil {
		t.Fatalf("the sender's retry: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("the retry was given reservation %s, the first run committed %s: it was reserved twice", second.ID, first.ID)
	}
	if v.fx[1].canonicalState() != afterFirst {
		t.Fatal("the retry changed the leader's books: quota heads, series counts or the ledger were charged again")
	}
}

// A finalize whose answer was lost was committed: the retry finds the reservation consumed at the same cursor and changes nothing.
func TestAFinalizeWhoseAnswerWasLostIsFoundByItsRetry(t *testing.T) {
	v := callVoters(t)
	f := v.fx[2].fenceFx
	scope, b, err := seriesBatch(f, "lost_answer_finalize")
	if err != nil {
		t.Fatal(err)
	}
	r, err := v.stores[2].ReserveAdmission(f.ctx, scope, b)
	if err != nil {
		t.Fatal(err)
	}
	fin := model.FinalizeAdmission{ReservationID: r.ID, Cursor: model.Cursor{Group: model.NewID(), Index: 1}}
	v.mesh.calls.Store(int32(callAnswerLost))
	requireRetryableUnavailable(t, "a finalize whose answer was lost", v.stores[2].FinalizeAdmission(f.ctx, scope, fin))
	afterFirst := v.fx[1].canonicalState()
	v.mesh.calls.Store(int32(callWorks))
	if err = v.stores[2].FinalizeAdmission(f.ctx, scope, fin); err != nil {
		t.Fatalf("the sender's retry: %v", err)
	}
	if v.fx[1].canonicalState() != afterFirst {
		t.Fatal("the retry changed the leader's books")
	}
}

// A settlement whose answer was lost was committed: the retry finds its rows gone, commits nothing and leaves the books as the first
// run did.
func TestASettlementWhoseAnswerWasLostIsFoundByItsRetry(t *testing.T) {
	v := callVoters(t)
	f := v.fx[1].fenceFx
	scope := sourceScopeOf(f)
	group := model.NewID()
	var rows []model.AdmissionReservation
	for i := range 4 {
		r, err := reserveSeries(f, fmt.Sprintf("lost_answer_settle_%d", i))
		if err != nil {
			t.Fatal(err)
		}
		cursor := model.Cursor{Group: group, Index: model.Uint64(i + 1)}
		if err = v.stores[1].FinalizeAdmission(f.ctx, scope, model.FinalizeAdmission{ReservationID: r.ID, Cursor: cursor}); err != nil {
			t.Fatal(err)
		}
		r.State, r.Cursor = "consumed", &cursor
		rows = append(rows, r)
	}
	var items []model.ChargeItem
	for _, r := range rows {
		items = append(items, model.ChargeOf(r))
	}
	candidates := []model.SettleCandidate{{Group: group, N: 0, Span: 4, Batches: 4, Charge: model.ChargeDigest(items)}}
	v.converge()
	v.mesh.calls.Store(int32(callAnswerLost))
	_, err := v.stores[2].SettleAdmissions(f.ctx, candidates)
	requireRetryableUnavailable(t, "a settlement whose answer was lost", err)
	afterFirst := v.fx[1].canonicalState()
	if got := reservationsOf(t, v.fx[1]); got != 0 {
		t.Fatalf("%d reservation rows are left after the call the leader ran", got)
	}
	v.mesh.calls.Store(int32(callWorks))
	rep, err := v.stores[2].SettleAdmissions(f.ctx, candidates)
	if err != nil || rep.Reservations != 0 {
		t.Fatalf("the sender's retry settled %+v again, %v", rep, err)
	}
	if v.fx[1].canonicalState() != afterFirst {
		t.Fatal("the retry changed the leader's books")
	}
}

func reservationsOf(t *testing.T, f *eraseFx) (n int) {
	t.Helper()
	if err := f.store.View(f.ctx, func(st control.State) error { n = len(st.Reservations); return nil }); err != nil {
		t.Fatal(err)
	}
	return n
}
