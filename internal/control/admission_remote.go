// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// Admission transitions judged by the leader.
//
// A transition is judged against the books, and the round that carries it is proposed against the revision it read
// (admission_group.go). With every voter running its own rounds, the voters that are not the leader lose that race nearly
// every time they run it (measured on three voters at 1750 records/s: 83 % and 90 % of the rounds of the two followers lost,
// 15 % of the leader's), because the state they read is a read-index round trip older than the leader's own, and a lost round
// of a follower has already carried its whole patch to the leader and been refused there: the followers' requests waited their
// full budget in the queue, the leader's alone were answered, and the link carried the patches of the rounds that were lost.
//
// A voter that is not the leader therefore asks the leader to judge the two transitions of every batch (reserve, finalize):
// the request carries what the transition needs of the request (the scope as a claim, the reservation, the owner's answer
// about a settled batch), the leader runs it in its own round beside its own and everyone else's, and answers with the
// reservation as the books left it. The patch is exactly the one the voter would have proposed, with the same ops, proposed
// by the voter that holds the current revision; nothing about what is replicated, applied or stored changes. A voter judges
// the transition itself only when the leader serves no such call (a release that does not know it, replica.ErrNoCall), as it
// always did: the transitions are idempotent by their keys. A call that fails otherwise (a failed hop, a leader that is busy, a
// leader that changed) is answered to the caller as unavailable, which its sender retries: a voter that judged it itself would
// lose the round at the leader nearly every time, and carry the whole patch there to be refused.
//
// A failed call is answered by what is known of it (replica.CallFailure). Nothing sent (no leader known, refused, unreachable, or the
// member answered that it does not lead): retryable unavailable, which the HTTP layer answers 503 with a Retry-After of 1 to 3
// seconds. The request sent and no answer back (the leader may have committed it): retryable only because every call below is
// idempotent under a retry with the same key: a reserve finds the reservation of its key (reserveStep, quota.go: reservationKey
// names organization, project, source, producer, slot and batch) and answers it without charging again; a finalize finds the
// reservation consumed at the same cursor and changes nothing (finalizeStep, quota.go), or already folded into a settled window; a
// settlement finds its rows gone and commits nothing (SettleAdmissions: settleRowsHeld, errNothingToSettle, settle.go). The claim
// is checked afresh by each run against the leader's own state. A leader's own fault keeps its code and its retryable bit
// (replica callResult). A call added here that is not idempotent passes false to callLeaderRaw, and its sender is told only that
// the outcome is unknown.

// admitCall is the name of the leader call that judges one admission transition.
const admitCall = "admission.v1"

// remoteBackoff is how long a voter judges its own transitions after the leader answered that it serves no such call, so that
// a leader of another release costs a request one failed hop and not one for every request.
const remoteBackoff = 10 * time.Second

// claimScopes makes the scope of a claim (auth.Service).
type claimScopes interface {
	ScopeOfClaim(auth.SourceClaim) auth.Scope
}

// BindAdmissionScopes installs the authority that makes the scope of a forwarded transition's claim. Without it a voter judges
// its own transitions and refuses the calls of the others.
func (s *Store) BindAdmissionScopes(scopes claimScopes) error {
	if scopes == nil || !s.scopes.CompareAndSwap(nil, &scopes) {
		return model.Fail(model.Conflict)
	}
	return nil
}

type remoteReserve struct {
	Reservation    model.AdmissionReservation `json:"reservation"`
	PolicyRevision model.Revision             `json:"policy_revision"`
	Looked         bool                       `json:"looked,omitempty"`
	Admitted       *model.Receipt             `json:"admitted,omitempty"`
}

// remoteAdmission is one transition a voter asks the leader to judge.
type remoteAdmission struct {
	Claim    auth.SourceClaim         `json:"claim"`
	Reserve  *remoteReserve           `json:"reserve,omitempty"`
	Finalize *model.FinalizeAdmission `json:"finalize,omitempty"`
}

// remoteAnswer is the leader's answer: the reservation as the books left it (a reserve), or that the owner has to be asked about
// the batch first (errNeedsAdmittedLookup); a finalization is answered with neither. The reservation is a pointer so that an answer
// without one is not written with a zero reservation, which does not encode (its identifiers refuse to be written as zero): that
// made every finalization a follower handed to the leader fail to be answered after it had committed.
type remoteAnswer struct {
	Reservation *model.AdmissionReservation `json:"reservation,omitempty"`
	NeedsLookup bool                        `json:"needs_lookup,omitempty"`
}

// callLeader asks the leader to judge q. handled is false when there is no leader to ask or it serves no such call: the caller
// judges the transition itself. Every other outcome is handled: the leader's answer, its refusal, or unavailable.
func (s *Store) callLeader(ctx context.Context, scope auth.Scope, q remoteAdmission) (a remoteAnswer, handled bool, err error) {
	if s.scopes.Load() == nil || !s.leaderCallable() {
		return a, false, nil
	}
	claim, ok := scope.SourceClaim()
	if !ok {
		return a, false, nil
	}
	q.Claim = claim
	body, e := json.Marshal(q)
	if e != nil {
		return a, false, nil
	}
	raw, handled, err := s.callLeaderRaw(ctx, admitCall, body, true)
	if !handled || err != nil {
		return a, handled, err
	}
	if model.StrictJSON(raw, &a) != nil {
		s.remoteFallbacks.Add(1)
		return a, false, nil
	}
	return a, true, nil
}

// leaderCallable is whether this voter has a leader to hand a transition to: replication is on, the installation applies ledger
// commands, the leader did not answer lately that it serves no such call, and another voter leads.
func (s *Store) leaderCallable() bool {
	if s.repl == nil || time.Now().UnixNano() < s.remoteDownUntil.Load() || !s.layoutLedger.Load() || !s.StatePatch() {
		return false
	}
	leader, self := s.repl.group.Leader()
	return leader != 0 && !self
}

// callLeaderRaw is a leader call by name: the voter that is not the leader hands body to the leader's handler of name. handled is
// false when there is no leader to ask (see leaderCallable) or the leader serves no such call (a release that does not know it:
// replica.ErrNoCall, remembered for remoteBackoff). idempotent says whether a retry with the same key finds what a first run
// committed and commits nothing more: a call that failed after the request was sent is then answered retryable (every call below is,
// see the file comment); one that is not keeps its outcome ambiguous, answered unavailable and not retryable.
func (s *Store) callLeaderRaw(ctx context.Context, name string, body []byte, idempotent bool) (raw []byte, handled bool, err error) {
	if !s.leaderCallable() {
		return nil, false, nil
	}
	s.remoteCalls.Add(1)
	started := time.Now()
	raw, e := s.repl.group.CallLeader(ctx, name, body)
	s.remoteCallNS.Add(uint64(time.Since(started)))
	switch {
	case e == nil:
		return raw, true, nil
	case errors.Is(e, replica.ErrNoCall):
		s.remoteFallbacks.Add(1)
		s.remoteDownUntil.Store(time.Now().Add(remoteBackoff).UnixNano())
		return nil, false, nil
	case ctx.Err() != nil:
		noteFailure("call.ctx", ctx.Err())
		return nil, true, ctx.Err()
	}
	noteFailure("call", e)
	return nil, true, replica.CallFailure(e, idempotent) // the leader's refusal as it answered it, or unavailable
}

// reserveAtLeader judges the reservation of a batch at the leader (ReserveAdmission).
func (s *Store) reserveAtLeader(ctx context.Context, scope auth.Scope, b model.NormalizedBatch, r *model.AdmissionReservation, looked bool, admitted *model.Receipt) (handled bool, err error) {
	a, handled, err := s.callLeader(ctx, scope, remoteAdmission{Reserve: &remoteReserve{Reservation: *r, PolicyRevision: b.PolicyRevision, Looked: looked, Admitted: admitted}})
	if !handled || err != nil {
		return handled, err
	}
	if a.NeedsLookup {
		return true, errNeedsAdmittedLookup
	}
	if a.Reservation == nil {
		return true, replica.CallFailure(replica.ErrCallOutcomeUnknown, true) // a reserve is answered with the reservation as the books left it; a retry finds it by its key
	}
	*r = *a.Reservation
	return true, nil
}

// finalizeAtLeader judges the finalization of a reservation at the leader (FinalizeAdmission).
func (s *Store) finalizeAtLeader(ctx context.Context, scope auth.Scope, r FinalizeAdmission) (handled bool, err error) {
	_, handled, err = s.callLeader(ctx, scope, remoteAdmission{Finalize: &r})
	return handled, err
}

// serveAdmission is the leader's handler of admitCall: it judges the transition in its own admission round.
func (s *Store) serveAdmission(ctx context.Context, _ uint64, body []byte) ([]byte, error) {
	scopes := s.scopes.Load()
	if scopes == nil {
		return nil, replica.ErrNoCall // this leader has no authority that makes the scope of a claim: the caller judges the transition itself
	}
	if s.repl == nil {
		return nil, model.Fail(model.Unavailable)
	}
	var q remoteAdmission
	if model.StrictJSON(body, &q) != nil || (q.Reserve == nil) == (q.Finalize == nil) {
		return nil, model.Fail(model.Invalid)
	}
	scope := (*scopes).ScopeOfClaim(q.Claim)
	s.remoteServed.Add(1)
	if q.Finalize != nil {
		err := s.admissionUpdate(ctx, writerFinalizeAdmission, func(core *State, books admissionBooks) error {
			if e := auth.ValidateSourceClaim(*core, q.Claim); e != nil {
				return e
			}
			return finalizeStep(core, books, scope, *q.Finalize)
		})
		if err != nil {
			noteFailure("serve.finalize", err)
			return nil, err
		}
		return json.Marshal(remoteAnswer{})
	}
	r := q.Reserve.Reservation
	b := model.NormalizedBatch{}
	b.PolicyRevision = q.Reserve.PolicyRevision
	err := s.admissionUpdate(ctx, writerReserveAdmission, func(core *State, books admissionBooks) error {
		if e := auth.ValidateSourceClaim(*core, q.Claim); e != nil {
			return e
		}
		return reserveStep(core, books, scope, &r, b, q.Reserve.Looked, q.Reserve.Admitted)
	})
	if errors.Is(err, errNeedsAdmittedLookup) {
		return json.Marshal(remoteAnswer{NeedsLookup: true})
	}
	if err != nil {
		noteFailure("serve.reserve", err)
		return nil, err
	}
	return json.Marshal(remoteAnswer{Reservation: &r})
}

// settleCall is the name of the leader call that settles the windows the storage engine of a voter offers.
const settleCall = "settle.v1"

// settleAtLeader hands the windows a voter's storage offered to the leader (SettleAdmissions). Settlement is a command of its own
// (up to 64 reservation rows dropped, their charge folded into the settlement: 355 KB of patch at 5,000 records/s) that every voter
// ran for the windows its storage engine offered, from the revision it read: the voters that were not the leader lost that race
// nearly every time (78 % of the rounds of the two followers at 5,000 records/s, one item and 355 KB each), and a commit of theirs
// that did win moved the revision under the leader's round in flight, which was then lost (a third of the leader's rounds). The
// leader settles them in its own rounds, against its own books: the candidates are the data's statement of what its windows
// contain, which the leader proves against the rows it holds, exactly as a voter that settled them itself would.
func (s *Store) settleAtLeader(ctx context.Context, candidates []model.SettleCandidate) (rep SettleReport, handled bool, err error) {
	body, e := json.Marshal(candidates)
	if e != nil {
		return rep, false, nil
	}
	raw, handled, err := s.callLeaderRaw(ctx, settleCall, body, true)
	if !handled || err != nil {
		return rep, handled, err
	}
	if model.StrictJSON(raw, &rep) != nil {
		return rep, true, replica.CallFailure(replica.ErrCallOutcomeUnknown, true) // the leader ran it: a retry finds the rows settled (settle.go, settleRowsHeld)
	}
	return rep, true, nil
}

// serveSettle is the leader's handler of settleCall: it settles the windows in its own rounds.
func (s *Store) serveSettle(ctx context.Context, _ uint64, body []byte) ([]byte, error) {
	if s.repl == nil {
		return nil, model.Fail(model.Unavailable)
	}
	var candidates []model.SettleCandidate
	if model.StrictJSON(body, &candidates) != nil || len(candidates) == 0 {
		return nil, model.Fail(model.Invalid)
	}
	rep, err := s.SettleAdmissions(ctx, candidates)
	if err != nil {
		noteFailure("serve.settle", err)
		return nil, err
	}
	return json.Marshal(rep)
}
