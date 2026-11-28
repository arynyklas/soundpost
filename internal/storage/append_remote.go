// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// Appends made by the leader of their slot.
//
// An append is ordered after the one before it in its slot (the application index it names, Engine.slotMu): the member that
// takes the request reads, checks and queues it (append_queue.go) while it leads the slot. When the request enters at a member
// that does not lead the slot, that is a forwarded proposal (an HTTP request to the leader that carries the command out and the
// whole committed command back, and then the wait for the local apply), about four times the time of a commit the leader makes
// itself (measured on three voters at 1750 records/s: 176 ms against the ~40 ms of a led slot), under a lock a slot has one of:
// the requests that entered anywhere else queued behind them. The proposals of different members for the same slot also name the
// same next index, and all but one are refused as stale.
//
// A member that does not lead the slot therefore asks the leader to make the append: the batch and the claim of the request's
// scope are the whole request, the leader checks and proposes it in its own queue for the slot, and answers with the receipt;
// the member waits until it has applied the append itself, so that a read it serves afterwards sees what it acknowledged, and
// answers the client. What the leader does is Append as it always was (the claim is made a scope that every check of Append
// judges against the leader's own control state), so nothing replicated, stored or acknowledged differs: the receipt is
// acknowledged after the quorum's fsync and the apply, by the leader and by the answering member. A member makes the append
// itself (as a forwarded proposal) only when it knows no leader or the leader serves no such call (a release that does not know
// it, replica.ErrNoCall); a call that fails otherwise is answered unavailable, retryable when nothing was sent or the append is
// idempotent under a retry of the batch (replica.CallFailure), which the sender retries.

// appendCall is the name of the leader call that makes one append.
const appendCall = "append.v1"

// remoteBackoff is how long a member makes its own appends after the leader answered that it serves no such call, so that a
// leader of another release costs a request one failed hop and not one for every request.
const remoteBackoff = 10 * time.Second

// claimScopes makes the scope of a claim (auth.Service).
type claimScopes interface {
	ScopeOfClaim(auth.SourceClaim) auth.Scope
}

// BindAppendScopes installs the authority that makes the scope of a forwarded append's claim. Without it a member makes its own
// appends and refuses the calls of the others.
func (e *Engine) BindAppendScopes(scopes claimScopes) error {
	if scopes == nil || !e.scopes.CompareAndSwap(nil, &scopes) {
		return model.Fail(model.Conflict)
	}
	return nil
}

// remoteAppends counts what the calls did, for a diagnostic build's report.
var remoteAppends struct{ calls, callNS, fallbacks, served atomic.Uint64 }

type remoteAppend struct {
	Claim auth.SourceClaim      `json:"claim"`
	Batch model.NormalizedBatch `json:"batch"`
}

// appendAtLeader makes the append at the leader of the slot. handled is false when this member leads, knows no leader, or the
// leader serves no such call: the caller makes the append itself.
func (e *Engine) appendAtLeader(ctx context.Context, scope auth.Scope, b model.NormalizedBatch) (r model.Receipt, handled bool, err error) {
	if e.scopes.Load() == nil || time.Now().UnixNano() < e.remoteDownUntil.Load() {
		return r, false, nil
	}
	repl := e.repl
	if repl == nil || b.RouteSlot >= 64 || repl.groups[b.RouteSlot] == nil {
		return r, false, nil
	}
	group := repl.groups[b.RouteSlot]
	if leader, self := group.Leader(); leader == 0 || self {
		return r, false, nil
	}
	claim, ok := scope.SourceClaim()
	if !ok {
		return r, false, nil
	}
	b.Canonical = nil // the leader makes it again from the batch, and the hash it is checked against is the member's
	body, err := json.Marshal(remoteAppend{Claim: claim, Batch: b})
	if err != nil {
		return r, false, nil
	}
	remoteAppends.calls.Add(1)
	started := time.Now()
	raw, err := group.CallLeader(ctx, appendCall, body)
	remoteAppends.callNS.Add(uint64(time.Since(started)))
	switch {
	case err == nil:
		if model.StrictJSON(raw, &r) != nil {
			remoteAppends.fallbacks.Add(1)
			return model.Receipt{}, false, nil
		}
		// What this member acknowledges it can also read: it has applied the append before it answers.
		if err = group.WaitApplied(ctx, r.Cursor); err != nil {
			return model.Receipt{}, true, storageReplicaFault(err)
		}
		return r, true, nil
	case errors.Is(err, replica.ErrNoCall):
		remoteAppends.fallbacks.Add(1)
		e.remoteDownUntil.Store(time.Now().Add(remoteBackoff).UnixNano())
		return model.Receipt{}, false, nil
	case ctx.Err() != nil:
		return model.Receipt{}, true, model.Fail(model.Cancelled)
	}
	// The append is idempotent under a retry of the same batch: Append answers the receipt a stored batch already has (appendOwn,
	// storedReceipt, group.go) and writes nothing again, so a call that was sent and not answered is retryable.
	return model.Receipt{}, true, replica.CallFailure(err, true)
}

// serveAppend is the leader's handler of appendCall: Append as it always was, for the scope the claim describes.
func (e *Engine) serveAppend(ctx context.Context, _ uint64, body []byte) ([]byte, error) {
	scopes := e.scopes.Load()
	if scopes == nil {
		return nil, replica.ErrNoCall // this leader has no authority that makes the scope of a claim: the caller makes the append itself
	}
	var q remoteAppend
	if model.StrictJSON(body, &q) != nil {
		return nil, model.Fail(model.Invalid)
	}
	canonical, err := model.CanonicalJSON(q.Batch.Batch)
	if err != nil {
		return nil, model.Fail(model.Invalid)
	}
	b := q.Batch
	b.Canonical = canonical
	remoteAppends.served.Add(1)
	// The reads the append's checks make of the control state (the source, the scope, the reservation the caller just made, the
	// deletions) share one barrier, as they do for an append made by the member that took the request.
	r, err := e.appendOwn(model.WithReadShare(ctx), (*scopes).ScopeOfClaim(q.Claim), b)
	if err != nil {
		return nil, err
	}
	return json.Marshal(r)
}
