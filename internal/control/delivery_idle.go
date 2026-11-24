// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// DeliveryClaimIdle reports whether committing the claim c under lease would change nothing in the control state but the record that the command
// ran. The notification runner claims once per project on every pass, and almost every claim leases, settles and prunes nothing; a commit that
// changes nothing still spends a control revision (every client command that names the global revision, create_org and create_user among them,
// is then refused as a conflict), stores a command record that pushes a real command out of the bounded dedup window, and costs a replicated
// round. The same rule as the replayed command (Transact answers it from a read) and the expiry of the control log (it commits nothing when
// nothing is due): a transition that would change nothing is not proposed, and the read that proved it is the linearization point of the empty
// answer.
//
// It answers true only when the handler is certain to leave the state as it is:
//   - the scope passes the handler's own checks against st (ValidateControlState, the organization-administrator permission, the project): a scope
//     the handler would refuse is never idle, so the commit reports the fault;
//   - the project outbox's fence already equals lease (the first claim of a new leader term commits, because the committed fence it raises is
//     what makes a deposed leader's later commit stale);
//   - the claim names the committed cutover revision (a stale one commits, so the handler refuses it);
//   - no open delivery is leased, settled, exhausted or lapsed by it (claimStepOf is the handler's own decision);
//   - no completed deletion that covers the project still has something to erase, and the settled history is within its bound.
//
// st must be a decode of the caller's own (Store.View, never the shared one): the late-erasure check runs the erasure on it. The notification
// runner uses Store.ClaimIdle, which reads the shared decode and takes a decode of its own only for a project that a finished deletion covers.
func DeliveryClaimIdle(scope auth.Scope, st State, lease replica.FenceToken, c DeliveryClaim) bool {
	return claimIdleBeforeLateEffects(scope, &st, lease, c) && !lateEffectPending(&st, scope.OrgID(), c.Project)
}

// ClaimIdle is DeliveryClaimIdle for the runner's claim pass: it reads the control state through the decode every shared reader uses and returns
// the claim with OwnerRevision set to the cutover revision of the same read, and whether committing it would change nothing. No decode of the
// whole state is made for it unless a finished deletion covers the project: only then does the late-erasure check need a state it may run the
// erasure on, and that one is read through View.
func (s *Store) ClaimIdle(ctx context.Context, scope auth.Scope, lease replica.FenceToken, c DeliveryClaim) (DeliveryClaim, bool, error) {
	org := scope.OrgID()
	var passes, needsErasureCheck bool
	if err := s.ViewCore(ctx, func(st State) error {
		c.OwnerRevision = CutoverRevision(st, org, c.Project)
		passes = claimIdleBeforeLateEffects(scope, &st, lease, c)
		needsErasureCheck = passes && finishedDeletionCovers(&st, org, c.Project)
		return nil
	}); err != nil {
		return c, false, err
	}
	if !needsErasureCheck {
		return c, passes, nil
	}
	idle := false
	err := s.View(ctx, func(st State) error {
		c.OwnerRevision = CutoverRevision(st, org, c.Project)
		idle = DeliveryClaimIdle(scope, st, lease, c)
		return nil
	})
	return c, idle, err
}

// finishedDeletionCovers reports whether a deletion that is complete or failed covers the project: the only state in which lateEffectPending can
// answer true.
func finishedDeletionCovers(st *State, org, project model.ID) bool {
	for _, op := range st.Deletions {
		if (op.Phase == model.DeletePhaseComplete || op.Phase == model.DeletePhaseFailed) && op.Predicate.CoversProject(org, project) {
			return true
		}
	}
	return false
}

// claimIdleBeforeLateEffects is every check of DeliveryClaimIdle but the late-erasure one. It only reads st.
func claimIdleBeforeLateEffects(scope auth.Scope, st *State, lease replica.FenceToken, c DeliveryClaim) bool {
	if scope.ValidateControlState(*st) != nil {
		return false
	}
	org := scope.OrgID()
	if projectAdminScope(scope, st, org, c.Project) != nil {
		return false
	}
	if c.Now <= 0 || c.Expires <= c.Now || c.Expires-c.Now > DeliveryMaxClaimTTL || c.Limit == 0 || c.Limit > maxDeliveryClaimLimit {
		return false
	}
	if lease.Group != st.Installation || lease.Term == 0 {
		return false
	}
	if cur, ok, err := loadDeliveryFence(st, org, c.Project); err != nil || !ok || cur != lease {
		return false
	}
	gate, err := cutoverGateOf(st, org, c.Project)
	if err != nil || c.OwnerRevision != gate.revision {
		return false
	}
	recs, err := projectDeliveries(st, org, c.Project)
	if err != nil {
		return false
	}
	settled := 0
	for i := range recs {
		r := &recs[i]
		if !r.Open() {
			settled++
			continue
		}
		if gate.block != "" {
			continue // not the active owner: nothing is leased or settled
		}
		if r.Phase == DeliveryClaimed {
			if len(r.Attempts) == 0 || c.Now >= r.Attempts[len(r.Attempts)-1].Expires {
				return false // a lapsed claim is closed as unknown by the next claim
			}
			continue // a live claim
		}
		if _, step := claimStepOf(st, gate, r, c); step != claimKeep {
			return false
		}
	}
	return settled <= maxSettledDeliveries
}

// lateEffectPending reports whether eraseLateEffect would change st for the project: some finished deletion that covers it still has a payload to
// drop or an over-erasure to record. It runs the erasure on st itself, so st is changed.
func lateEffectPending(st *State, org, project model.ID) bool {
	for _, op := range st.Deletions {
		if op.Phase != model.DeletePhaseComplete && op.Phase != model.DeletePhaseFailed || !op.Predicate.CoversProject(org, project) {
			continue
		}
		audits := len(st.Audits)
		recorded, err := eraseControlPayloadsBy(st, &op, op.CompletedAt, stateErasedLate)
		if err != nil || recorded || len(st.Audits) != audits {
			return true
		}
	}
	return false
}
