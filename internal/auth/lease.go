// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"github.com/arynyklas/soundpost/internal/model"
	"sync"
	"time"
)

// Copies of an opaque Scope share this auth-owned state. Only a successful
// authoritative read refreshes it; callers do not reconstruct scopes to renew.
type scopeLease struct {
	mu       sync.RWMutex
	deadline time.Time
}

func (scope Scope) LeaseDeadline() time.Time {
	if scope.lease == nil {
		return time.Time{}
	}
	scope.lease.mu.RLock()
	defer scope.lease.mu.RUnlock()
	return scope.lease.deadline
}

func (s *Service) grantLease(scope Scope, st model.ControlState, checkedAt time.Time) error {
	return s.grantLeaseRO(scope, model.ReadOnlyOf(&st), checkedAt)
}

// grantLeaseRO is grantLease over the read-only view of the control state.
//
// grantLease runs before initial scope publication, or while Revalidate holds
// the lease lock. Start at the authority-read boundary, not after a slow read.
func (s *Service) grantLeaseRO(scope Scope, st model.ReadOnlyControl, checkedAt time.Time) error {
	deadline := checkedAt.Add(5 * time.Second)
	if !scope.credential.system {
		session, _ := st.Session(hashToken(scope.credential.token))
		credentialExpiry := session.Expires
		if scope.credential.machine {
			token, _ := st.ServerToken(s.serverTokenDigest(scope.credential.token))
			credentialExpiry = token.Expires
		}
		if credentialExpiry <= deadline.Unix() {
			deadline = checkedAt.Add(time.Unix(credentialExpiry, 0).Sub(checkedAt))
		}
	}
	if scope.elevation != (model.ID{}) && scope.elevationExpires.Before(deadline) {
		deadline = checkedAt.Add(scope.elevationExpires.Sub(checkedAt))
	}
	if !scope.expiresAt.IsZero() && scope.expiresAt.Before(deadline) {
		deadline = checkedAt.Add(scope.expiresAt.Sub(checkedAt))
	}
	if !s.now().Before(deadline) {
		return model.Fail(model.Stale)
	}
	scope.lease.deadline = deadline
	return nil
}
