// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"encoding/json"
	"soundpost/internal/model"
	"time"
)

// AuthorizeRestrictedSource derives the one scope that may read a single named
// restricted-raw source. Raw read eligibility ends when the source policy's
// expiration or the source's own lifetime passes: an expired source is the same
// NotFound as a guessed one, and the scope carries that instant (ExpiresAt) so
// revalidation, leases, caches, tickets and export grants all end with it.
func (s *Service) AuthorizeRestrictedSource(ctx context.Context, c Credential, org, project, source model.ID) (Scope, error) {
	scope, e := s.Authorize(ctx, c, org, []model.ID{project}, RawRead)
	if e != nil {
		return Scope{}, e
	}
	e = s.store.View(ctx, func(st model.ControlState) error {
		if err := s.validateCredentialState(st, c); err != nil {
			return err
		}
		o := st.Orgs[org.String()]
		if o.Epoch != scope.epoch {
			return model.Fail(model.NotFound)
		}
		var policy SourcePolicyConfig
		if e := json.Unmarshal(o.Settings["source_policy:"+source.String()], &policy); e != nil {
			return model.Fail(model.NotFound)
		}
		if !policy.Enabled || policy.ProjectID != project || !hasID(policy.Readers, c.user) {
			return model.Fail(model.NotFound)
		}
		// A source with no authority record carries no clock window (no data can
		// exist for it); one that does is readable only inside its window.
		if src, onboarded := st.Sources[source.String()]; onboarded {
			end, alive := rawWindowEnd(src, s.now())
			if !alive {
				return model.Fail(model.NotFound)
			}
			scope.expiresAt = end
			scope.lease.mu.Lock()
			if end.Before(scope.lease.deadline) {
				scope.lease.deadline = end
			}
			scope.lease.mu.Unlock()
		}
		scope.sources = []model.ID{source}
		scope.fingerprint = hashToken(scope.fingerprint + "|selected_source:" + source.String())
		return nil
	})
	if e != nil {
		return Scope{}, e
	}
	return scope, nil
}

// rawWindowEnd is the instant a restricted-raw source stops being readable: the
// earlier of its policy expiration (when set) and its own lifetime. alive is
// false once that instant has passed.
func rawWindowEnd(src model.SourceAuthority, now time.Time) (end time.Time, alive bool) {
	end = time.Unix(0, int64(src.Expires))
	if src.Policy.Expires != 0 {
		if policyEnd := time.Unix(0, int64(src.Policy.Expires)); policyEnd.Before(end) {
			end = policyEnd
		}
	}
	return end, now.Before(end)
}

// RenewLease fences revocations before a long computation receives another
// bounded lease. Revalidate must additionally precede every response/chunk.
func (s *Service) RenewLease(ctx context.Context, scope Scope) (Scope, error) {
	if e := s.Revalidate(ctx, scope); e != nil {
		return Scope{}, e
	}
	return scope, nil
}
