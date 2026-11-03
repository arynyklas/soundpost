// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"encoding/json"
	"soundpost/internal/model"
)

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
		scope.sources = []model.ID{source}
		return nil
	})
	if e != nil {
		return Scope{}, e
	}
	return scope, nil
}

// RenewLease fences revocations before a long computation receives another
// bounded lease. Revalidate must additionally precede every response/chunk.
func (s *Service) RenewLease(ctx context.Context, scope Scope) (Scope, error) {
	if e := s.Revalidate(ctx, scope); e != nil {
		return Scope{}, e
	}
	return scope, nil
}
