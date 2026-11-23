// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"github.com/arynyklas/soundpost/internal/model"
)

func (s *Service) validateCredentialState(st model.ControlState, c Credential) error {
	return s.validateCredentialStateRO(model.ReadOnlyOf(&st), c)
}

// validateCredentialStateRO is validateCredentialState over the read-only view, which the shared
// reads (Revalidate, AuthorizeSystem) hand out.
func (s *Service) validateCredentialStateRO(st model.ReadOnlyControl, c Credential) error {
	if c.service != s {
		return model.Fail(model.Unauthenticated)
	}
	if c.system {
		// The runner's credential has no token, session or user record: it is valid
		// only as the system principal; the organization checks are the scope's.
		if !IsSystemPrincipal(c.user) || c.token != "" || c.machine {
			return model.Fail(model.Unauthenticated)
		}
		return nil
	}
	if IsSystemPrincipal(c.user) {
		// No session or token principal may carry a system principal ID.
		return model.Fail(model.Unauthenticated)
	}
	exists, disabled := st.UserState(c.user.String())
	if c.machine {
		token, ok := st.ServerToken(s.serverTokenDigest(c.token))
		if !ok || !exists || token.Principal != c.user || disabled || token.Revoked || token.Expires <= s.now().Unix() {
			return model.Fail(model.Unauthenticated)
		}
		return nil
	}
	session, ok := st.Session(hashToken(c.token))
	if !ok || !exists || session.User != c.user || session.Expires <= s.now().Unix() || disabled {
		return model.Fail(model.Unauthenticated)
	}
	return nil
}

// ValidateControlState is invoked inside the authority's write transaction so a
// revocation ordered before that transaction cannot race an earlier read check.
func (scope Scope) ValidateControlState(st model.ControlState) error {
	if scope.sourceCredential != nil {
		if len(scope.projects) != 1 || len(scope.sources) != 1 {
			return model.Fail(model.Forbidden)
		}
		return scope.ValidateSourceState(st, scope.projects[0], scope.sources[0], !scope.historical)
	}
	return scope.ValidateControlStateRO(model.ReadOnlyOf(&st))
}

// ValidateControlStateRO is ValidateControlState over the read-only view of the control state, for
// a reader of the shared decode. A source scope is not validated here (the source tables are not
// part of the view) but refused with Forbidden, which is what ValidateSourceState answers for every
// action but Ingest; a reader that calls this has refused such a scope by its permission first.
func (scope Scope) ValidateControlStateRO(st model.ReadOnlyControl) error {
	if scope.sourceCredential != nil || scope.service == nil {
		return model.Fail(model.Forbidden)
	}
	if scope.credential.system {
		return scope.service.validateSystemStateRO(st, scope)
	}
	if err := scope.service.validateCredentialStateRO(st, scope.credential); err != nil {
		return err
	}
	epoch, ok := st.OrgEpoch(scope.org.String())
	if !ok || epoch != scope.epoch {
		return model.Fail(model.NotFound)
	}
	if !tokenAllowsRO(st, scope.credential, scope.org, scope.projects, scope.tokenAction()) {
		return model.Fail(model.NotFound)
	}
	if scope.elevation != (model.ID{}) && !scope.service.now().Before(scope.elevationExpires) {
		return model.Fail(model.Forbidden)
	}
	if !scope.expiresAt.IsZero() && !scope.service.now().Before(scope.expiresAt) {
		return model.Fail(model.NotFound)
	}
	return nil
}
