// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"soundpost/internal/model"
)

func (s *Service) validateCredentialState(st model.ControlState, c Credential) error {
	if c.service != s {
		return model.Fail(model.Unauthenticated)
	}
	if c.machine {
		token, ok := st.ServerTokens[s.serverTokenDigest(c.token)]
		user, exists := st.Users[c.user.String()]
		if !ok || !exists || token.Principal != c.user || user.Disabled || token.Revoked || token.Expires <= s.now().Unix() {
			return model.Fail(model.Unauthenticated)
		}
		return nil
	}
	session, ok := st.Sessions[hashToken(c.token)]
	user, exists := st.Users[c.user.String()]
	if !ok || !exists || session.User != c.user || session.Expires <= s.now().Unix() || user.Disabled {
		return model.Fail(model.Unauthenticated)
	}
	return nil
}

// ValidateControlState is invoked inside the authority's write transaction so a
// revocation ordered before that transaction cannot race an earlier read check.
func (scope Scope) ValidateControlState(st model.ControlState) error {
	if scope.service == nil {
		return model.Fail(model.Forbidden)
	}
	if err := scope.service.validateCredentialState(st, scope.credential); err != nil {
		return err
	}
	org, ok := st.Orgs[scope.org.String()]
	if !ok || org.Epoch != scope.epoch {
		return model.Fail(model.NotFound)
	}
	if !tokenAllows(st, scope.credential, scope.org, scope.projects, scope.action) {
		return model.Fail(model.NotFound)
	}
	if scope.elevation != (model.ID{}) && !scope.service.now().Before(scope.elevationExpires) {
		return model.Fail(model.Forbidden)
	}
	return nil
}
