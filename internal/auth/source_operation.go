// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"soundpost/internal/model"
)

func (s *Service) SourceFenceFor(ctx context.Context, c Credential, source model.ID) (model.SourceFence, error) {
	if c.service != s || c.machine {
		return model.SourceFence{}, model.Fail(model.NotFound)
	}
	var out model.SourceFence
	err := s.store.View(ctx, func(st model.ControlState) error {
		if err := s.validateCredentialState(st, c); err != nil {
			return err
		}
		f, ok := st.SourceFences[source.String()]
		if !ok || !st.Orgs[f.Org.String()].Admins[c.user.String()] {
			return model.Fail(model.NotFound)
		}
		out = f
		return nil
	})
	return out, err
}
