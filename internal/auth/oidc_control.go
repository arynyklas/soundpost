// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/model"
)

// ConfiguredOIDC selects one explicitly administered provider in one organization.
// The provider ID is public routing metadata, not an authorization grant.
func (s *Service) ConfiguredOIDC(ctx context.Context, org, provider model.ID) (OIDCConfig, error) {
	var cfg OIDCConfig
	err := s.store.View(ctx, func(st model.ControlState) error {
		o, ok := st.Orgs[org.String()]
		if !ok {
			return model.Fail(model.Unauthenticated)
		}
		raw, ok := o.Settings["sso:"+provider.String()]
		if !ok {
			return model.Fail(model.Unauthenticated)
		}
		if e := json.Unmarshal(raw, &cfg); e != nil {
			return model.Fail(model.Corrupt)
		}
		if sealed := o.Secrets["sso:"+provider.String()]; sealed != "" {
			secret, e := s.store.OpenSecret(sealed)
			if e != nil {
				return model.Fail(model.Unavailable)
			}
			cfg.ClientSecret = secret
		}
		cfg.org = org.String()
		cfg.provider = provider.String()
		return nil
	})
	return cfg, err
}
func (s *Service) OIDCConfigForState(ctx context.Context, state string) (OIDCConfig, error) {
	var pending oidcState
	if err := s.store.View(ctx, func(st model.ControlState) error {
		if err := json.Unmarshal(st.OIDC[hashToken(state)], &pending); err != nil {
			return model.Fail(model.Unauthenticated)
		}
		return nil
	}); err != nil {
		return OIDCConfig{}, err
	}
	org, err := model.ParseID(pending.Org)
	if err != nil {
		return OIDCConfig{}, model.Fail(model.Unauthenticated)
	}
	provider, err := model.ParseID(pending.Provider)
	if err != nil {
		return OIDCConfig{}, model.Fail(model.Unauthenticated)
	}
	cfg, err := s.ConfiguredOIDC(ctx, org, provider)
	if err != nil {
		return OIDCConfig{}, err
	}
	if cfg.Issuer != pending.Issuer || cfg.ClientID != pending.ClientID || cfg.RedirectURL != pending.RedirectURL {
		return OIDCConfig{}, model.Fail(model.Unauthenticated)
	}
	return cfg, nil
}
