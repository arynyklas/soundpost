// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"net/url"
	"soundpost/internal/model"
	"time"
)

type OIDCConfig struct {
	Issuer, ClientID, ClientSecret, RedirectURL string
	Subjects                                    map[string]model.ID
	org, provider                               string
}
type oidcState struct {
	State, Nonce, Verifier, Binding, Issuer string
	Expires                                 int64
	ClientID, RedirectURL, Org, Provider    string
}

func (s *Service) OIDCStart(ctx context.Context, cfg OIDCConfig, binding string) (string, error) {
	u, e := url.Parse(cfg.Issuer)
	redirect, redirectErr := url.Parse(cfg.RedirectURL)
	if e != nil || redirectErr != nil || redirect.Scheme != "https" || u.Scheme != "https" || cfg.ClientID == "" || binding == "" {
		return "", model.Fail(model.Invalid)
	}
	provider, e := oidc.NewProvider(ctx, cfg.Issuer)
	if e != nil {
		return "", model.Fail(model.Unavailable)
	}
	for _, endpoint := range []string{provider.Endpoint().AuthURL, provider.Endpoint().TokenURL} {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" {
			return "", model.Fail(model.Invalid)
		}
	}
	st := oidcState{State: randomToken(), Nonce: randomToken(), Verifier: oauth2.GenerateVerifier(), Binding: hashToken(binding), Issuer: cfg.Issuer, Expires: s.now().Add(5 * time.Minute).Unix(), ClientID: cfg.ClientID, RedirectURL: cfg.RedirectURL, Org: cfg.org, Provider: cfg.provider}
	raw, _ := json.Marshal(st)
	e = s.store.Update(ctx, func(state *model.ControlState) error { state.OIDC[hashToken(st.State)] = raw; return nil })
	if e != nil {
		return "", e
	}
	conf := oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Endpoint: provider.Endpoint(), RedirectURL: cfg.RedirectURL, Scopes: []string{oidc.ScopeOpenID}}
	return conf.AuthCodeURL(st.State, oauth2.S256ChallengeOption(st.Verifier), oidc.Nonce(st.Nonce)), nil
}
func (s *Service) OIDCCallback(ctx context.Context, cfg OIDCConfig, binding, state, code string) (Session, error) {
	var pending oidcState
	e := s.store.Update(ctx, func(st *model.ControlState) error {
		raw, ok := st.OIDC[hashToken(state)]
		if !ok {
			return model.Fail(model.Unauthenticated)
		}
		delete(st.OIDC, hashToken(state))
		if e := json.Unmarshal(raw, &pending); e != nil {
			return model.Fail(model.Corrupt)
		}
		return nil
	})
	if e != nil {
		return Session{}, e
	}
	if pending.Expires <= s.now().Unix() || pending.Issuer != cfg.Issuer || pending.ClientID != cfg.ClientID || pending.RedirectURL != cfg.RedirectURL || pending.Org != cfg.org || pending.Provider != cfg.provider || subtle.ConstantTimeCompare([]byte(pending.Binding), []byte(hashToken(binding))) != 1 {
		return Session{}, model.Fail(model.Unauthenticated)
	}
	provider, e := oidc.NewProvider(ctx, cfg.Issuer)
	if e != nil {
		return Session{}, model.Fail(model.Unavailable)
	}
	endpoint, endpointErr := url.Parse(provider.Endpoint().TokenURL)
	if endpointErr != nil || endpoint.Scheme != "https" {
		return Session{}, model.Fail(model.Invalid)
	}
	conf := oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Endpoint: provider.Endpoint(), RedirectURL: cfg.RedirectURL}
	tok, e := conf.Exchange(ctx, code, oauth2.VerifierOption(pending.Verifier))
	if e != nil {
		return Session{}, model.Fail(model.Unauthenticated)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		return Session{}, model.Fail(model.Unauthenticated)
	}
	id, e := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, raw)
	if e != nil || id.Nonce != pending.Nonce {
		return Session{}, model.Fail(model.Unauthenticated)
	}
	user, ok := cfg.Subjects[id.Subject]
	if !ok {
		return Session{}, model.Fail(model.Forbidden)
	}
	out := s.newSession(user)
	e = s.store.Update(ctx, func(st *model.ControlState) error {
		u, ok := st.Users[user.String()]
		if !ok || u.Disabled {
			return model.Fail(model.Forbidden)
		}
		if cfg.org != "" {
			org, exists := st.Orgs[cfg.org]
			if !exists || !org.Members[user.String()] && !org.Admins[user.String()] {
				return model.Fail(model.Forbidden)
			}
			var current OIDCConfig
			if err := json.Unmarshal(org.Settings["sso:"+cfg.provider], &current); err != nil || current.Subjects[id.Subject] != user || current.Issuer != cfg.Issuer || current.ClientID != cfg.ClientID {
				return model.Fail(model.Forbidden)
			}
		}
		st.Sessions[hashToken(out.Token)] = model.ControlSession{User: user, CSRF: out.CSRF, Expires: out.Expires, Reauthenticated: s.now().Unix()}
		return nil
	})
	return out, e
}
