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
	"strings"
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
	Source                                  string `json:",omitempty"`
}

func (s *Service) OIDCStart(ctx context.Context, cfg OIDCConfig, binding string) (string, error) {
	u, e := url.Parse(cfg.Issuer)
	redirect, redirectErr := url.Parse(cfg.RedirectURL)
	if e != nil || redirectErr != nil || redirect.Scheme != "https" || u.Scheme != "https" || cfg.ClientID == "" || binding == "" {
		return "", model.Fail(model.Invalid)
	}
	if e = s.OIDCCapacity(ctx); e != nil {
		return "", e
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
	now := s.now()
	source := oidcSource(ctx)
	st := oidcState{State: randomToken(), Nonce: randomToken(), Verifier: oauth2.GenerateVerifier(), Binding: hashToken(binding), Issuer: cfg.Issuer, Expires: now.Add(5 * time.Minute).Unix(), ClientID: cfg.ClientID, RedirectURL: cfg.RedirectURL, Org: cfg.org, Provider: cfg.provider, Source: source}
	raw, _ := json.Marshal(st)
	e = s.store.Update(ctx, func(state *model.ControlState) error {
		// The expiry instant is the leader-supplied now above; the transition
		// reads no clock, so replicas install identical state bytes.
		sweepExpiredState(state, now.Unix())
		if livePendingOIDC(*state, now.Unix()) >= pendingOIDCCap || sourceFull(*state, now.Unix(), source) {
			return errOIDCFull()
		}
		state.OIDC[hashToken(st.State)] = raw
		return nil
	})
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
	e = s.updateSession(ctx, func(st *model.ControlState) error {
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
		st.Sessions[hashToken(out.Token)] = model.ControlSession{User: user, CSRF: out.CSRF, Expires: int64(out.Expires), Reauthenticated: s.now().Unix()}
		return nil
	})
	return out, e
}

// MaxPendingOIDC bounds live (unexpired) pending login records: OIDCStart is
// reachable without a credential, so replicated state it can create is capped.
const MaxPendingOIDC = 1024

var pendingOIDCCap = MaxPendingOIDC

// MaxPendingOIDCPerSource bounds the live pending logins one client address may hold inside the
// global ceiling, so one address cannot fill MaxPendingOIDC and block everyone else. The address
// is the one the login throttle uses (WithSource: the peer, or the forwarded client address
// behind a trusted proxy); a request with no known source is bounded by the global ceiling only.
const MaxPendingOIDCPerSource = 16

var pendingOIDCSourceCap = MaxPendingOIDCPerSource

// oidcSource is the digest stored on a pending record in place of the client address.
func oidcSource(ctx context.Context) string {
	s := SourceFrom(ctx)
	if s == "" {
		return ""
	}
	return hashToken("oidc-source\x00" + s)
}

func sourceFull(st model.ControlState, now int64, source string) bool {
	if source == "" {
		return false
	}
	n := 0
	for k, raw := range st.OIDC {
		if strings.Contains(k, ":") {
			continue
		}
		var p oidcState
		if json.Unmarshal(raw, &p) == nil && p.State != "" && hashToken(p.State) == k && p.Expires > now && p.Source == source {
			n++
		}
	}
	return n >= pendingOIDCSourceCap
}

const elevationKeyPrefix = "elevation:"

func errOIDCFull() error {
	f := model.Fail(model.Unavailable)
	f.Retryable = true
	return f
}

// pendingOIDCRecord reports whether (key, raw) is a pending login record and
// its expiry. Other residents of st.OIDC (elevation records, restore stashes)
// never match: a pending record is keyed by the hash of its own State.
func pendingOIDCRecord(key string, raw json.RawMessage) (expires int64, ok bool) {
	if strings.Contains(key, ":") {
		return 0, false
	}
	var p oidcState
	if json.Unmarshal(raw, &p) != nil || p.State == "" || hashToken(p.State) != key {
		return 0, false
	}
	return p.Expires, true
}
func livePendingOIDC(st model.ControlState, now int64) (n int) {
	for k, raw := range st.OIDC {
		if exp, ok := pendingOIDCRecord(k, raw); ok && exp > now {
			n++
		}
	}
	return n
}

// expiredOIDC reports whether an st.OIDC resident is a pending login or
// elevation record whose expiry is at or before now (the same boundary the
// callback and elevation resolution refuse at).
func expiredOIDC(key string, raw json.RawMessage, now int64) bool {
	if strings.HasPrefix(key, elevationKeyPrefix) {
		var r elevationRecord
		return json.Unmarshal(raw, &r) == nil && r.Expires <= now
	}
	exp, ok := pendingOIDCRecord(key, raw)
	return ok && exp <= now
}

// sweepExpiredState deletes expired records. Audit rows are never touched and
// the result does not depend on map iteration order.
func sweepExpiredState(st *model.ControlState, now int64) (removed int) {
	for k, raw := range st.OIDC {
		if expiredOIDC(k, raw, now) {
			delete(st.OIDC, k)
			removed++
		}
	}
	return removed
}

// OIDCCapacity is a read-only check that a new login may be started. Callers on
// unauthenticated routes use it before any outbound fetch or state write.
func (s *Service) OIDCCapacity(ctx context.Context) error {
	now := s.now().Unix()
	return s.store.View(ctx, func(st model.ControlState) error {
		if livePendingOIDC(st, now) >= pendingOIDCCap || sourceFull(st, now, oidcSource(ctx)) {
			return errOIDCFull()
		}
		return nil
	})
}

// SweepExpired removes expired pending OIDC state and expired elevation records
// from replicated control state and returns how many were removed. The instant
// is read once here, on the caller (leader); the transition itself is a pure
// function of (state, instant). Run it periodically (RunFences cadence).
func (s *Service) SweepExpired(ctx context.Context) (int, error) {
	now := s.now().Unix()
	pending := false
	if err := s.store.View(ctx, func(st model.ControlState) error {
		for k, raw := range st.OIDC {
			if expiredOIDC(k, raw, now) {
				pending = true
				break
			}
		}
		return nil
	}); err != nil || !pending {
		return 0, err
	}
	removed := 0
	err := s.store.Update(ctx, func(st *model.ControlState) error {
		removed = sweepExpiredState(st, now)
		return nil
	})
	return removed, err
}
