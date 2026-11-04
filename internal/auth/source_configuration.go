// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"soundpost/internal/model"
)

func (s *Service) AllowsBrowserOrigin(ctx context.Context, origin string) bool {
	if origin == "" {
		return false
	}
	allowed := false
	s.store.View(ctx, func(st model.ControlState) error {
		for _, src := range st.Sources {
			if !src.Browser || src.Revoked || src.Retired || int64(src.Expires) <= s.now().UnixNano() {
				continue
			}
			for _, v := range src.Origins {
				if v == origin {
					allowed = true
				}
			}
		}
		return nil
	})
	return allowed
}

// canonicalSourcePolicyPayload is the sole capability vocabulary for both new
// onboarding and refresh. Authorization is read by SourceConfiguration; kinds
// never imply another permission, and absent/unknown kinds remain disabled.
func canonicalSourcePolicyPayload(src model.SourceAuthority, admissionAllowed bool) ([]byte, error) {
	payload := struct {
		Version  uint16         `json:"version"`
		Org      model.ID       `json:"org"`
		Project  model.ID       `json:"project"`
		Source   model.ID       `json:"source"`
		Revision model.Revision `json:"revision"`
		Expires  model.UnixNano `json:"expires_ns"`
		Errors   bool           `json:"errors"`
		Logs     bool           `json:"logs"`
		Traces   bool           `json:"traces"`
		Jobs     bool           `json:"jobs"`
		Loss     bool           `json:"loss"`
		Replay   bool           `json:"replay"`
		Bodies   bool           `json:"bodies"`
	}{Version: 1, Org: src.Org, Project: src.Project, Source: src.ID, Revision: src.Policy.Revision, Expires: src.Expires}
	if src.Policy.Expires != 0 && src.Policy.Expires < payload.Expires {
		payload.Expires = src.Policy.Expires
	}
	if admissionAllowed && src.Policy.Enabled && !src.Closing && !src.Revoked && !src.Retired {
		for _, kind := range src.Policy.Kinds {
			switch kind {
			case model.ErrorKind:
				payload.Errors = true
			case model.Log:
				payload.Logs = true
			case model.SpanKind:
				payload.Traces = true
			case model.JobAttempt:
				payload.Jobs = true
			case model.Loss:
				payload.Loss = true
			case model.Replay:
				payload.Replay = src.Policy.Replay
			}
		}
	}
	// Bodies is always false, including explicitly restricted source classes.
	return model.CanonicalJSON(payload)
}
func (s *Service) SourceConfiguration(ctx context.Context, c SourceCredential) (SourceOnboarded, error) {
	var src model.SourceAuthority
	var sealed string
	var epoch uint64
	var admissionAllowed bool
	e := s.store.View(ctx, func(st model.ControlState) error {
		if err := s.checkSource(st, c, false); err != nil {
			return err
		}
		src = st.Sources[c.source.String()]
		sealed = st.PolicySigningKey
		epoch = st.Orgs[src.Org.String()].Epoch
		admissionAllowed = s.checkSource(st, c, true) == nil
		return nil
	})
	if e != nil {
		return SourceOnboarded{}, e
	}
	secret, e := s.store.OpenSecret(sealed)
	if e != nil {
		return SourceOnboarded{}, model.Fail(model.Unavailable)
	}
	key, e := base64.RawStdEncoding.DecodeString(secret)
	if e != nil || len(key) != ed25519.PrivateKeySize {
		return SourceOnboarded{}, model.Fail(model.Corrupt)
	}
	payload, e := canonicalSourcePolicyPayload(src, admissionAllowed)
	if e != nil {
		return SourceOnboarded{}, e
	}
	pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	id := "installation-" + model.HashCanonical(pub).String()[:32]
	e = s.store.View(ctx, func(st model.ControlState) error {
		if err := s.checkSource(st, c, false); err != nil {
			return err
		}
		current := st.Sources[c.source.String()]
		if current.Policy.Revision != src.Policy.Revision || current.Closing != src.Closing || current.Policy.Enabled != src.Policy.Enabled || st.Orgs[src.Org.String()].Epoch != epoch || st.PolicySigningKey != sealed || (s.checkSource(st, c, true) == nil) != admissionAllowed {
			return model.Fail(model.Stale)
		}
		return nil
	})
	if e != nil {
		return SourceOnboarded{}, e
	}
	return SourceOnboarded{Descriptor: model.SourceDescriptor{Version: 1, Org: src.Org, Project: src.Project, Source: src.ID, RoutingVersion: 1, Slots: 64, PolicyRevision: src.Policy.Revision}, Policy: model.SignedPolicyEnvelope{Version: 1, Algorithm: "Ed25519", KeyID: id, Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(key), payload))}, TrustedKeys: map[string]string{id: base64.RawURLEncoding.EncodeToString(pub)}}, nil
}
