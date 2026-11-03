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
func (s *Service) SourceConfiguration(ctx context.Context, c SourceCredential) (SourceOnboarded, error) {
	src, e := s.SourceAuthority(ctx, c, false)
	if e != nil {
		return SourceOnboarded{}, e
	}
	var sealed string
	if e = s.store.View(ctx, func(st model.ControlState) error {
		if e := s.checkSource(st, c, false); e != nil {
			return e
		}
		sealed = st.PolicySigningKey
		return nil
	}); e != nil {
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
	expiry := src.Expires
	if src.Policy.Expires != 0 && src.Policy.Expires < expiry {
		expiry = src.Policy.Expires
	}
	_, admissionError := s.SourceAuthority(ctx, c, true)
	enabled := func(k model.Kind) bool {
		if admissionError != nil || !src.Policy.Enabled || src.Closing {
			return false
		}
		for _, v := range src.Policy.Kinds {
			if v == k {
				return true
			}
		}
		return false
	}
	payload, e := model.CanonicalJSON(map[string]any{"version": 1, "org": src.Org.String(), "project": src.Project.String(), "source": src.ID.String(), "revision": src.Policy.Revision, "expires_ns": expiry, "errors": enabled(model.ErrorKind), "logs": enabled(model.Log), "replay": enabled(model.Replay) && src.Policy.Replay, "bodies": false})
	if e != nil {
		return SourceOnboarded{}, e
	}
	pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	id := "installation-" + model.HashCanonical(pub).String()[:32]
	current, e := s.SourceAuthority(ctx, c, false)
	if e != nil {
		return SourceOnboarded{}, e
	}
	if current.Policy.Revision != src.Policy.Revision || current.Closing != src.Closing || current.Policy.Enabled != src.Policy.Enabled {
		return SourceOnboarded{}, model.Fail(model.Stale)
	}
	return SourceOnboarded{Descriptor: model.SourceDescriptor{Version: 1, Org: src.Org, Project: src.Project, Source: src.ID, RoutingVersion: 1, Slots: 64, PolicyRevision: src.Policy.Revision}, Policy: model.SignedPolicyEnvelope{Version: 1, Algorithm: "Ed25519", KeyID: id, Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(key), payload))}, TrustedKeys: map[string]string{id: base64.RawURLEncoding.EncodeToString(pub)}}, nil
}
