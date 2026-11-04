// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"soundpost/internal/model"
)

type BearerPurpose string

const (
	ServerAPIBearer BearerPurpose = "server-api"
	SourceBearer    BearerPurpose = "source"
)

// BearerDigest is the consumer-owned authority seam for server/API and source
// owners. It exposes no key material and accepts only registered purposes.
func (s *Service) BearerDigest(purpose BearerPurpose, token string) (string, error) {
	if s == nil || s.store == nil {
		return "", model.Fail(model.Unavailable)
	}
	switch purpose {
	case ServerAPIBearer, SourceBearer:
	default:
		return "", model.Fail(model.Invalid)
	}
	return s.keyedBearerDigest(purpose, token), nil
}
func (s *Service) keyedBearerDigest(purpose BearerPurpose, token string) string {
	mac := hmac.New(sha256.New, s.bearerHashKey[:])
	_, _ = mac.Write([]byte("soundpost/bearer-authority/v1\x00"))
	_, _ = mac.Write([]byte(purpose))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(token))
	return "hmac-sha256:v1:" + hex.EncodeToString(mac.Sum(nil))
}
func (s *Service) serverTokenDigest(token string) string {
	return s.keyedBearerDigest(ServerAPIBearer, token)
}

// initializeBearerHashKey performs startup I/O before request handling. Random
// key generation and envelope sealing happen outside deterministic state apply.
// The installation's immutable hash key is distinct from rotating envelope keys.
func initializeBearerHashKey(store ControlStore) ([32]byte, error) {
	var key [32]byte
	var sealed string
	ctx := context.Background()
	if err := store.View(ctx, func(st model.ControlState) error {
		sealed = st.BearerHashKey
		if st.BearerHashKeyVersion > 1 {
			return model.Fail(model.Corrupt)
		}
		if sealed == "" && (st.BearerHashKeyVersion != 0 || st.BootstrapHash == "" || len(st.Users) > 0 || len(st.Sessions) > 0 || len(st.ServerTokens) > 0 || len(st.Sources) > 0 || len(st.SourceCredentials) > 0) {
			return model.Fail(model.Corrupt)
		}
		if sealed != "" && st.BearerHashKeyVersion != 1 {
			return model.Fail(model.Corrupt)
		}
		return nil
	}); err != nil {
		return key, err
	}
	if sealed == "" {
		var candidate [32]byte
		if _, err := rand.Read(candidate[:]); err != nil {
			return key, err
		}
		encoded := base64.RawStdEncoding.EncodeToString(candidate[:])
		clear(candidate[:])
		candidateEnvelope, err := store.Seal(encoded)
		if err != nil {
			return key, err
		}
		if err := store.InitializeBearerHashKey(ctx, candidateEnvelope, 1); err != nil {
			return key, err
		}
		// Re-read the committed root: concurrent constructors must use the first
		// installed authority, never assume their prepared candidate won.
		if err := store.View(ctx, func(st model.ControlState) error {
			if st.BearerHashKey == "" || st.BearerHashKeyVersion != 1 {
				return model.Fail(model.Corrupt)
			}
			sealed = st.BearerHashKey
			return nil
		}); err != nil {
			return key, err
		}
	}
	encoded, err := store.OpenSecret(sealed)
	if err != nil {
		return key, model.Fail(model.Unavailable)
	}
	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != len(key) {
		return key, model.Fail(model.Corrupt)
	}
	copy(key[:], decoded)
	clear(decoded)
	return key, nil
}
