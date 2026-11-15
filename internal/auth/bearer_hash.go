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
	"github.com/arynyklas/soundpost/internal/model"
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

// SchemaMarker is the control-state format marker this build reads and writes: the persisted
// BearerHashKeyVersion. A stored marker above it was written by a newer build, a stored marker
// below it by a build that predates the format (a pristine root, marker 0 with nothing stored,
// is not that: the first start initializes it).
const SchemaMarker uint8 = 1

// SchemaError is the typed decision that the stored control state is in a format this build does
// not support. It is neither corruption nor an I/O failure and is deliberately not a model.Fault:
// the startup path reports it as the readiness reason schema_newer or schema_old and serves
// nothing, where a fault would be printed as a failed (corrupt) start.
type SchemaError struct{ Observed uint8 }

// Newer reports a marker above SchemaMarker (written by a newer build); false is an older one.
func (e *SchemaError) Newer() bool { return e.Observed > SchemaMarker }

func (e *SchemaError) Error() string {
	if e.Newer() {
		return "schema_newer: the control state was written by a newer format than this build supports"
	}
	return "schema_old: the control state predates the format this build requires"
}

// holdsAuthority reports state that only an installation in use carries.
func holdsAuthority(st model.ControlState) bool {
	return len(st.Users) > 0 || len(st.Sessions) > 0 || len(st.ServerTokens) > 0 || len(st.Sources) > 0 || len(st.SourceCredentials) > 0
}

// checkSchema decides the format marker of a decoded control state. Any marker above SchemaMarker
// is newer. A lower one is old when the state is in use (a sealed key, or users, sessions, tokens
// or sources stored): a pristine root is left to initializeBearerHashKey. A marker this build
// supports is not judged here; what is inconsistent with it is corruption.
func checkSchema(st model.ControlState) error {
	switch v := st.BearerHashKeyVersion; {
	case v > SchemaMarker:
		return &SchemaError{Observed: v}
	case v < SchemaMarker && (st.BearerHashKey != "" || holdsAuthority(st)):
		return &SchemaError{Observed: v}
	}
	return nil
}

// initializeBearerHashKey performs startup I/O before request handling. Random
// key generation and envelope sealing happen outside deterministic state apply.
// The installation's immutable hash key is distinct from rotating envelope keys.
// The format marker is decided first (checkSchema), before anything is initialized or sealed.
func initializeBearerHashKey(store ControlStore) ([32]byte, error) {
	var key [32]byte
	var sealed string
	ctx := context.Background()
	if err := store.View(ctx, func(st model.ControlState) error {
		if err := checkSchema(st); err != nil {
			return err
		}
		sealed = st.BearerHashKey
		if sealed == "" && (st.BearerHashKeyVersion != 0 || st.BootstrapHash == "" || holdsAuthority(st)) {
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
