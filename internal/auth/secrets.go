// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// hashToken is only for random session/one-use handles, recovery codes and
// non-authority fingerprints. API/source bearer authority uses BearerDigest.
func hashToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
