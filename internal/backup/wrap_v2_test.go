// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// Every wrap of one data key under one KEK is a different ciphertext under a different derived key
// (fresh salt, fixed nonce), so no (key, nonce) pair repeats however many keys a KEK wraps. A wrap
// made with a fixed salt would repeat itself and fail this test.
func TestEveryWrapUsesItsOwnDerivedKey(t *testing.T) {
	kek := testKey(t, "kek-1")
	dek, _ := newDataKey()
	aad := []byte("backup-1/data")
	seen := map[string]bool{}
	salts := map[string]bool{}
	for range 64 {
		w, err := wrapKey(kek, dek, aad)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(w, []byte(wrapMagic)) {
			t.Fatal("a new wrap is not of the derived-key layout")
		}
		if seen[string(w)] || salts[string(w[len(wrapMagic):len(wrapMagic)+saltSize])] {
			t.Fatal("two wraps share a salt (and so a key and nonce)")
		}
		seen[string(w)], salts[string(w[len(wrapMagic):len(wrapMagic)+saltSize])] = true, true
		if got, err := unwrapKey(kek, w, aad); err != nil || !bytes.Equal(got, dek) {
			t.Fatalf("unwrap: %v", err)
		}
		w[len(w)-1] ^= 1
		if _, err = unwrapKey(kek, w, aad); err == nil {
			t.Fatal("an altered wrap unwrapped")
		}
	}
}

// Wraps written before the layout changed (a random nonce, ciphertext under the KEK itself) still
// unwrap, including one whose random nonce begins with the new layout's magic.
func TestWrapsOfTheFirstLayoutStillUnwrap(t *testing.T) {
	kek := testKey(t, "kek-1")
	dek, _ := newDataKey()
	aad := []byte("backup-1/data")
	g, err := kek.aead()
	if err != nil {
		t.Fatal(err)
	}
	for _, magic := range []bool{false, true} {
		nonce := make([]byte, g.NonceSize(), g.NonceSize()+len(dek)+g.Overhead())
		if _, err = rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		if magic {
			copy(nonce, wrapMagic)
		}
		legacy := g.Seal(nonce, nonce, dek, append([]byte(wrapContext), aad...))
		if got, err := unwrapKey(kek, legacy, aad); err != nil || !bytes.Equal(got, dek) {
			t.Fatalf("first-layout wrap (magic-prefixed nonce %v): %v", magic, err)
		}
	}
}
