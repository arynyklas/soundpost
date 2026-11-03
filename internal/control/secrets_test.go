// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"soundpost/internal/control"
	"strings"
	"testing"
)

func TestSecretRotationRetainsOldDecrypt(t *testing.T) {
	dir := t.TempDir()
	store, err := control.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	old, err := store.Seal("first-secret")
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := store.RotateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	next, err := store.Seal("second-secret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(next, keyID+":") || strings.HasPrefix(old, keyID+":") {
		t.Fatal("missing distinct key IDs")
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = control.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for sealed, want := range map[string]string{old: "first-secret", next: "second-secret"} {
		got, err := store.OpenSecret(sealed)
		if err != nil || got != want {
			t.Fatalf("durable envelope roundtrip: %v", err)
		}
	}
	if _, err = store.OpenSecret("../../outside:invalid"); err == nil {
		t.Fatal("invalid key ID accepted")
	}
}
