// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestLockedSanityAnswersRejectMutationAndAlternateFile(t *testing.T) {
	original := []byte(`{"expected":{"bits":"4008000000000000"}}`)
	hash := sha256.Sum256(original)
	lock := SourceLock{InventoryFiles: map[string]string{"cases/oracle-sanity.json": hex.EncodeToString(hash[:])}}
	path := filepath.Join(t.TempDir(), "cases.json")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	var value any
	if err := ReadLockedJSON(lock, "cases/oracle-sanity.json", path, &value); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"expected":{"bits":"0000000000000000"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ReadLockedJSON(lock, "cases/oracle-sanity.json", path, &value); err == nil {
		t.Fatal("changed expected answer bypassed exact content lock")
	}
	if err := ReadLockedJSON(lock, "unlocked-case", path, &value); err == nil {
		t.Fatal("missing case lock accepted")
	}
}
func TestManifestObligationsRequireExactProfileSet(t *testing.T) {
	ledger := Ledger{Obligations: []Obligation{{ID: "a", Profile: "p"}, {ID: "b", Profile: "p"}, {ID: "other", Profile: "q"}}}
	if err := validateManifestObligations("p", []string{"b", "a"}, ledger); err != nil {
		t.Fatal(err)
	}
	for _, ids := range [][]string{{"a"}, {"a", "a"}, {"a", "other"}, {"a", "b", "extra"}} {
		if err := validateManifestObligations("p", ids, ledger); err == nil {
			t.Fatalf("nonexact manifest accepted: %v", ids)
		}
	}
}
