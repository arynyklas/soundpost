// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/profiles"
	"io/fs"
	"os"
	"path"
	"testing"
)

// TestEmbeddedProfilesMatchTheConformanceLock: the profile manifests a built
// binary carries are byte-for-byte the files the conformance lock pins, so the
// shipped engine semantics cannot drift from the locked ones without a failing
// default test (the oracle-backed sanity run only exists in the integration
// build).
func TestEmbeddedProfilesMatchTheConformanceLock(t *testing.T) {
	const lockPath = "../../conformance/query/source-lock.json"
	raw, err := os.ReadFile(lockPath)
	if errors.Is(err, fs.ErrNotExist) {
		t.Skipf("conformance lock %s is not in this checkout; the embedded profiles cannot be compared", lockPath)
	}
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		ProfileFiles map[string]string `json:"profile_files"`
	}
	if err = json.Unmarshal(raw, &lock); err != nil {
		t.Fatal(err)
	}
	if len(lock.ProfileFiles) == 0 {
		t.Fatal("the lock pins no profile files")
	}
	embedded, err := profiles.Query()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(embedded, ".")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		data, err := fs.ReadFile(embedded, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		key := path.Join("profiles/query", entry.Name())
		sum := sha256.Sum256(data)
		want, ok := lock.ProfileFiles[key]
		if !ok {
			t.Errorf("embedded profile %s is not pinned by the lock", key)
			continue
		}
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("embedded profile %s has sha256 %s, the lock pins %s", key, got, want)
		}
		seen[key] = true
	}
	for key := range lock.ProfileFiles {
		if !seen[key] {
			t.Errorf("the lock pins %s but the binary does not embed it", key)
		}
	}
}
