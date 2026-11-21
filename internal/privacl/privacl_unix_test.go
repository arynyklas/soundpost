// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package privacl_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/arynyklas/soundpost/internal/privacl"
)

func TestCheckRefusesGroupAndOtherAccess(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "secret")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := privacl.Check(file); err != nil {
		t.Fatalf("0600 refused: %v", err)
	}
	if err := os.Chmod(file, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := privacl.Check(file); !errors.Is(err, privacl.ErrNotPrivate) {
		t.Fatalf("0640 admitted: %v", err)
	}
	if err := privacl.Check(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a path that cannot be examined must be refused")
	}
}
