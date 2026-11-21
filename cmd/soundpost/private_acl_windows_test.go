// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/arynyklas/soundpost/internal/privacl"
)

func icacls(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
		t.Fatalf("icacls %v: %v\n%s", args, err, out)
	}
}

// [09.06x-W4 / M-4] On Windows the data directory's DACL is verified, not skipped:
// a directory other users can read is restricted to its owner, and an operator
// TLS key readable by other users is refused.
func TestPreparePrivateReadsTheWindowsACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	icacls(t, dir, "/grant", "Everyone:(OI)(CI)R")
	if err := privacl.Check(dir); !errors.Is(err, privacl.ErrNotPrivate) {
		t.Fatalf("setup: %v", err)
	}
	if err := preparePrivate(dir, ""); err != nil {
		t.Fatal(err)
	}
	if err := privacl.Check(dir); err != nil {
		t.Fatalf("the data directory was left readable by other users: %v", err)
	}

	key := filepath.Join(t.TempDir(), "server.key")
	if err := os.WriteFile(key, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	icacls(t, key, "/inheritance:r", "/grant:r", os.Getenv("USERNAME")+":F")
	if err := preparePrivate(dir, key); err != nil {
		t.Fatalf("an owner-only key was refused: %v", err)
	}
	icacls(t, key, "/grant", "Everyone:R")
	if err := preparePrivate(dir, key); !errors.Is(err, errInsecureMode) {
		t.Fatalf("a key readable by Everyone was admitted: %v", err)
	}
}
