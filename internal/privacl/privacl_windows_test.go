// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package privacl_test

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

// [09.06x-W4 / M-4] The ACL is read, not asserted: a directory restricted to the
// current user passes, the same directory with Everyone added is refused, and a
// path that does not exist is refused.
func TestCheckReadsTheDACL(t *testing.T) {
	dir := t.TempDir()
	icacls(t, dir, "/inheritance:r", "/grant:r", os.Getenv("USERNAME")+":(OI)(CI)F")
	if err := privacl.Check(dir); err != nil {
		t.Fatalf("a directory restricted to its owner was refused: %v", err)
	}
	icacls(t, dir, "/grant", "Everyone:(OI)(CI)R")
	if err := privacl.Check(dir); !errors.Is(err, privacl.ErrNotPrivate) {
		t.Fatalf("a directory readable by Everyone was admitted: %v", err)
	}
	if err := privacl.Check(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a path that cannot be examined must be refused")
	}
}

func TestCheckRefusesAnUsersGroupGrant(t *testing.T) {
	dir := t.TempDir()
	icacls(t, dir, "/inheritance:r", "/grant:r", os.Getenv("USERNAME")+":(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)R")
	if err := privacl.Check(dir); !errors.Is(err, privacl.ErrNotPrivate) {
		t.Fatalf("a directory readable by BUILTIN\\Users was admitted: %v", err)
	}
}

func TestRestrictMakesAnOpenDirectoryPrivate(t *testing.T) {
	dir := t.TempDir()
	icacls(t, dir, "/grant", "Everyone:(OI)(CI)R")
	if err := privacl.Check(dir); !errors.Is(err, privacl.ErrNotPrivate) {
		t.Fatalf("setup: %v", err)
	}
	if err := privacl.Restrict(dir); err != nil {
		t.Fatal(err)
	}
	if err := privacl.Check(dir); err != nil {
		t.Fatalf("a restricted directory was refused: %v", err)
	}
	child := filepath.Join(dir, "child")
	if err := os.WriteFile(child, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := privacl.Check(child); err != nil {
		t.Fatalf("a file created under a restricted directory inherits the restriction: %v", err)
	}
}
