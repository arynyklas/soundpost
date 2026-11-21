// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// [09.06x-W4 / M-4] On Windows the credential file's DACL is read: a file
// Everyone can read is refused, the same file restricted to its owner is read.
func TestReadCredentialReadsTheWindowsACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", path, "/inheritance:r", "/grant:r", os.Getenv("USERNAME")+":F").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v %s", err, out)
	}
	if _, err := ReadCredential(path); err != nil {
		t.Fatalf("an owner-only credential was refused: %v", err)
	}
	if out, err := exec.Command("icacls", path, "/grant", "Everyone:R").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v %s", err, out)
	}
	if _, err := ReadCredential(path); err == nil {
		t.Fatal("a credential readable by Everyone was read")
	}
}
