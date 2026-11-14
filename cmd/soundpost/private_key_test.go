// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"testing"
)

// systemd materialises LoadCredential= files as 0440 root:root (the service user is granted
// read access through an ACL, which shows up as the group bits). That must be accepted,
// while every way another local user could read the key must still be refused.
func TestKeyModeDecision(t *testing.T) {
	const rootGID, userGID = 0, 1001
	for _, c := range []struct {
		name  string
		perm  os.FileMode
		gid   uint32
		known bool
		ok    bool
	}{
		{"owner only", 0o600, userGID, true, true},
		{"owner read only", 0o400, userGID, true, true},
		{"systemd credential 0440 root group", 0o440, rootGID, true, true},
		{"0640 root group", 0o640, rootGID, true, true},
		{"0440 user group", 0o440, userGID, true, false},
		{"0640 user group", 0o640, userGID, true, false},
		{"0640 unknown group", 0o640, rootGID, false, false},
		{"0644 root group", 0o644, rootGID, true, false},
		{"0604 root group", 0o604, rootGID, true, false},
		{"0444 root group", 0o444, rootGID, true, false},
		{"0777", 0o777, rootGID, true, false},
		{"0001", 0o001, userGID, true, false},
	} {
		if got := keyModePrivate(c.perm, c.gid, c.known); got != c.ok {
			t.Errorf("%s: keyModePrivate(%04o, gid %d, known %v) = %v, want %v", c.name, c.perm, c.gid, c.known, got, c.ok)
		}
	}
}

// A real file is judged from its actual group: the test user's own group is never root's.
func TestPreparePrivateRefusesUserGroupKey(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("a root-owned test group cannot be told from the root group")
	}
	dir := t.TempDir()
	key := dir + "/k.key"
	if err := os.WriteFile(key, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := preparePrivate(dir+"/d", key); err == nil {
		t.Fatal("0640 key in the service user's own group was accepted")
	}
}
