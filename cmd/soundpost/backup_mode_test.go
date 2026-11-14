// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// distributedDirectory lays down what a stopped node of a three-member installation
// leaves in raft/control: a journal whose first record names node 2 of three members.
func distributedDirectory(t *testing.T, dir string) {
	t.Helper()
	payload := `{"group":"00000000000000000000000000000001","node":"2","members":{"revision":"1","nodes":[{"id":"1","address":"https://a","node_identity":"n1","failure_domain":"d1"},{"id":"2","address":"https://b","node_identity":"n2","failure_domain":"d2"},{"id":"3","address":"https://c","node_identity":"n3","failure_domain":"d3"}]}}`
	table := crc32.MakeTable(crc32.Castagnoli)
	var header [16]byte
	copy(header[:4], "SPR1")
	binary.BigEndian.PutUint32(header[4:8], uint32(len(payload)))
	binary.BigEndian.PutUint32(header[8:12], crc32.Checksum([]byte(payload), table))
	binary.BigEndian.PutUint32(header[12:], crc32.Checksum(header[:12], table))
	if err := os.MkdirAll(filepath.Join(dir, "raft", "control"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "raft", "control", "ready.wal"), append(header[:], payload...), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Backup, restore and activation implement the single-node layout only. Pointed at a
// distributed node's directory they must refuse with the stable code unsupported_mode
// and a line naming what is supported, never the untyped internal error the replica
// journal's own refusal used to surface.
func TestBackupRefusesADistributedDirectoryWithATypedCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	work := t.TempDir()
	node := filepath.Join(work, "node-2")
	distributedDirectory(t, node)
	keyDir := filepath.Join(work, "keys")
	if _, code := runSoundpost(t, "backup", "keygen", "--key-dir", keyDir, "--id", "data-kek"); code != 0 {
		t.Fatal("keygen failed")
	}
	keysPath := filepath.Join(work, "authority-keys.json")
	if _, code := runSoundpost(t, "backup", "authority-keygen", "--out", keysPath, "--id", "authority-1"); code != 0 {
		t.Fatal("authority-keygen failed")
	}
	authority := []string{"--authority-keys", keysPath, "--authority-dir", filepath.Join(work, "authority")}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"create", append([]string{"backup", "create", "--data-dir", node, "--admin-email", "ops@example.test", "--key-dir", keyDir, "--data-kek", "data-kek", "--secret-kek", "data-kek", "--dest-dir", filepath.Join(work, "dest")}, authority...)},
		{"authority-init with a data directory", append([]string{"backup", "authority-init", "--data-dir", node}, authority...)},
		{"activate", append([]string{"backup", "activate", "--root", node}, authority...)},
		{"restore into a distributed directory", append([]string{"backup", "restore", "--backup-id", "00000000000000000000000000000001", "--root", node, "--key-dir", keyDir, "--dest-dir", filepath.Join(work, "dest")}, authority...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stderr, code := runSoundpost(t, tc.args...)
			if code != 1 {
				t.Fatalf("exit code %d, want 1 (stderr %q)", code, stderr)
			}
			if !strings.Contains(stderr, "unsupported_mode") || !strings.Contains(stderr, "single-node") {
				t.Fatalf("stderr %q is not the typed refusal naming the supported mode", stderr)
			}
			if strings.Contains(stderr, "internal error") || strings.Contains(stderr, work) {
				t.Fatalf("stderr %q is an internal error or names a path", stderr)
			}
		})
	}
}
