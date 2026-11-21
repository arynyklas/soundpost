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

// distributedDirectoryWithoutControlJournal lays down what a stopped node of a three-member
// installation leaves when its control journal (raft/control/ready.wal) is gone: the data
// groups' journals (raft/data/slot-N/ready.wal) still name node 2 of three members.
func distributedDirectoryWithoutControlJournal(t *testing.T, dir string) {
	t.Helper()
	payload := `{"group":"00000000000000000000000000000001","node":"2","members":{"revision":"1","nodes":[{"id":"1","address":"https://a","node_identity":"n1","failure_domain":"d1"},{"id":"2","address":"https://b","node_identity":"n2","failure_domain":"d2"},{"id":"3","address":"https://c","node_identity":"n3","failure_domain":"d3"}]}}`
	table := crc32.MakeTable(crc32.Castagnoli)
	var header [16]byte
	copy(header[:4], "SPR1")
	binary.BigEndian.PutUint32(header[4:8], uint32(len(payload)))
	binary.BigEndian.PutUint32(header[8:12], crc32.Checksum([]byte(payload), table))
	binary.BigEndian.PutUint32(header[12:], crc32.Checksum(header[:12], table))
	slot := filepath.Join(dir, "raft", "data", "slot-0")
	if err := os.MkdirAll(slot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slot, "ready.wal"), append(header[:], payload...), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A distributed node's directory that lost its control journal is refused with the same typed
// unsupported_mode as one that has it, before anything opens (and so creates files in) it.
func TestBackupRefusesADistributedDirectoryWithoutAControlJournal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	work := t.TempDir()
	node := filepath.Join(work, "node-2")
	distributedDirectoryWithoutControlJournal(t, node)
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
		say  string
	}{
		{"create without joining the cluster", append([]string{"backup", "create", "--data-dir", node, "--admin-email", "ops@example.test", "--key-dir", keyDir, "--data-kek", "data-kek", "--secret-kek", "data-kek", "--dest-dir", filepath.Join(work, "dest")}, authority...), "--mode distributed"},
		{"authority-init with a data directory", append([]string{"backup", "authority-init", "--data-dir", node}, authority...), "single-voter root"},
		{"activate", append([]string{"backup", "activate", "--root", node}, authority...), "single-voter root"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stderr, code := runSoundpost(t, tc.args...)
			if code != 1 {
				t.Fatalf("exit code %d, want 1 (stderr %q)", code, stderr)
			}
			if !strings.Contains(stderr, "unsupported_mode") || !strings.Contains(stderr, tc.say) {
				t.Fatalf("stderr %q is not the typed refusal naming the supported mode", stderr)
			}
			if strings.Contains(stderr, "internal error") || strings.Contains(stderr, work) {
				t.Fatalf("stderr %q is an internal error or names a path", stderr)
			}
			if _, err := os.Stat(filepath.Join(node, "control.db")); !os.IsNotExist(err) {
				t.Fatalf("the refusal came after the directory was opened: control.db exists (%v)", err)
			}
		})
	}
}
