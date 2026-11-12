// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

// writeFirstRecord writes a control-group journal whose first record has the replica
// journal's framing (magic, length, CRC-32C of the payload and of the header).
func writeFirstRecord(t *testing.T, dir string, payload string) {
	t.Helper()
	crc := crc32.MakeTable(crc32.Castagnoli)
	var header [16]byte
	copy(header[:4], "SPR1")
	binary.BigEndian.PutUint32(header[4:8], uint32(len(payload)))
	binary.BigEndian.PutUint32(header[8:12], crc32.Checksum([]byte(payload), crc))
	binary.BigEndian.PutUint32(header[12:], crc32.Checksum(header[:12], crc))
	path := filepath.Join(dir, "raft", "control")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "ready.wal"), append(header[:], payload...), 0o600); err != nil {
		t.Fatal(err)
	}
}

const (
	threeMemberRecord = `{"group":"00000000000000000000000000000001","node":"2","members":{"revision":"1","nodes":[{"id":"1","address":"https://a","node_identity":"n1","failure_domain":"d1"},{"id":"2","address":"https://b","node_identity":"n2","failure_domain":"d2"},{"id":"3","address":"https://c","node_identity":"n3","failure_domain":"d3"}]}}`
	singleRecord      = `{"group":"00000000000000000000000000000001","node":"1","members":{"revision":"1","nodes":[{"id":"1","address":"https://single.invalid","node_identity":"single","failure_domain":"local-disk"}]}}`
)

func TestIsDistributedDirectoryClassifiesByTheControlJournal(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(t *testing.T, dir string)
		want bool
	}{
		{"no journal at all", func(*testing.T, string) {}, false},
		{"a node of a three-member group", func(t *testing.T, dir string) { writeFirstRecord(t, dir, threeMemberRecord) }, true},
		{"the single-node layout", func(t *testing.T, dir string) { writeFirstRecord(t, dir, singleRecord) }, false},
		{"a journal that is not a journal", func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "raft", "control"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "raft", "control", "ready.wal"), []byte("not a journal at all"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"an empty journal", func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "raft", "control"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "raft", "control", "ready.wal"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.set(t, dir)
			got, err := IsDistributedDirectory(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("IsDistributedDirectory = %v, want %v", got, tc.want)
			}
		})
	}
}
