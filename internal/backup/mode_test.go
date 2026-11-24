// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// writeFirstRecord writes a control-group journal whose first record has the replica
// journal's framing (magic, length, CRC-32C of the payload and of the header).
func writeFirstRecord(t *testing.T, dir string, payload string) {
	t.Helper()
	writeJournalAt(t, filepath.Join(dir, "raft", "control"), payload)
}

// writeSlotJournal writes the journal of one data group (raft/data/slot-N) the same way.
func writeSlotJournal(t *testing.T, dir string, slot int, payload string) {
	t.Helper()
	writeJournalAt(t, filepath.Join(dir, "raft", "data", "slot-"+strconv.Itoa(slot)), payload)
}

func writeJournalAt(t *testing.T, path string, payload string) {
	t.Helper()
	crc := crc32.MakeTable(crc32.Castagnoli)
	var header [16]byte
	copy(header[:4], "SPR1")
	binary.BigEndian.PutUint32(header[4:8], uint32(len(payload)))
	binary.BigEndian.PutUint32(header[8:12], crc32.Checksum([]byte(payload), crc))
	binary.BigEndian.PutUint32(header[12:], crc32.Checksum(header[:12], crc))
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

// A journal whose first record is a part record of a chained snapshot (a snapshot larger than one
// record) is classified by the node and members that part record carries, like a whole first record.
func TestIsDistributedDirectoryReadsAJournalThatStartsWithASnapshotPart(t *testing.T) {
	part := func(record string) string {
		return strings.TrimSuffix(record, "}") + `,"snapshot_part":"AAAA"}`
	}
	dir := t.TempDir()
	writeFirstRecord(t, dir, part(threeMemberRecord))
	if got, err := IsDistributedDirectory(dir); err != nil || !got {
		t.Fatalf("three-member chain: %v %v", got, err)
	}
	dir = t.TempDir()
	writeFirstRecord(t, dir, part(singleRecord))
	if got, err := IsDistributedDirectory(dir); err != nil || got {
		t.Fatalf("single-node chain: %v %v", got, err)
	}
}

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

// A distributed node's directory whose control journal is gone (deleted, or torn at its first
// record) is still the directory of a cluster node: the data groups' journals were created
// with the same identity and membership. A directory that only holds snapshots is not
// classified, because a single-voter root restored from a cluster backup holds exactly that
// (snapshots cut in the cluster) until it is first opened.
func TestIsDistributedDirectoryFallsBackToTheDataGroupJournals(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(t *testing.T, dir string)
		want bool
	}{
		{"control journal deleted, a data group names a node of three", func(t *testing.T, dir string) {
			writeSlotJournal(t, dir, 0, threeMemberRecord)
		}, true},
		{"control journal deleted, the third of several data groups names a node of three", func(t *testing.T, dir string) {
			writeSlotJournal(t, dir, 0, singleRecord)
			writeSlotJournal(t, dir, 1, singleRecord)
			writeSlotJournal(t, dir, 2, threeMemberRecord)
		}, true},
		{"control journal torn at its first record, a data group names a node of three", func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "raft", "control"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "raft", "control", "ready.wal"), []byte("SPR1\x00\x00"), 0o600); err != nil {
				t.Fatal(err)
			}
			writeSlotJournal(t, dir, 7, threeMemberRecord)
		}, true},
		{"control journal deleted, the data groups are the single-node layout", func(t *testing.T, dir string) {
			writeSlotJournal(t, dir, 0, singleRecord)
			writeSlotJournal(t, dir, 1, singleRecord)
		}, false},
		{"control journal deleted, a journal outside the slot directories is not a data group", func(t *testing.T, dir string) {
			writeJournalAt(t, filepath.Join(dir, "raft", "data", "scratch"), threeMemberRecord)
		}, false},
		{"a restored root before its first open: installed snapshots, no journal anywhere", func(t *testing.T, dir string) {
			snap := filepath.Join(dir, "raft", "data", "slot-0", "snapshots", "snap-00000000000000000001-00000000")
			if err := os.MkdirAll(snap, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(snap, "envelope"), []byte(`{"members":{"revision":"1","nodes":[{"id":"1"},{"id":"2"},{"id":"3"}]}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "raft", "data", "slot-0", "snapshots", "CURRENT"), []byte(`{}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"a control journal that says single-node is decisive over a data group that disagrees", func(t *testing.T, dir string) {
			writeFirstRecord(t, dir, singleRecord)
			writeSlotJournal(t, dir, 0, threeMemberRecord)
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
