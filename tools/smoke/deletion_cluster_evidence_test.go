// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"testing"

	bolt "go.etcd.io/bbolt"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

// walFrame is one ready.wal frame as internal/replica writes it.
func walFrame(t *testing.T, snapshot *pb.Snapshot, entries ...*pb.Entry) []byte {
	t.Helper()
	record := struct {
		Group    string   `json:"group"`
		Node     string   `json:"node"`
		Snapshot []byte   `json:"snapshot,omitempty"`
		Entries  [][]byte `json:"entries,omitempty"`
	}{Group: "00000000-0000-0000-0000-000000000001", Node: "3"}
	if snapshot != nil {
		raw, err := proto.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		record.Snapshot = raw
	}
	for _, e := range entries {
		raw, err := proto.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		record.Entries = append(record.Entries, raw)
	}
	body, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	table := crc32.MakeTable(crc32.Castagnoli)
	header := make([]byte, 16)
	copy(header, "SPR1")
	binary.BigEndian.PutUint32(header[4:], uint32(len(body)))
	binary.BigEndian.PutUint32(header[8:], crc32.Checksum(body, table))
	binary.BigEndian.PutUint32(header[12:], crc32.Checksum(header[:12], table))
	return append(header, body...)
}

func walEntries(from, to uint64) []*pb.Entry {
	var out []*pb.Entry
	for i := from; i <= to; i++ {
		out = append(out, &pb.Entry{Term: new(uint64(1)), Index: new(i), Data: []byte("x")})
	}
	return out
}

func walSnapshot(index uint64) *pb.Snapshot {
	return &pb.Snapshot{Metadata: &pb.SnapshotMetadata{Index: new(index), Term: new(uint64(1)), ConfState: &pb.ConfState{Voters: []uint64{1, 2, 3}}}}
}

// The journal range is read the way the replica reads it: entries append, a snapshot moves the
// start, and a torn final frame (a live node mid-append) is ignored, not an error.
func TestDeletionClusterReadsAJournalsRange(t *testing.T) {
	dir := t.TempDir()
	writeDCFile(t, dir, "raft/data/slot-7/ready.wal", slices.Concat(walFrame(t, walSnapshot(0)), walFrame(t, nil, walEntries(1, 4)...)))
	got, err := dcReadJournal(filepath.Join(dir, "raft/data/slot-7/ready.wal"))
	if err != nil || got != (dcJournal{Snapshot: 0, Last: 4}) {
		t.Fatalf("whole history: %+v %v", got, err)
	}

	// A snapshot installed past the journal's end, then the entries that follow it.
	installed := slices.Concat(walFrame(t, walSnapshot(0)), walFrame(t, nil, walEntries(1, 4)...), walFrame(t, walSnapshot(9)), walFrame(t, nil, walEntries(10, 11)...))
	writeDCFile(t, dir, "raft/data/slot-8/ready.wal", installed)
	got, err = dcReadJournal(filepath.Join(dir, "raft/data/slot-8/ready.wal"))
	if err != nil || got != (dcJournal{Snapshot: 9, Last: 11}) {
		t.Fatalf("after an install: %+v %v", got, err)
	}

	torn := slices.Concat(walFrame(t, walSnapshot(0)), walFrame(t, nil, walEntries(1, 3)...), walFrame(t, nil, walEntries(4, 5)...)[:20])
	writeDCFile(t, dir, "raft/control/ready.wal", torn)
	got, err = dcReadJournal(filepath.Join(dir, "raft/control/ready.wal"))
	if err != nil || got != (dcJournal{Snapshot: 0, Last: 3}) {
		t.Fatalf("torn tail: %+v %v", got, err)
	}

	all, err := dcJournals(dir)
	if err != nil || len(all) != 3 || all["raft/data/slot-8/ready.wal"].Snapshot != 9 || all["raft/control/ready.wal"].Last != 3 {
		t.Fatalf("every journal under the directory, keyed by relative path: %+v %v", all, err)
	}
}

// walRawFrame frames body as one ready.wal frame.
func walRawFrame(body []byte) []byte {
	table := crc32.MakeTable(crc32.Castagnoli)
	header := make([]byte, 16)
	copy(header, "SPR1")
	binary.BigEndian.PutUint32(header[4:], uint32(len(body)))
	binary.BigEndian.PutUint32(header[8:], crc32.Checksum(body, table))
	binary.BigEndian.PutUint32(header[12:], crc32.Checksum(header[:12], table))
	return append(header, body...)
}

// walChain writes a snapshot as internal/replica does when it does not fit one record: part records
// (each a slice of the snapshot's protobuf encoding), then the record that carries snapshot_parts and
// the entries. It returns the frames of the parts and of the closing record apart.
func walChain(t *testing.T, snapshot *pb.Snapshot, parts int, declared int, entries ...*pb.Entry) (partFrames, closing []byte) {
	t.Helper()
	raw, err := proto.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	step := (len(raw) + parts - 1) / parts
	for off := 0; off < len(raw); off += step {
		body, err := json.Marshal(map[string]any{"group": "00000000-0000-0000-0000-000000000001", "node": "3", "snapshot_part": raw[off:min(off+step, len(raw))]})
		if err != nil {
			t.Fatal(err)
		}
		partFrames = append(partFrames, walRawFrame(body)...)
	}
	var encoded [][]byte
	for _, e := range entries {
		b, err := proto.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, b)
	}
	body, err := json.Marshal(map[string]any{"group": "00000000-0000-0000-0000-000000000001", "node": "3", "snapshot_parts": strconv.Itoa(declared), "entries": encoded})
	if err != nil {
		t.Fatal(err)
	}
	return partFrames, walRawFrame(body)
}

// A snapshot written as a chain of part records is joined like the replica joins it; a chain whose last
// record never reached the disk is ignored; a missing, extra or damaged part is an error.
func TestDeletionClusterReadsAChainedJournal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "raft/ready.wal")
	snap := &pb.Snapshot{Data: bytes.Repeat([]byte("state"), 40), Metadata: &pb.SnapshotMetadata{Index: new(uint64(9)), Term: new(uint64(1)), ConfState: &pb.ConfState{Voters: []uint64{1, 2, 3}}}}
	head := walFrame(t, walSnapshot(0))
	parts, closing := walChain(t, snap, 3, 3, walEntries(10, 11)...)
	writeDCFile(t, dir, "raft/ready.wal", slices.Concat(head, parts, closing))
	if got, err := dcReadJournal(path); err != nil || got != (dcJournal{Snapshot: 9, Last: 11}) {
		t.Fatalf("chain: %+v %v", got, err)
	}

	// The record that completes the chain never reached the disk (absent, or torn): the chain is ignored.
	prior := slices.Concat(head, walFrame(t, nil, walEntries(1, 4)...))
	for name, tail := range map[string][]byte{"absent": nil, "torn": closing[:len(closing)-5]} {
		writeDCFile(t, dir, "raft/ready.wal", slices.Concat(prior, parts, tail))
		if got, err := dcReadJournal(path); err != nil || got != (dcJournal{Snapshot: 0, Last: 4}) {
			t.Fatalf("unfinished chain, last record %s: %+v %v", name, got, err)
		}
	}

	missing, missingEnd := walChain(t, snap, 3, 4)
	extra, extraEnd := walChain(t, snap, 3, 2)
	loose := walRawFrame([]byte(`{"group":"00000000-0000-0000-0000-000000000001","node":"3","snapshot_part":"AAAA"}`))
	fat := walRawFrame([]byte(`{"group":"00000000-0000-0000-0000-000000000001","node":"3","snapshot_part":"AAAA","entries":["AAAA"]}`))
	for name, bad := range map[string][]byte{
		"missing part":             slices.Concat(prior, missing, missingEnd),
		"extra part":               slices.Concat(prior, extra, extraEnd),
		"part cut off by a record": slices.Concat(prior, loose, walFrame(t, nil, walEntries(5, 5)...)),
		"chain end without parts":  slices.Concat(prior, closing),
		"part carrying entries":    slices.Concat(prior, fat),
	} {
		writeDCFile(t, dir, "raft/ready.wal", bad)
		if _, err := dcReadJournal(path); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// A journal is stranded when the live node's cut lies past the lagging voter's last entry; a
// voter whose journal now starts at or past that cut moved over the gap by installing it.
func TestDeletionClusterStrandedAndInstalledJournals(t *testing.T) {
	lagging := map[string]dcJournal{"a": {Snapshot: 0, Last: 10}, "b": {Snapshot: 0, Last: 20}, "c": {Snapshot: 0, Last: 5}, "only-lagging": {Last: 1}}
	live := map[string]dcJournal{"a": {Snapshot: 12, Last: 12}, "b": {Snapshot: 20, Last: 22}, "c": {Snapshot: 3, Last: 9}, "only-live": {Snapshot: 50, Last: 50}}
	stranded := dcStranded(lagging, live)
	if !reflect.DeepEqual(stranded, []string{"a"}) { // b: cut AT the voter's last entry needs nothing; c: the voter holds past the cut
		t.Fatalf("stranded %v", stranded)
	}
	after := map[string]dcJournal{"a": {Snapshot: 12, Last: 15}}
	if got := dcInstalledPast(stranded, live, after); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("installed past: %v", got)
	}
	if got := dcInstalledPast(stranded, live, map[string]dcJournal{"a": {Snapshot: 0, Last: 12}}); len(got) != 0 {
		t.Fatalf("a voter that never installed a snapshot (journal still whole) must not count: %v", got)
	}
	if got := dcInstalledPast(stranded, live, map[string]dcJournal{}); len(got) != 0 {
		t.Fatalf("a missing journal must not count: %v", got)
	}
}

// The erase-protocol facts are read from the replicated-data bucket of a stopped node's apply.db
// by what the key names, whichever slot prefix they carry for other bookkeeping.
func TestDeletionClusterReadsEraseFactsFromApplyDB(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(filepath.Join(dir, "data", "apply.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	u64 := func(v uint64) []byte { var b [8]byte; binary.BigEndian.PutUint64(b[:], v); return b[:] }
	key := func(slot uint16, name string) []byte {
		var p [2]byte
		binary.BigEndian.PutUint16(p[:], slot)
		return append(p[:], name...)
	}
	if err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket([]byte("replica_data"))
		if err != nil {
			return err
		}
		for k, v := range map[string][]byte{
			string(key(0, "erase-notice:3:node-3-identity")): u64(41),
			string(key(0, "erase-notice:2:node-2-identity")): u64(7),
			string(key(0, "install-epoch")):                  u64(2),
			string(key(0, "notice-settled")):                 u64(41),
			string(key(5, "erase-notice:3:not-slot-zero")):   u64(99),
			string(key(0, "erased:op")):                      u64(1),
		} {
			if err := b.Put([]byte(k), v); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := dcReadFacts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.NoticeByNode["3"] != 41 || got.NoticeByNode["2"] != 7 || len(got.NoticeByNode) != 2 || got.InstallEpoch != 2 || got.NoticeSettled != 41 {
		t.Fatalf("facts %+v", got)
	}
	empty := t.TempDir()
	if _, err = dcReadFacts(empty); err == nil {
		t.Fatal("a directory without an apply.db is an error, not zero facts")
	}
}

func TestDeletionClusterLagNodeList(t *testing.T) {
	if got, err := dcParseNodes("--lag-nodes", "3,2,1"); err != nil || !reflect.DeepEqual(got, []uint64{3, 2, 1}) {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := dcParseNodes("--lag-nodes", " 2 "); err != nil || !reflect.DeepEqual(got, []uint64{2}) {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"", "0", "4", "1,1", "a", "1,,2", "1 2", "none"} {
		if got, err := dcParseNodes("--lag-nodes", bad); err == nil {
			t.Errorf("%q accepted: %v", bad, got)
		}
	}
}

// The artifact of one lagging-node run is named after that node so a run of all three keeps them apart.
func TestDeletionClusterArtifactFileIsNamedPerRun(t *testing.T) {
	dir := t.TempDir()
	r := newDCRecorder()
	r.artifactDir = dir
	r.file = dcArtifactName(2)
	r.enter("dc_x")
	if err := r.finish(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "deletion-cluster-lag-2.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "deletion-cluster.json")); err == nil {
		t.Fatal("the unnamed artifact must not be written next to a named one")
	}
}
