// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	raft "go.etcd.io/raft/v3"
	pb "go.etcd.io/raft/v3/raftpb"
)

// The red tests of decision D86, condition 3: a snapshot of a group whose state is larger than one journal
// record (the record is bounded: 256 MiB, and the state is encoded twice as text inside it) failed the
// bound, and with it the first compaction of the journal stopped the node and a lagging voter could not be
// given the state. The tests lower the bound (SetRecordLimitForTest) instead of building hundreds of
// megabytes of state.

// journalFrames reads the records of a journal file as they lie in it.
func journalFrames(t *testing.T, path string) (records []readyRecord, starts []int64, lengths []int) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for off := 0; off < len(raw); {
		if len(raw)-off < 16 || string(raw[off:off+4]) != "SPR1" {
			t.Fatalf("journal frame at %d is not a record", off)
		}
		n := int(binary.BigEndian.Uint32(raw[off+4 : off+8]))
		var r readyRecord
		if err = json.Unmarshal(raw[off+16:off+16+n], &r); err != nil {
			t.Fatal(err)
		}
		records, starts, lengths = append(records, r), append(starts, int64(off)), append(lengths, n)
		off += 16 + n
	}
	return records, starts, lengths
}

func randomText(t *testing.T, n int) string {
	t.Helper()
	raw := make([]byte, n/2)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

// A snapshot that does not fit one record is journaled as a chain of records and read back whole.
func TestASnapshotBeyondOneRecordIsJournaledInPartsAndReadBack(t *testing.T) {
	defer SetRecordLimitForTest(8 << 10)()
	dir, group := t.TempDir(), model.NewID()
	state := []byte(randomText(t, 100<<10))
	w, _, err := openReadyWAL(dir, group, 1, soloMembers(), state, 7, 1, 1, nil, nil)
	if err != nil {
		t.Fatalf("a seed larger than one record: %v", err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	records, _, lengths := journalFrames(t, filepath.Join(dir, "ready.wal"))
	parts := 0
	for i, r := range records {
		if lengths[i] > maxReady() {
			t.Fatalf("record %d is %d B beyond the bound %d", i, lengths[i], maxReady())
		}
		if len(r.SnapshotPart) > 0 {
			parts++
		}
	}
	if parts < 2 || records[len(records)-1].SnapshotParts != uint64(parts) {
		t.Fatalf("seed journaled in %d part records, completed by %d", parts, records[len(records)-1].SnapshotParts)
	}
	_, memory, err := openReadyWAL(dir, group, 1, soloMembers(), nil, 0, 0, 0, nil, nil)
	if err != nil {
		t.Fatalf("reading the journal back: %v", err)
	}
	snap, err := memory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var envelope snapshotEnvelope
	if err = json.Unmarshal(snap.GetData(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(envelope.State, state) || envelope.Application != 7 || snap.GetMetadata().GetIndex() != 1 {
		t.Fatalf("the snapshot read back differs: %d B state, application %d, index %d", len(envelope.State), envelope.Application, snap.GetMetadata().GetIndex())
	}
}

// A chain whose last record never reached the disk is a write nothing acknowledged: the journal is cut back
// to where the chain began. A chain that lost a record from its middle, or whose record is damaged, is
// corruption and is refused.
func TestAnInterruptedChainOfSnapshotPartsIsDroppedAndADamagedOneIsRefused(t *testing.T) {
	defer SetRecordLimitForTest(8 << 10)()
	dir, group := t.TempDir(), model.NewID()
	w, _, err := openReadyWAL(dir, group, 1, soloMembers(), []byte("seed"), 0, 1, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	earlier, err := os.ReadFile(filepath.Join(dir, "ready.wal"))
	if err != nil {
		t.Fatal(err)
	}
	big := &pb.Snapshot{Data: []byte(randomText(t, 60<<10)), Metadata: &pb.SnapshotMetadata{Index: new(uint64(5)), Term: new(uint64(1)), ConfState: &pb.ConfState{Voters: []uint64{1}}}}
	if err = w.persist(raft.Ready{Snapshot: big, HardState: &pb.HardState{Term: new(uint64(1)), Commit: new(uint64(5))}}); err != nil {
		t.Fatalf("a snapshot beyond one record: %v", err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	whole, err := os.ReadFile(filepath.Join(dir, "ready.wal"))
	if err != nil {
		t.Fatal(err)
	}
	records, starts, lengths := journalFrames(t, filepath.Join(dir, "ready.wal"))
	if len(records) < 4 || records[len(records)-1].SnapshotParts == 0 || len(records[len(records)-1].Hard) == 0 {
		t.Fatalf("the chain is not what the test needs: %d records", len(records))
	}
	reopen := func(content []byte) (*raft.MemoryStorage, error) {
		if err := os.WriteFile(filepath.Join(dir, "ready.wal"), content, 0600); err != nil {
			t.Fatal(err)
		}
		w, memory, err := openReadyWAL(dir, group, 1, soloMembers(), nil, 0, 0, 0, nil, nil)
		if err == nil {
			w.Close()
		}
		return memory, err
	}
	end := func(i int) int { return int(starts[i]) + 16 + lengths[i] }
	chain := len(earlier) // the first record of the chain starts where the seed ends
	for _, cut := range []int{end(1), end(len(records) - 2), end(len(records)-2) + 100, len(whole) - 7} {
		memory, err := reopen(whole[:cut])
		if err != nil {
			t.Fatalf("journal cut at %d of %d inside the chain: %v", cut, len(whole), err)
		}
		if snap, _ := memory.Snapshot(); snap.GetMetadata().GetIndex() != 1 {
			t.Fatalf("an unfinished chain installed a snapshot at %d", snap.GetMetadata().GetIndex())
		}
		if after, _ := os.ReadFile(filepath.Join(dir, "ready.wal")); !bytes.Equal(after, earlier) {
			t.Fatalf("journal cut at %d is %d B after the open, want the %d B before the chain", cut, len(after), chain)
		}
	}
	if memory, err := reopen(whole); err != nil {
		t.Fatalf("the whole chain: %v", err)
	} else if snap, _ := memory.Snapshot(); snap.GetMetadata().GetIndex() != 5 || !bytes.Equal(snap.GetData(), big.GetData()) {
		t.Fatalf("the whole chain installed index %d", snap.GetMetadata().GetIndex())
	}
	lost := append(bytes.Clone(whole[:starts[2]]), whole[end(2):]...) // a middle part is missing
	if _, err = reopen(lost); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a chain that lost a part: %v", err)
	}
	flipped := bytes.Clone(whole)
	flipped[int(starts[1])+16+lengths[1]/2] ^= 0x40
	if _, err = reopen(flipped); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a damaged part: %v", err)
	}
	stray := append(bytes.Clone(whole[:end(1)]), earlier[len(earlier)-1:]...) // not a frame: a torn tail after a part
	if _, err = reopen(stray); err == nil {
		if after, _ := os.ReadFile(filepath.Join(dir, "ready.wal")); !bytes.Equal(after, earlier) {
			t.Fatalf("a part followed by a torn tail left %d B", len(after))
		}
	}
}

// The compaction of a journal whose snapshot does not fit one record used to fail the bound while the group
// was rewriting its journal, and stopped the node (replica: fail-stop in rewrite journal: invalid replica
// command). It writes the snapshot as a chain, and a restart reads it.
func TestCompactingAJournalWhoseSnapshotExceedsOneRecordDoesNotStopTheNode(t *testing.T) {
	defer SetRecordLimitForTest(16 << 10)()
	id := model.NewID()
	dir := t.TempDir()
	s := openSolo(t, dir, id, nil)
	for i := range 120 {
		s.propose(Data, fmt.Sprintf("row-%03d-%s", i, randomText(t, 1500)))
	}
	snapshot := s.snapshot()
	for i := range 3 {
		s.propose(Data, fmt.Sprintf("suffix-%d", i))
	}
	if _, err := s.group.CompactJournal(context.Background()); err != nil {
		t.Fatalf("compaction: %v", err)
	}
	if first, _ := s.group.JournalRange(); first != snapshot.Manifest.Index+1 {
		t.Fatalf("journal first index %d, want %d", first, snapshot.Manifest.Index+1)
	}
	s.propose(Data, "after the compaction") // the group still commits: it did not stop
	records, _, _ := journalFrames(t, filepath.Join(dir, "raft", "ready.wal"))
	parts := 0
	for _, r := range records {
		if len(r.SnapshotPart) > 0 {
			parts++
		}
	}
	if parts < 2 {
		t.Fatalf("the compacted journal holds the snapshot in %d part records", parts)
	}
	s.close()
	re := openSolo(t, dir, id, nil)
	if got := len(re.machine.rows); got != 124 {
		t.Fatalf("restart holds %d rows, want 124", got)
	}
}

// A group of three whose third member joins after the leader compacted its journal: the leader sends it a
// snapshot that is larger than one request and than one record, over the production transport. Node 3
// installs it whole (its journal holds it as a chain) and goes on with the log.
func TestALaggingVoterIsGivenASnapshotLargerThanOneRequestOverTheTransport(t *testing.T) {
	defer SetRecordLimitForTest(32 << 10)()
	roots, certificates := testPKI(t, 3)
	listeners := make([]net.Listener, 3)
	members := Members{Revision: 1}
	for i := range listeners {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners[i] = l
		members.Nodes = append(members.Nodes, Member{ID: uint64(i + 1), Address: "https://" + l.Addr().String(), NodeIdentity: fmt.Sprintf("node-%d", i+1), FailureDomain: fmt.Sprintf("test-disk-%d", i+1)})
	}
	id := model.NewID()
	type node struct {
		machine *ledgerMachine
		group   *Group
		dir     string
	}
	nodes := make([]*node, 3)
	start := func(i int) {
		transport, err := NewMTLS(uint64(i+1), fmt.Sprintf("node-%d", i+1), certificates[i], roots, "")
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Handler: transport, TLSConfig: transport.ServerTLS(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
		go func() { _ = server.Serve(tls.NewListener(listeners[i], server.TLSConfig)) }()
		dir := t.TempDir()
		machine := newLedgerMachine(id, filepath.Join(dir, "machine"))
		g, err := Open(Config{ID: uint64(i + 1), Group: id, Directory: filepath.Join(dir, "raft"), Members: members, Machine: machine, Transport: transport, TickInterval: 20 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		if err = transport.Register(g); err != nil {
			t.Fatal(err)
		}
		nodes[i] = &node{machine: machine, group: g, dir: dir}
		t.Cleanup(func() { server.Close(); transport.Close(); g.Close() })
	}
	start(0)
	start(1)
	if err := nodes[0].group.Campaign(); err != nil {
		t.Fatal(err)
	}
	ready, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for {
		if _, err := nodes[0].group.ReadIndex(ready); err == nil {
			break
		} else if ready.Err() != nil {
			t.Fatalf("no leader: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for i := range 150 {
		if _, err := nodes[0].group.Propose(ready, Entry{ID: model.NewID(), Kind: Data, Payload: []byte(fmt.Sprintf("row-%03d-%s", i, randomText(t, 1200)))}); err != nil {
			t.Fatal(err)
		}
	}
	snap, err := nodes[0].group.CreateSnapshot(ready, model.Cursor{Group: id, Index: nodes[0].group.Status().ApplicationCursor.Index})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = nodes[0].group.CompactJournal(ready); err != nil {
		t.Fatal(err)
	}
	if first, _ := nodes[0].group.JournalRange(); first != snap.Manifest.Index+1 {
		t.Fatalf("the leader's journal begins at %d, want %d", first, snap.Manifest.Index+1)
	}
	if _, err = nodes[0].group.Propose(ready, Entry{ID: model.NewID(), Kind: Data, Payload: []byte("suffix")}); err != nil {
		t.Fatal(err)
	}
	start(2) // the member that was never reachable: only a snapshot can bring it up to date
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		nodes[2].machine.mu.Lock()
		got := len(nodes[2].machine.rows)
		nodes[2].machine.mu.Unlock()
		if got == 151 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	nodes[2].machine.mu.Lock()
	got := len(nodes[2].machine.rows)
	nodes[2].machine.mu.Unlock()
	if got != 151 {
		t.Fatalf("the third member holds %d rows of 151 after the leader's snapshot", got)
	}
	nodes[0].machine.mu.Lock()
	nodes[2].machine.mu.Lock()
	same := fmt.Sprint(nodes[0].machine.rows) == fmt.Sprint(nodes[2].machine.rows)
	nodes[2].machine.mu.Unlock()
	nodes[0].machine.mu.Unlock()
	if !same {
		t.Fatal("the third member's state differs from the leader's")
	}
	records, _, lengths := journalFrames(t, filepath.Join(nodes[2].dir, "raft", "ready.wal"))
	parts := 0
	for i, r := range records {
		if lengths[i] > maxReady() {
			t.Fatalf("record %d of the member's journal is %d B beyond the bound", i, lengths[i])
		}
		if len(r.SnapshotPart) > 0 {
			parts++
		}
	}
	if parts < 2 {
		t.Fatalf("the member's journal holds the leader's snapshot in %d part records", parts)
	}
}
