// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// A replacement voter is a fresh learner added with a new member id after the
// leaders already truncated their journals to a snapshot that predates it. Raft
// refuses to restore any snapshot whose configuration does not contain the
// recipient, so the leader must offer a snapshot cut with the current
// configuration or the learner can never be repaired (it ignored every snapshot
// forever, and a replacement voter could not join).
func TestSnapshotRepairsFreshLearnerAddedAfterTruncation(t *testing.T) {
	id := model.NewID()
	wire := &testWire{nodes: map[uint64]*Group{}, blocked: map[uint64]bool{}}
	members := Members{Revision: 1, Nodes: []Member{{ID: 1, Address: "https://node1.invalid", FailureDomain: "disk-a", NodeIdentity: "node-1"}, {ID: 2, Address: "https://node2.invalid", FailureDomain: "disk-b", NodeIdentity: "node-2"}, {ID: 3, Address: "https://node3.invalid", FailureDomain: "disk-c", NodeIdentity: "node-3"}}}
	machines := map[uint64]*ledgerMachine{}
	open := func(node uint64, m Members) {
		dir := t.TempDir()
		machines[node] = newLedgerMachine(id, filepath.Join(dir, "machine"))
		g, err := Open(Config{ID: node, Group: id, Directory: filepath.Join(dir, "raft"), Members: m, Machine: machines[node], Transport: wire})
		if err != nil {
			t.Fatal(err)
		}
		wire.mu.Lock()
		wire.nodes[node] = g
		wire.mu.Unlock()
		t.Cleanup(func() { g.Close() })
	}
	for node := uint64(1); node <= 3; node++ {
		open(node, members)
	}
	if err := wire.nodes[1].Campaign(); err != nil {
		t.Fatal(err)
	}
	wire.pump(t)
	acked := map[model.ID]CommittedEntry{}
	entries := map[model.ID]Entry{}
	put := func(kind Kind, payload string) {
		e := Entry{ID: model.NewID(), Kind: kind, Payload: []byte(payload)}
		c, err := testPropose(t, wire, 1, e)
		if err != nil {
			t.Fatal(err)
		}
		acked[e.ID], entries[e.ID] = c, e
	}
	for i := range 12 {
		put(Data, fmt.Sprintf("row-%d", i))
	}
	put(Barrier, "tombstone")
	var snap Snapshot
	if err := testAwait(t, wire, func(ctx context.Context) error {
		var err error
		snap, err = wire.nodes[1].CreateSnapshot(ctx, model.Cursor{Group: id, Index: wire.nodes[1].Status().ApplicationCursor.Index})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := wire.nodes[1].CompactJournal(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		put(Data, fmt.Sprintf("suffix-%d", i))
	}
	if first, _ := wire.nodes[1].JournalRange(); first != snap.Manifest.Index+1 {
		t.Fatalf("leader journal not truncated to the cut: first=%d cut=%d", first, snap.Manifest.Index)
	}

	// The replacement joins as a learner under a new id.
	learnerMembers := Members{Revision: 2, Nodes: append(append([]Member(nil), members.Nodes...), Member{ID: 4, Address: "https://node4.invalid", FailureDomain: "disk-d", NodeIdentity: "node-4", Learner: true})}
	open(4, learnerMembers)
	if err := testAwait(t, wire, func(ctx context.Context) error { return wire.nodes[1].ChangeMembers(ctx, 1, learnerMembers) }); err != nil {
		t.Fatal(err)
	}
	for range 3000 {
		wire.nodes[1].Tick()
		wire.pump(t)
		if len(machines[4].rows) == len(acked) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(machines[4].rows) != len(acked) {
		t.Fatalf("fresh learner was not repaired from a snapshot: %d of %d entries", len(machines[4].rows), len(acked))
	}
	if len(machines[4].fences) != 1 {
		t.Fatal("tombstone missing on the repaired learner")
	}
	if first, _ := wire.nodes[4].JournalRange(); first <= 2 {
		t.Fatalf("the learner's journal starts at %d: it replayed history instead of installing a snapshot", first)
	}
	// Everything ACKed before the repair still resolves to its original receipt.
	for eid, original := range acked {
		retry, err := testPropose(t, wire, 1, entries[eid])
		if err != nil || retry.Index != original.Index {
			t.Fatalf("retry changed the original receipt: %v", err)
		}
	}
}
