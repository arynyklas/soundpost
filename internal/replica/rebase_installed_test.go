// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// A disaster restore installs a snapshot cut in a three-voter cluster into the directory of a new
// group with other members. Without Config.RebaseInstalled the fresh journal keeps the snapshot's
// Raft configuration (voters 1, 2, 3) and a one-voter group can never elect; with it the group
// takes the members it was configured with, serves the installed state, accepts new writes and
// keeps its membership across a restart. The flag is explicit: nothing else rebases.
func TestRebaseInstalledStartsAFreshJournalFromAForeignClusterSnapshot(t *testing.T) {
	id := model.NewID()
	wire := &testWire{nodes: map[uint64]*Group{}, blocked: map[uint64]bool{}}
	members := Members{Revision: 1, Nodes: []Member{{ID: 1, Address: "https://node1.invalid", FailureDomain: "disk-a", NodeIdentity: "node-1"}, {ID: 2, Address: "https://node2.invalid", FailureDomain: "disk-b", NodeIdentity: "node-2"}, {ID: 3, Address: "https://node3.invalid", FailureDomain: "disk-c", NodeIdentity: "node-3"}}}
	for node := uint64(1); node <= 3; node++ {
		dir := t.TempDir()
		g, err := Open(Config{ID: node, Group: id, Directory: filepath.Join(dir, "raft"), Members: members, Machine: newLedgerMachine(id, filepath.Join(dir, "machine")), Transport: wire})
		if err != nil {
			t.Fatal(err)
		}
		wire.nodes[node] = g
		t.Cleanup(func() { g.Close() })
	}
	if err := wire.nodes[1].Campaign(); err != nil {
		t.Fatal(err)
	}
	wire.pump(t)
	for i := range 5 {
		if _, err := testPropose(t, wire, 1, Entry{ID: model.NewID(), Kind: Data, Payload: []byte(fmt.Sprintf("row-%d", i))}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := testPropose(t, wire, 1, Entry{ID: model.NewID(), Kind: Barrier, Payload: []byte("tombstone")}); err != nil {
		t.Fatal(err)
	}
	var snap Snapshot
	if err := testAwait(t, wire, func(ctx context.Context) error {
		var err error
		snap, err = wire.nodes[2].CreateSnapshot(ctx, model.Cursor{Group: id, Index: wire.nodes[2].Status().ApplicationCursor.Index})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	foreign := stream(t, snap)

	install := func(t *testing.T) string {
		raft := filepath.Join(t.TempDir(), "raft")
		store, err := OpenSnapshotStore(raft, id, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = store.InstallSnapshot(context.Background(), snap.Manifest, bytes.NewReader(foreign)); err != nil {
			t.Fatal(err)
		}
		return raft
	}
	open := func(t *testing.T, raft string, rebase bool) (*Group, *ledgerMachine, *Loopback) {
		machine := newLedgerMachine(id, filepath.Join(filepath.Dir(raft), "machine"))
		transport := NewLoopback()
		g, err := Open(Config{ID: 1, Group: id, Directory: raft, Transport: transport, Members: soloMembers(), Machine: machine, RebaseInstalled: rebase})
		if err != nil {
			transport.Close()
			t.Fatal(err)
		}
		if err = transport.Register(g); err == nil {
			err = g.Campaign()
		}
		if err != nil {
			g.Close()
			transport.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { g.Close(); transport.Close() })
		return g, machine, transport
	}
	propose := func(g *Group, wait time.Duration) error {
		ctx, cancel := context.WithTimeout(context.Background(), wait)
		defer cancel()
		_, err := g.Propose(ctx, Entry{ID: model.NewID(), Kind: Data, Payload: []byte("after restore")})
		return err
	}

	t.Run("without the flag the foreign configuration keeps a one-voter group from electing", func(t *testing.T) {
		g, _, _ := open(t, install(t), false)
		if err := propose(g, 3*time.Second); err == nil {
			t.Fatal("a one-voter group started from a three-voter configuration elected itself")
		}
	})
	t.Run("with the flag the group takes its configured membership", func(t *testing.T) {
		raft := install(t)
		g, machine, _ := open(t, raft, true)
		if err := propose(g, 20*time.Second); err != nil {
			t.Fatalf("a rebased group does not accept writes: %v", err)
		}
		if len(machine.rows) != 7 || len(machine.fences) != 1 {
			t.Fatalf("the installed state is not served: %d rows, %d fences", len(machine.rows), len(machine.fences))
		}
		status := g.Status()
		if len(status.Members.Nodes) != 1 || status.Members.Nodes[0].NodeIdentity != "single" {
			t.Fatalf("the group still names the source cluster: %+v", status.Members)
		}
		g.Close()
		again, _, _ := open(t, raft, true)
		if err := propose(again, 20*time.Second); err != nil {
			t.Fatalf("the rebased group does not restart: %v", err)
		}
	})
}
