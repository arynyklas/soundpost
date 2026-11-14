// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	pb "go.etcd.io/raft/v3/raftpb"
)

// groupWire carries the messages of several groups between three nodes, one queue for all.
type groupWire struct {
	mu     sync.Mutex
	groups map[model.ID]map[uint64]*Group
	queue  []groupMessage
}
type groupMessage struct {
	group model.ID
	m     *pb.Message
}

func (w *groupWire) Send(group model.ID, m *pb.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.queue = append(w.queue, groupMessage{group: group, m: m})
	return nil
}
func (w *groupWire) pump(t *testing.T) {
	t.Helper()
	for range 20000 {
		w.mu.Lock()
		if len(w.queue) == 0 {
			w.mu.Unlock()
			return
		}
		next := w.queue[0]
		w.queue = w.queue[1:]
		g := w.groups[next.group][next.m.GetTo()]
		w.mu.Unlock()
		if g != nil {
			if err := g.Step(context.Background(), next.m); err != nil && !errors.Is(err, ErrUnavailable) {
				t.Fatal(err)
			}
		}
	}
	t.Fatal("transport did not settle")
}

// tickRound ticks every group of every node once and delivers everything that results.
func (w *groupWire) tickRound(t *testing.T) {
	t.Helper()
	for _, nodes := range w.groups {
		for _, g := range nodes {
			g.Tick()
		}
	}
	w.pump(t)
}

type nodeGroups struct {
	wire    *groupWire
	ids     []model.ID
	domains map[uint64]*FailDomain
}

// testNodes opens `count` groups on each of three nodes. Every node's groups share one FailDomain
// when shared is true (the production wiring), none otherwise. Node 1 leads all groups.
func testNodes(t *testing.T, count int, shared bool) *nodeGroups {
	t.Helper()
	members := Members{Revision: 1, Nodes: []Member{{ID: 1, Address: "https://node1.invalid", FailureDomain: "disk-a", NodeIdentity: "node-1"}, {ID: 2, Address: "https://node2.invalid", FailureDomain: "disk-b", NodeIdentity: "node-2"}, {ID: 3, Address: "https://node3.invalid", FailureDomain: "disk-c", NodeIdentity: "node-3"}}}
	n := &nodeGroups{wire: &groupWire{groups: map[model.ID]map[uint64]*Group{}}, domains: map[uint64]*FailDomain{}}
	for node := uint64(1); node <= 3; node++ {
		if shared {
			n.domains[node] = NewFailDomain()
		}
	}
	for range count {
		id := model.NewID()
		n.ids = append(n.ids, id)
		n.wire.groups[id] = map[uint64]*Group{}
		for node := uint64(1); node <= 3; node++ {
			g, err := Open(Config{ID: node, Group: id, Directory: t.TempDir(), Members: members, Machine: &testMachine{rows: map[string]string{}}, Transport: n.wire, Domain: n.domains[node]})
			if err != nil {
				t.Fatal(err)
			}
			n.wire.groups[id][node] = g
			t.Cleanup(func() { g.Close() })
		}
	}
	for _, id := range n.ids {
		if err := n.wire.groups[id][1].Campaign(); err != nil {
			t.Fatal(err)
		}
	}
	n.wire.pump(t)
	return n
}

// propose runs one proposal on the node's group while delivering the messages it needs.
func (n *nodeGroups) propose(t *testing.T, group model.ID, node uint64, payload string) error {
	t.Helper()
	g := n.wire.groups[group][node]
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := g.Propose(ctx, Entry{ID: model.NewID(), Kind: Data, Payload: []byte(payload)})
		done <- err
	}()
	for range 3100 {
		n.wire.pump(t)
		select {
		case err := <-done:
			return err
		default:
			time.Sleep(time.Millisecond)
		}
	}
	t.Fatal("proposal stalled")
	return nil
}

// leaderOf is the node that leads the group (per a node that is not failed), 0 while none does.
func (n *nodeGroups) leaderOf(group model.ID) uint64 {
	for node := uint64(1); node <= 3; node++ {
		if s := n.wire.groups[group][node].Status(); !s.Failed && s.Leader == node {
			return node
		}
	}
	return 0
}

// A node whose storage failed in one group must not keep leading the others. Without the shared
// domain node 1 stays leader of group B (heartbeats keep both voters from ever campaigning)
// although it can persist nothing, so B has no leader that can commit.
func TestAStorageFailureInOneGroupFailStopsEveryGroupOfTheNode(t *testing.T) {
	n := testNodes(t, 2, true)
	a, b := n.ids[0], n.ids[1]
	for _, g := range []model.ID{a, b} {
		if err := n.propose(t, g, 1, "before the failure"); err != nil {
			t.Fatalf("group %s: baseline proposal: %v", g, err)
		}
	}
	// Node 1's disk stops syncing: the first group that writes notices.
	n.wire.groups[a][1].disk.beforeSync = func() error { return errors.New("injected EIO on fsync") }
	if err := n.propose(t, a, 1, "the write that fails"); err == nil {
		t.Fatal("a proposal whose journal could not be synced was acknowledged")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !n.wire.groups[b][1].Status().Failed {
		if time.Now().After(deadline) {
			t.Fatal("group B of the node whose storage failed is still serving: it keeps its leadership although it can persist nothing")
		}
		time.Sleep(5 * time.Millisecond)
	}
	failure, ok := n.domains[1].Failure()
	if !ok || failure.Group != a || failure.Reason != FailJournal {
		t.Fatalf("domain failure = %+v (%v), want group A, %s", failure, ok, FailJournal)
	}
	select {
	case <-n.domains[1].Done():
	default:
		t.Fatal("the domain of the failed node is not reported done")
	}
	if _, ok := n.domains[2].Failure(); ok {
		t.Fatal("a healthy node's domain failed with it")
	}
	// The two healthy voters elect a leader in B among themselves and commit through it.
	for round := 0; n.leaderOf(b) == 0; round++ {
		if round > 60 {
			t.Fatal("the surviving voters of group B never elected a leader")
		}
		n.wire.tickRound(t)
	}
	leader := n.leaderOf(b)
	if leader == 1 {
		t.Fatal("the failed node still leads group B")
	}
	if err := n.propose(t, b, leader, "after the failure"); err != nil {
		t.Fatalf("the survivors cannot commit in group B: %v", err)
	}
}

// Groups of different nodes never share a fate, and a group without a domain fails alone.
func TestFailDomainIsPerNodeAndOptional(t *testing.T) {
	n := testNodes(t, 2, false)
	a, b := n.ids[0], n.ids[1]
	n.wire.groups[a][1].disk.beforeSync = func() error { return errors.New("injected EIO on fsync") }
	if err := n.propose(t, a, 1, "the write that fails"); err == nil {
		t.Fatal("a proposal whose journal could not be synced was acknowledged")
	}
	if !n.wire.groups[a][1].Status().Failed {
		t.Fatal("the group that could not sync did not fail closed")
	}
	time.Sleep(50 * time.Millisecond)
	if n.wire.groups[b][1].Status().Failed {
		t.Fatal("a group without a domain was failed by another group")
	}
}

// A domain that failed admits no new group, so a node cannot reopen a group on failed storage.
func TestAFailedDomainAdmitsNoNewGroup(t *testing.T) {
	n := testNodes(t, 1, true)
	n.wire.groups[n.ids[0]][1].FailStop(FailEngine)
	select {
	case <-n.domains[1].Done():
	case <-time.After(2 * time.Second):
		t.Fatal("FailStop did not fail the domain")
	}
	members := Members{Revision: 1, Nodes: []Member{{ID: 1, Address: "https://node1.invalid", FailureDomain: "disk-a", NodeIdentity: "node-1"}, {ID: 2, Address: "https://node2.invalid", FailureDomain: "disk-b", NodeIdentity: "node-2"}, {ID: 3, Address: "https://node3.invalid", FailureDomain: "disk-c", NodeIdentity: "node-3"}}}
	_, err := Open(Config{ID: 1, Group: model.NewID(), Directory: t.TempDir(), Members: members, Machine: &testMachine{rows: map[string]string{}}, Transport: n.wire, Domain: n.domains[1]})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Open on a failed domain = %v, want ErrUnavailable", err)
	}
}
