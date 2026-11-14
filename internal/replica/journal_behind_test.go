// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	raft "go.etcd.io/raft/v3"
	pb "go.etcd.io/raft/v3/raftpb"
)

// A journal that holds less than its own persisted commit (a rolled-back or replaced disk) must be
// refused with a typed error before raft starts: raft itself panics on such a state.
func TestAJournalShorterThanItsCommitIsRefusedBeforeRaftStarts(t *testing.T) {
	dir, group := t.TempDir(), model.NewID()
	w, _, err := openReadyWAL(dir, group, 1, soloMembers(), []byte("seed"), 0, 1, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The journal commits index 9 while it ends at index 1.
	if err = w.persist(raft.Ready{HardState: &pb.HardState{Term: new(uint64(1)), Commit: new(uint64(9))}}); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	transport := NewLoopback()
	defer transport.Close()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("raft panicked instead of a typed refusal: %v", r)
		}
	}()
	_, err = Open(Config{ID: 1, Group: group, Directory: dir, Members: soloMembers(), Machine: &testMachine{rows: map[string]string{}}, Transport: transport})
	if !errors.Is(err, ErrJournalBehind) {
		t.Fatalf("Open on a journal shorter than its commit = %v, want ErrJournalBehind", err)
	}
}

// A leader that commits beyond the end of this node's journal proves the node acknowledged more
// than it holds. That is a typed fail-stop of the whole node, never a panic in the serving goroutine.
func TestAHeartbeatCommittingBeyondTheJournalFailStopsTheNodeWithATypedReason(t *testing.T) {
	n := testNodes(t, 2, true)
	a, b := n.ids[0], n.ids[1]
	g := n.wire.groups[a][2]
	heartbeat := &pb.Message{Type: pb.MsgHeartbeat.Enum(), From: new(uint64(1)), To: new(uint64(2)), Term: new(g.Status().Term), Commit: new(uint64(1 << 20))}
	err := g.Step(context.Background(), heartbeat)
	if !errors.Is(err, ErrJournalBehind) {
		t.Fatalf("Step = %v, want ErrJournalBehind", err)
	}
	select {
	case <-n.domains[2].Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the node was not failed closed")
	}
	failure, ok := n.domains[2].Failure()
	if !ok || failure.Group != a || failure.Reason != FailBehind || string(failure.Reason) != ReasonJournalBehind {
		t.Fatalf("domain failure = %+v (%v), want group A, %s", failure, ok, FailBehind)
	}
	if !g.Status().Failed {
		t.Fatal("the group that was committed beyond its journal still serves")
	}
	if _, ok := n.domains[1].Failure(); ok {
		t.Fatal("the leader's node failed with it")
	}
	_ = b
	// What the node reports afterwards, e.g. a startup read of another group answering unavailable because the
	// whole node failed closed, is the journal-behind refusal, not the symptom.
	if got := n.domains[2].Cause(ErrUnavailable); !errors.Is(got, ErrJournalBehind) {
		t.Fatalf("Cause(unavailable) after a journal-behind fail-stop = %v, want ErrJournalBehind", got)
	}
	if got := n.domains[1].Cause(ErrUnavailable); got != ErrUnavailable {
		t.Fatalf("a healthy domain rewrote an unrelated error: %v", got)
	}
}

// A group without a FailDomain has no node to stop with it: FailStop is a no-op for it.
func TestFailStopWithoutADomainDoesNothing(t *testing.T) {
	n := testNodes(t, 1, false)
	g := n.wire.groups[n.ids[0]][1]
	g.FailStop(FailEngine)
	if g.Status().Failed {
		t.Fatal("FailStop failed a group that has no domain")
	}
}
