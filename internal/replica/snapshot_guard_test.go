// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	pb "go.etcd.io/raft/v3/raftpb"

	"github.com/arynyklas/soundpost/internal/model"
)

// openGuarded opens a one-voter group that also lists node 2 as a learner, with a sender-side
// SnapshotGuard (Config.SnapshotGuard) that answers with what the test sets and records which member it
// was asked about.
func openGuarded(t *testing.T, guard func(context.Context, Member) error) (*Group, *captureTransport) {
	t.Helper()
	id, dir := model.NewID(), t.TempDir()
	machine := newLedgerMachine(id, filepath.Join(dir, "machine"))
	if err := os.MkdirAll(machine.dir, 0700); err != nil {
		t.Fatal(err)
	}
	members := soloMembers()
	members.Nodes = append(members.Nodes, Member{ID: 2, Address: "https://learner.invalid", NodeIdentity: "learner-2", FailureDomain: "disk-2", Learner: true})
	transport := &captureTransport{Loopback: NewLoopback()}
	group, err := Open(Config{ID: 1, Group: id, Directory: filepath.Join(dir, "raft"), Transport: transport, Members: members, Machine: machine, SnapshotGuard: guard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { group.Close(); transport.Loopback.Close() })
	return group, transport
}

func (c *captureTransport) snapshots() []*pb.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*pb.Message
	for _, m := range c.sent {
		if m.GetType() == pb.MsgSnap {
			out = append(out, m)
		}
	}
	return out
}

// A snapshot of a state the receiver cannot read is withheld by the SENDER: the guard is asked about the
// member the message is for (with its identity, so the refusal can name it), nothing reaches the
// transport while it refuses, and a snapshot the guard lets through leaves as it always left (no
// erase-gate advertisement: the control machine is not a SnapshotGate, and an older receiver must not refuse it).
func TestSnapshotGuardWithholdsTheSnapshotFromAMemberItRefuses(t *testing.T) {
	var mu sync.Mutex
	var asked []Member
	refuse := errors.New("layout_incompatible:learner-2")
	var verdict error = refuse
	group, transport := openGuarded(t, func(_ context.Context, to Member) error {
		mu.Lock()
		defer mu.Unlock()
		asked = append(asked, to)
		return verdict
	})
	send := func() {
		group.mu.Lock()
		group.sendGatedSnapshot(&pb.Message{Type: pb.MsgSnap.Enum(), To: new(uint64(2)), From: new(uint64(1))})
		group.mu.Unlock()
		group.gateWG.Wait()
	}
	send()
	if n := len(transport.snapshots()); n != 0 {
		t.Fatalf("a snapshot reached the transport although the guard refused: %d", n)
	}
	mu.Lock()
	if len(asked) != 1 || asked[0].ID != 2 || asked[0].NodeIdentity != "learner-2" || asked[0].Address != "https://learner.invalid" {
		t.Fatalf("the guard was asked about %+v, want the learner with its identity and address", asked)
	}
	verdict = nil
	mu.Unlock()
	send()
	snaps := transport.snapshots()
	if len(snaps) != 1 {
		t.Fatalf("%d snapshots sent after the guard let it through, want 1", len(snaps))
	}
	if _, framed := gateToken(snaps[0].GetContext()); framed {
		t.Fatalf("a guard-only group advertised the erase gate: %q", snaps[0].GetContext())
	}
}

// A snapshot for a node the group does not list is never sent (fail closed: the guard cannot name it).
func TestSnapshotGuardRefusesANodeTheGroupDoesNotList(t *testing.T) {
	group, transport := openGuarded(t, func(context.Context, Member) error { return nil })
	group.mu.Lock()
	group.sendGatedSnapshot(&pb.Message{Type: pb.MsgSnap.Enum(), To: new(uint64(9)), From: new(uint64(1))})
	group.mu.Unlock()
	group.gateWG.Wait()
	if n := len(transport.snapshots()); n != 0 {
		t.Fatalf("a snapshot was sent to a node outside the configuration: %d", n)
	}
}
