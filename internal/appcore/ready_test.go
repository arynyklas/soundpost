// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	pb "go.etcd.io/raft/v3/raftpb"
)

// lateWire delivers between three in-process groups, but only once opened. Until
// then every send fails the way an unreachable peer does.
type lateWire struct {
	mu     sync.Mutex
	open   bool
	groups map[uint64]*replica.Group
}

func (w *lateWire) Send(_ model.ID, m *pb.Message) error {
	w.mu.Lock()
	destination, up := w.groups[m.GetTo()], w.open
	w.mu.Unlock()
	if !up || destination == nil {
		return replica.ErrUnavailable
	}
	go func() { _ = destination.Step(context.Background(), m) }()
	return nil
}
func (w *lateWire) openAfter(delay time.Duration) {
	time.AfterFunc(delay, func() { w.mu.Lock(); w.open = true; w.mu.Unlock() })
}

type emptyMachine struct {
	mu      sync.Mutex
	applied uint64
}

func (m *emptyMachine) Applied() uint64 { m.mu.Lock(); defer m.mu.Unlock(); return m.applied }
func (m *emptyMachine) Apply(c replica.CommittedEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applied = c.Index
	return nil
}
func (m *emptyMachine) Snapshot() ([]byte, error)    { return []byte("{}"), nil }
func (m *emptyMachine) Restore([]byte, uint64) error { return nil }

func threeVoters(t *testing.T, wire *lateWire) []*replica.Group {
	t.Helper()
	id := model.NewID()
	members := replica.Members{Revision: 1}
	for node := uint64(1); node <= 3; node++ {
		suffix := string(rune('0' + node))
		members.Nodes = append(members.Nodes, replica.Member{ID: node, Address: "https://node" + suffix + ".invalid", NodeIdentity: "node-" + suffix, FailureDomain: "disk-" + suffix})
	}
	wire.groups = map[uint64]*replica.Group{}
	var groups []*replica.Group
	for node := uint64(1); node <= 3; node++ {
		g, err := replica.Open(replica.Config{ID: node, Group: id, Directory: filepath.Join(t.TempDir(), "raft"), Members: members, Machine: &emptyMachine{}, Transport: wire, TickInterval: 20 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { g.Close() })
		wire.groups[node] = g
		groups = append(groups, g)
	}
	return groups
}

// A peer that is still starting must not fail startup at the first group's
// five-second freshness window while the startup budget remains: the node waits
// for the quorum round, and only then opens intake.
func TestStartupWaitsForLatePeersWithinItsBudget(t *testing.T) {
	wire := &lateWire{}
	groups := threeVoters(t, wire)
	wire.openAfter(6 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	started := time.Now()
	if err := awaitReady(ctx, groups[0]); err != nil {
		t.Fatalf("a peer that came up after %v failed startup: %v", time.Since(started).Round(time.Second), err)
	}
	if time.Since(started) < 5*time.Second {
		t.Fatal("the group was ready before any peer could answer")
	}
}

// The startup budget still bounds the wait: without a quorum the node does not
// open intake, it fails once its own budget is spent.
func TestStartupWithoutQuorumFailsWhenItsBudgetIsSpent(t *testing.T) {
	groups := threeVoters(t, &lateWire{})
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := awaitReady(ctx, groups[0])
	if !errors.Is(err, replica.ErrStale) {
		t.Fatalf("a node without quorum reported %v instead of failing its freshness fence", err)
	}
	if elapsed := time.Since(started); elapsed < time.Second || elapsed > 4*time.Second {
		t.Fatalf("startup failed after %v, not at its 1.5s budget", elapsed)
	}
}

// A failed or closed group is final; waiting out the budget would only delay the
// failure.
func TestStartupFailsFastOnAClosedGroup(t *testing.T) {
	groups := threeVoters(t, &lateWire{})
	groups[0].Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	started := time.Now()
	if err := awaitReady(ctx, groups[0]); !errors.Is(err, replica.ErrUnavailable) {
		t.Fatalf("closed group: %v", err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("a closed group was retried instead of reported")
	}
}
