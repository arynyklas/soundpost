// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	pb "go.etcd.io/raft/v3/raftpb"
)

type testWire struct {
	mu      sync.Mutex
	nodes   map[uint64]*Group
	queue   []*pb.Message
	blocked map[uint64]bool
}

func (w *testWire) Send(_ model.ID, m *pb.Message) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.blocked[m.GetFrom()] && !w.blocked[m.GetTo()] {
		w.queue = append(w.queue, m)
	}
	return nil
}
func (w *testWire) block(id uint64) { w.mu.Lock(); defer w.mu.Unlock(); w.blocked[id] = true }
func (w *testWire) pump(t *testing.T) {
	t.Helper()
	for range 10000 {
		w.mu.Lock()
		if len(w.queue) == 0 {
			w.mu.Unlock()
			return
		}
		message := w.queue[0]
		w.queue = w.queue[1:]
		g := w.nodes[message.GetTo()]
		blocked := w.blocked[message.GetFrom()] || w.blocked[message.GetTo()]
		w.mu.Unlock()
		if g != nil && !blocked {
			if err := g.Step(context.Background(), message); err != nil && !errors.Is(err, ErrUnavailable) {
				t.Fatal(err)
			}
		}
	}
	t.Fatal("transport did not settle")
}

type testMachine struct {
	mu      sync.Mutex
	applied uint64
	rows    map[string]string
}

func (m *testMachine) Applied() uint64 { m.mu.Lock(); defer m.mu.Unlock(); return m.applied }
func (m *testMachine) Apply(c CommittedEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.Index <= m.applied {
		return nil
	}
	if c.Entry.Kind != Noop {
		m.rows[c.Entry.ID.String()] = string(c.Entry.Payload)
	}
	m.applied = c.Index
	return nil
}
func (m *testMachine) Snapshot() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return json.Marshal(m.rows)
}
func (m *testMachine) Restore(raw []byte, index uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := json.Unmarshal(raw, &m.rows); err != nil {
		return err
	}
	m.applied = index
	return nil
}
func testCluster(t *testing.T) (*testWire, model.ID, []*testMachine) {
	t.Helper()
	id := model.NewID()
	wire := &testWire{nodes: map[uint64]*Group{}, blocked: map[uint64]bool{}}
	machines := make([]*testMachine, 3)
	members := Members{Revision: 1, Nodes: []Member{{ID: 1, Address: "https://node1.invalid", FailureDomain: "disk-a", NodeIdentity: "node-1"}, {ID: 2, Address: "https://node2.invalid", FailureDomain: "disk-b", NodeIdentity: "node-2"}, {ID: 3, Address: "https://node3.invalid", FailureDomain: "disk-c", NodeIdentity: "node-3"}}}
	for i := range machines {
		machines[i] = &testMachine{rows: map[string]string{}}
		g, err := Open(Config{ID: uint64(i + 1), Group: id, Directory: t.TempDir(), Members: members, Machine: machines[i], Transport: wire})
		if err != nil {
			t.Fatal(err)
		}
		wire.nodes[uint64(i+1)] = g
		t.Cleanup(func() { g.Close() })
	}
	if err := wire.nodes[1].Campaign(); err != nil {
		t.Fatal(err)
	}
	wire.pump(t)
	return wire, id, machines
}
func testAwait(t *testing.T, wire *testWire, fn func(context.Context) error) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- fn(ctx) }()
	for range 2100 {
		wire.pump(t)
		select {
		case err := <-done:
			return err
		default:
			time.Sleep(time.Millisecond)
		}
	}
	t.Fatal("operation stalled")
	return nil
}
func testPropose(t *testing.T, wire *testWire, node uint64, entry Entry) (CommittedEntry, error) {
	t.Helper()
	var committed CommittedEntry
	err := testAwait(t, wire, func(ctx context.Context) error {
		var e error
		committed, e = wire.nodes[node].Propose(ctx, entry)
		return e
	})
	return committed, err
}

// Removing Ready fsync or counting an unsynced follower response must break this.
func TestMajorityMeansDurableNotReceived(t *testing.T) {
	t.Run("unsynced receipt cannot vote", func(t *testing.T) {
		wire, _, machines := testCluster(t)
		wire.block(3)
		wire.nodes[2].disk.beforeSync = func() error { return errors.New("injected disk sync failure") }
		reservation := model.NewID()
		entry := Entry{ID: model.NewID(), Kind: Data, Payload: []byte("durable-value"), ReservationID: &reservation}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
		defer cancel()
		done := make(chan error, 1)
		go func() { _, err := wire.nodes[1].Propose(ctx, entry); done <- err }()
		for range 30 {
			wire.pump(t)
			time.Sleep(time.Millisecond)
		}
		if err := <-done; err == nil {
			t.Fatal("minority acknowledged")
		}
		if machines[0].Applied() > wire.nodes[1].Status().Commit {
			t.Fatal("applied beyond commit")
		}
		// Failing closed is asserted without a fixed delivery window: under CPU
		// contention node 2 may not have processed the append within the first
		// 30 ms, but it must fail closed once it does. The acknowledgement
		// assertions above are unconditional.
		failedClosed := false
		for range 2000 {
			if wire.nodes[2].Status().Failed {
				failedClosed = true
				break
			}
			wire.pump(t)
			time.Sleep(time.Millisecond)
		}
		if !failedClosed {
			t.Fatal("sync failure did not fail closed")
		}
	})
	for _, lost := range []uint64{1, 2} {
		t.Run(string(rune('0'+lost)), func(t *testing.T) {
			wire, _, machines := testCluster(t)
			// The third voter cannot receive this batch: the ACK has exactly two copies.
			wire.block(3)
			entry := Entry{ID: model.NewID(), Kind: Data, Payload: []byte("retained after acknowledged copy loss")}
			original, err := testPropose(t, wire, 1, entry)
			if err != nil {
				t.Fatal(err)
			}
			wire.block(lost)
			if err = wire.nodes[lost].Close(); err != nil {
				t.Fatal(err)
			}
			wire.mu.Lock()
			delete(wire.blocked, 3)
			wire.mu.Unlock()
			candidate := uint64(1)
			if lost == 1 {
				candidate = 2
			}
			if err = wire.nodes[candidate].Campaign(); err != nil {
				t.Fatal(err)
			}
			for range 30 {
				for _, id := range []uint64{1, 2, 3} {
					if id != lost {
						wire.nodes[id].Tick()
						wire.pump(t)
					}
				}
			}
			leader := uint64(0)
			for id, g := range wire.nodes {
				if id != lost && g.Status().Leader == id {
					leader = id
				}
			}
			if leader == 0 {
				t.Fatal("remaining quorum failed to elect")
			}
			retry, err := testPropose(t, wire, leader, entry)
			if err != nil {
				t.Fatal(err)
			}
			if retry.Index != original.Index || retry.Term != original.Term {
				t.Fatal("original commit changed after copy loss")
			}
			machines[leader-1].mu.Lock()
			got := machines[leader-1].rows[entry.ID.String()]
			machines[leader-1].mu.Unlock()
			if got != "retained after acknowledged copy loss" {
				t.Fatal("acknowledged value lost")
			}
		})
	}
}
func TestPartitionedLeaderCannotPublishOrSend(t *testing.T) {
	wire, _, _ := testCluster(t)
	var token FenceToken
	if err := testAwait(t, wire, func(ctx context.Context) error { var err error; token, err = wire.nodes[1].Fence(ctx); return err }); err != nil {
		t.Fatal(err)
	}
	wire.block(1)
	for range 30 {
		for _, id := range []uint64{1, 2, 3} {
			wire.nodes[id].Tick()
			wire.pump(t)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := wire.nodes[1].ValidateFence(ctx, token); err == nil {
		t.Fatal("partitioned lease authorized external effect")
	}
	if _, err := testPropose(t, wire, 1, Entry{ID: model.NewID(), Kind: Control, Payload: []byte("publish")}); err == nil {
		t.Fatal("partitioned leader published")
	}
}
func TestReadYourReceiptWaitsForApply(t *testing.T) {
	wire, id, machines := testCluster(t)
	committed, err := testPropose(t, wire, 1, Entry{ID: model.NewID(), Kind: Data, Payload: []byte("value")})
	if err != nil {
		t.Fatal(err)
	}
	wire.block(3)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err = wire.nodes[3].WaitApplied(ctx, model.Cursor{Group: id, Index: committed.ApplicationCursor.Index + 100}); err == nil {
		t.Fatal("lagging cursor reported absence instead of freshness failure")
	}
	if machines[0].Applied() < committed.Index {
		t.Fatal("receipt before apply")
	}
}
func TestReassignmentKeepsDedupAndScope(t *testing.T) {
	wire, id, _ := testCluster(t)
	reservation := model.NewID()
	entry := Entry{ID: model.NewID(), Kind: Data, Payload: []byte("opaque authorized leaf payload"), ReservationID: &reservation}
	original, err := testPropose(t, wire, 1, entry)
	if err != nil {
		t.Fatal(err)
	}
	wire.block(1)
	for range 30 {
		wire.nodes[2].Tick()
		wire.pump(t)
		wire.nodes[3].Tick()
		wire.pump(t)
	}
	leader := uint64(0)
	for _, n := range []uint64{2, 3} {
		if wire.nodes[n].Status().Leader == n {
			leader = n
		}
	}
	if leader == 0 {
		t.Fatal("no replacement leader")
	}
	retry, err := testPropose(t, wire, leader, entry)
	if err != nil {
		t.Fatal(err)
	}
	if original.Index != retry.Index || original.Term != retry.Term || retry.ApplicationCursor != original.ApplicationCursor || string(retry.Entry.Payload) != string(entry.Payload) {
		t.Fatal("relocation changed original committed identity")
	}
	if retry.Group != id {
		t.Fatal("routing group changed")
	}
	slot, err := SlotGroup(id, 63)
	if err != nil || slot == (model.ID{}) {
		t.Fatal("stable slot mapping missing")
	}
	if _, err = SlotGroup(id, 64); err == nil {
		t.Fatal("invalid slot accepted")
	}
}
func TestCommitSetWatermarkRefusesKnownReservation(t *testing.T) {
	wire, _, _ := testCluster(t)
	reservation := model.NewID()
	_, err := testPropose(t, wire, 1, Entry{ID: model.NewID(), Kind: Data, Payload: []byte("value"), ReservationID: &reservation})
	if err != nil {
		t.Fatal(err)
	}
	err = testAwait(t, wire, func(ctx context.Context) error { _, err := wire.nodes[1].Absent(ctx, reservation); return err })
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("committed reservation absence proof: %v", err)
	}
}
func TestFailureDomainsAndReadiness(t *testing.T) {
	members := Members{Revision: 1, Nodes: []Member{{ID: 1, Address: "https://a.invalid", FailureDomain: "same", NodeIdentity: "a"}, {ID: 2, Address: "https://b.invalid", FailureDomain: "same", NodeIdentity: "b"}, {ID: 3, Address: "https://c.invalid", FailureDomain: "different", NodeIdentity: "c"}}}
	if err := ValidateMembers(members); err == nil {
		t.Fatal("shared failure domain claimed HA")
	}
}
