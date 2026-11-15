// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	pb "go.etcd.io/raft/v3/raftpb"
)

type voterWire struct {
	mu     sync.Mutex
	groups map[uint64]*replica.Group
}

func (w *voterWire) Send(_ model.ID, m *pb.Message) error {
	w.mu.Lock()
	to := w.groups[m.GetTo()]
	w.mu.Unlock()
	if to == nil {
		return replica.ErrUnavailable
	}
	go func() { _ = to.Step(context.Background(), m) }()
	return nil
}

type voterMachine struct {
	mu      sync.Mutex
	applied uint64
}

func (m *voterMachine) Applied() uint64 { m.mu.Lock(); defer m.mu.Unlock(); return m.applied }
func (m *voterMachine) Apply(c replica.CommittedEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applied = c.Index
	return nil
}
func (m *voterMachine) Snapshot() ([]byte, error)    { return []byte("{}"), nil }
func (m *voterMachine) Restore([]byte, uint64) error { return nil }

// electedFence is the fence of one node of a real three-voter group: it holds
// the fence only while that voter leads the voters' group, and then acts with
// the application's own control lease.
type electedFence struct {
	id    uint64
	voter *replica.Group
	inner appcore.LeaderFence
}

func (f electedFence) Fence(ctx context.Context) (replica.FenceToken, error) {
	if _, err := f.voter.Fence(ctx); err != nil {
		return replica.FenceToken{}, err
	}
	return f.inner.Fence(ctx)
}

func (f electedFence) ValidateFence(ctx context.Context, t replica.FenceToken) error {
	if f.voter.Status().Leader != f.id {
		return replica.ErrStale
	}
	return f.inner.ValidateFence(ctx, t)
}

type failingProducer struct{}

func (failingProducer) Produce(context.Context, appcore.ProducerScopes, replica.FenceToken) (int, error) {
	return 0, model.Fail(model.Stale) // ends the pass: the later stages never run
}

func newVoterGroups(t *testing.T) map[uint64]*replica.Group {
	t.Helper()
	id := model.NewID()
	members := replica.Members{Revision: 1}
	for n := uint64(1); n <= 3; n++ {
		members.Nodes = append(members.Nodes, replica.Member{ID: n, Address: fmt.Sprintf("https://voter%d.invalid", n), NodeIdentity: fmt.Sprintf("voter-%d", n), FailureDomain: fmt.Sprintf("disk-%d", n)})
	}
	wire := &voterWire{groups: map[uint64]*replica.Group{}}
	for n := uint64(1); n <= 3; n++ {
		g, err := replica.Open(replica.Config{ID: n, Group: id, Directory: filepath.Join(t.TempDir(), "raft"), Members: members, Machine: &voterMachine{}, Transport: wire, TickInterval: 20 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { g.Close() })
		wire.groups[n] = g
	}
	return wire.groups
}

// leads waits until voter id leads with a working quorum round.
func leads(t *testing.T, groups map[uint64]*replica.Group, id uint64) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for round := 0; time.Now().Before(deadline); round++ {
		if groups[id].Status().Leader == id {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, err := groups[id].Fence(ctx)
			cancel()
			if err == nil {
				return
			}
		} else if round%10 == 0 {
			_ = groups[id].Campaign()
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("voter %d never led", id)
}

func transfer(t *testing.T, groups map[uint64]*replica.Group, from, to uint64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := groups[from].TransferLeadership(ctx, to); err != nil {
		t.Fatal(err)
	}
	leads(t, groups, to)
}

// The journal hold is memory of one node's storage engine. A node that becomes
// the leader (or restarts) must re-derive it from replicated state at the
// acquisition, not at the end of a pass that may never reach the journal stage:
// here an earlier producer ends every pass, so the journal producer never runs
// and only the acquisition can protect the evidence.
func TestJournalHoldIsRederivedWhenAVoterBecomesLeader(t *testing.T) {
	r := newJournalRig(t)
	entries := r.ingestAll(r.idsInOneSlot(2))
	groups := newVoterGroups(t)
	leads(t, groups, 1)
	inner := r.app.Control.ReplicaGroup()
	mk := func(id uint64) *appcore.Workers {
		w, err := r.app.NewWorkers(r.config(func(c *appcore.WorkerConfig) {
			c.Fence = electedFence{id: id, voter: groups[id], inner: inner}
			c.Producers = []appcore.Producer{failingProducer{}, r.app.JournalExpiryProducerWith(appcore.JournalExpiryConfig{Lead: 24 * time.Hour, ReserveBytes: 1, Clock: r.clock})}
		}))
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	w1, w2 := mk(1), mk(2)

	// Far from expiry: acquiring the leadership protects nothing.
	r.clock.set(entries[1].Deadline - model.UnixNano(60*time.Hour))
	if rep := w1.Tick(r.ctx); !rep.Leader {
		t.Fatalf("voter 1 does not lead: %+v", rep)
	}
	if holds := r.app.Storage.JournalHolds(); len(holds) != 0 {
		t.Fatalf("a hold before the lead: %+v", holds)
	}

	// Unprocessed evidence is now inside the lead; leadership moves to voter 2.
	r.clock.set(entries[1].Deadline - model.UnixNano(time.Hour))
	transfer(t, groups, 1, 2)
	if rep := w1.Tick(r.ctx); rep.Leader {
		t.Fatalf("voter 1 still acts after the transfer: %+v", rep)
	}
	rep := w2.Tick(r.ctx)
	if !rep.Leader {
		t.Fatalf("voter 2 does not act as leader: %+v", rep)
	}
	holds := r.app.Storage.JournalHolds()
	if len(holds) != 1 || holds[0].Org != r.org || holds[0].Project != r.project || holds[0].Reserve != 1 {
		t.Fatalf("the new leader did not re-derive the hold (report %+v): %+v", rep, holds)
	}
	if _, err := r.admit(r.batchOf(r.record("TypeError", 98, false, true, model.NewID()))); err == nil {
		t.Fatal("the held journal accepted evidence past its reserve")
	}

	// Voter 2 dies (its memory is gone), leadership returns to voter 1, which
	// noticed it lost the lease in between and so acquires afresh.
	r.app.Storage.ReleaseJournal(r.org, r.project)
	transfer(t, groups, 2, 1)
	if holds = r.app.Storage.JournalHolds(); len(holds) != 0 {
		t.Fatalf("setup: %+v", holds)
	}
	if rep = w1.Tick(r.ctx); !rep.Leader {
		t.Fatalf("voter 1 does not lead again: %+v", rep)
	}
	if holds = r.app.Storage.JournalHolds(); len(holds) != 1 {
		t.Fatalf("a leader that regained the lease did not re-derive the hold: %+v", holds)
	}
}
