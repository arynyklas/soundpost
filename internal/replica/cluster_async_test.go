// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	pb "go.etcd.io/raft/v3/raftpb"
)

// asyncWire delivers every message on its own goroutine per destination, in order, without ever blocking the sender
// (the in-process stand-in for a network between members that tick on their own), counts what it carries by type
// and destination, and drops what is sent from or to a member that is down.
type asyncWire struct {
	mu     sync.Mutex
	groups map[uint64]map[model.ID]*Group
	queues map[uint64]*asyncQueue
	down   map[uint64]bool
	counts map[uint64]map[pb.MessageType]*atomic.Int64 // by destination
}

type asyncQueue struct {
	mu     sync.Mutex
	wake   chan struct{}
	items  []asyncDelivery
	closed bool
}

type asyncDelivery struct {
	group model.ID
	m     *pb.Message
}

func newAsyncWire() *asyncWire {
	return &asyncWire{groups: map[uint64]map[model.ID]*Group{}, queues: map[uint64]*asyncQueue{}, down: map[uint64]bool{}, counts: map[uint64]map[pb.MessageType]*atomic.Int64{}}
}

// Send queues m for its destination.
func (w *asyncWire) Send(group model.ID, m *pb.Message) error {
	w.mu.Lock()
	if w.down[m.GetFrom()] || w.down[m.GetTo()] {
		w.mu.Unlock()
		return nil
	}
	q := w.queues[m.GetTo()]
	counts := w.counts[m.GetTo()]
	if counts == nil {
		counts = map[pb.MessageType]*atomic.Int64{}
		w.counts[m.GetTo()] = counts
	}
	c := counts[m.GetType()]
	if c == nil {
		c = new(atomic.Int64)
		counts[m.GetType()] = c
	}
	w.mu.Unlock()
	c.Add(1)
	if q == nil {
		return nil
	}
	q.mu.Lock()
	q.items = append(q.items, asyncDelivery{group: group, m: m})
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return nil
}

// sent is how many messages of type typ were sent to member to.
func (w *asyncWire) sent(to uint64, typ pb.MessageType) int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if c := w.counts[to][typ]; c != nil {
		return c.Load()
	}
	return 0
}

// serve delivers the queue of member id until the test ends. A message for a member that is down is dropped.
func (w *asyncWire) serve(t *testing.T, id uint64) {
	q := &asyncQueue{wake: make(chan struct{}, 1)}
	w.mu.Lock()
	w.queues[id] = q
	w.mu.Unlock()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			q.mu.Lock()
			items := q.items
			q.items = nil
			q.mu.Unlock()
			for _, d := range items {
				w.mu.Lock()
				g := w.groups[id][d.group]
				isDown := w.down[id] || w.down[d.m.GetFrom()]
				w.mu.Unlock()
				if g != nil && !isDown {
					_ = g.Step(context.Background(), d.m)
				}
			}
			if len(items) > 0 {
				continue
			}
			select {
			case <-q.wake:
			case <-done:
				return
			}
		}
	}()
}

// asyncCluster is three voters over an asyncWire, each with the same groups; a member can be stopped (its groups
// closed, its journal kept) and started again on the same directories with a fresh state machine.
type asyncCluster struct {
	t       *testing.T
	wire    *asyncWire
	ids     []model.ID // the groups
	members Members
	dirs    [3][]string
	groups  [3][]*Group
	rows    [3][]*ledgerMachine
	config  func(node, group int, c *Config)
}

func newAsyncCluster(t *testing.T, groups int, config func(node, group int, c *Config)) *asyncCluster {
	t.Helper()
	c := &asyncCluster{t: t, wire: newAsyncWire(), config: config}
	c.members = Members{Revision: 1, Nodes: []Member{{ID: 1, Address: "https://node1.invalid", FailureDomain: "disk-a", NodeIdentity: "node-1"}, {ID: 2, Address: "https://node2.invalid", FailureDomain: "disk-b", NodeIdentity: "node-2"}, {ID: 3, Address: "https://node3.invalid", FailureDomain: "disk-c", NodeIdentity: "node-3"}}}
	for range groups {
		c.ids = append(c.ids, model.NewID())
	}
	for n := range 3 {
		c.wire.serve(t, uint64(n+1))
		c.groups[n] = make([]*Group, groups)
		c.rows[n] = make([]*ledgerMachine, groups)
		for range groups {
			c.dirs[n] = append(c.dirs[n], t.TempDir())
		}
		c.start(n)
	}
	t.Cleanup(func() {
		for n := range 3 {
			c.stop(n)
		}
	})
	return c
}

// start opens every group of member n (0-based) on its directories with a fresh state machine.
func (c *asyncCluster) start(n int) {
	c.t.Helper()
	for i, id := range c.ids {
		machine := newLedgerMachine(id, filepath.Join(c.dirs[n][i], "machine"))
		if err := os.MkdirAll(machine.dir, 0700); err != nil {
			c.t.Fatal(err)
		}
		cfg := Config{ID: uint64(n + 1), Group: id, Directory: filepath.Join(c.dirs[n][i], "raft"), Members: c.members, Machine: machine, Transport: c.wire, TickInterval: 10 * time.Millisecond}
		if c.config != nil {
			c.config(n, i, &cfg)
		}
		g, err := Open(cfg)
		if err != nil {
			c.t.Fatal(err)
		}
		c.rows[n][i], c.groups[n][i] = machine, g
		c.wire.mu.Lock()
		if c.wire.groups[uint64(n+1)] == nil {
			c.wire.groups[uint64(n+1)] = map[model.ID]*Group{}
		}
		c.wire.groups[uint64(n+1)][id] = g
		c.wire.down[uint64(n+1)] = false
		c.wire.mu.Unlock()
	}
}

// stop closes every group of member n and drops what is sent to or from it: the process is gone.
func (c *asyncCluster) stop(n int) {
	c.wire.mu.Lock()
	c.wire.down[uint64(n+1)] = true
	c.wire.mu.Unlock()
	for i, g := range c.groups[n] {
		if g != nil {
			g.Close()
			c.groups[n][i] = nil
		}
	}
}

// leader is the member (1-based) that leads group i as far as the live members know, 0 when none does.
func (c *asyncCluster) leader(i int) uint64 {
	for n := range 3 {
		if g := c.groups[n][i]; g != nil {
			s := g.Status()
			if s.Leader == uint64(n+1) {
				return s.Leader
			}
		}
	}
	return 0
}

// await polls cond for up to d.
func await(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("not within %v: %s", d, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
