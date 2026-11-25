// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	pb "go.etcd.io/raft/v3/raftpb"
)

// An acknowledged command is a promise: a read that begins after the acknowledgement, with the receipt's
// cursor or without, never answers a cut below it. A lone voter answers reads without g.mu from a cursor
// that is refreshed at the end of every cycle, and applyEntry answers the waiters of a command in
// the middle of one: a waiter that is not the goroutine running the cycle (a retried proposal, a proposal
// forwarded to a leader) was handed its receipt while the cursor still read the state before the command.

// holdAfterAck makes the group stop right after applyEntry answered the waiters of the next command
// it applies, until release is called. It returns the channel that is closed when the group is held.
func holdAfterAck(g *Group) (held <-chan struct{}, release func()) {
	reached := make(chan struct{})
	gate := make(chan struct{})
	var once sync.Once
	armed := true
	g.mu.Lock()
	g.afterAck = func() {
		if !armed {
			return
		}
		armed = false
		close(reached)
		<-gate
	}
	g.mu.Unlock()
	return reached, func() { once.Do(func() { close(gate) }) }
}

// A read after an acknowledgement on a lone voter sees the command, from a goroutine other than the one
// that applied it.
func TestSoloReadAfterAcknowledgementSeesTheAcknowledgedCommand(t *testing.T) {
	g, machine := openApplyGated(t)
	if _, err := g.Propose(t.Context(), wholeEntry(machine.current().Rev, map[string]string{"a": "1"})); err != nil {
		t.Fatal(err)
	}
	if _, err := g.ReadIndex(t.Context()); err != nil {
		t.Fatal(err)
	}
	second := wholeEntry(machine.current().Rev, map[string]string{"a": "2"})
	// A second waiter on the command: handed the receipt by the goroutine that applies it.
	waiter := make(chan proposalResult, 1)
	g.mu.Lock()
	g.pending[second.ID] = append(g.pending[second.ID], waiter)
	g.mu.Unlock()
	held, release := holdAfterAck(g)
	t.Cleanup(release)
	proposed := make(chan error, 1)
	go func() { _, err := g.Propose(context.Background(), second); proposed <- err }()

	var receipt CommittedEntry
	select {
	case r := <-waiter:
		if r.err != nil {
			t.Fatal(r.err)
		}
		receipt = r.entry
	case <-time.After(10 * time.Second):
		t.Fatal("the command was never acknowledged")
	}
	select {
	case <-held:
	case <-time.After(10 * time.Second):
		t.Fatal("the group was not held after the acknowledgement")
	}

	t.Run("default read", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		cut, err := g.ReadIndex(ctx)
		if errors.Is(err, ErrStale) {
			return // an explicit freshness error is allowed, a false absence is not
		}
		if err != nil {
			t.Fatal(err)
		}
		if cut.Index < receipt.ApplicationCursor.Index {
			t.Fatalf("a read after the acknowledgement answered %v, below the receipt %v (false absence)", cut, receipt.ApplicationCursor)
		}
	})
	t.Run("min_cursor read", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		cut, err := g.ReadIndexAtLeast(ctx, receipt.ApplicationCursor)
		if err != nil {
			t.Fatalf("a read with the receipt's min_cursor failed after the acknowledgement: %v", err)
		}
		if cut.Index < receipt.ApplicationCursor.Index {
			t.Fatalf("a read with min_cursor %v answered %v", receipt.ApplicationCursor, cut)
		}
	})
	release()
	if err := <-proposed; err != nil {
		t.Fatal(err)
	}
}

// min_cursor waits for the group to apply the command in flight; it is not answered with the cut before it
// (a lone voter's default read is, and must stay so: TestReadIndexOfASingleVoterDoesNotWaitForTheCommandInFlight).
func TestSoloMinCursorWaitsForTheCommandInFlight(t *testing.T) {
	g, machine := openApplyGated(t)
	if _, err := g.Propose(t.Context(), wholeEntry(machine.current().Rev, map[string]string{"a": "1"})); err != nil {
		t.Fatal(err)
	}
	before, err := g.ReadIndex(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	machine.armed.Store(true)
	proposed := make(chan error, 1)
	go func() {
		_, err := g.Propose(context.Background(), wholeEntry(machine.current().Rev, map[string]string{"a": "2"}))
		proposed <- err
	}()
	select {
	case <-machine.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the command in flight never reached the state machine")
	}
	type read struct {
		cut model.Cursor
		err error
	}
	reads := make(chan read, 1)
	want := model.Cursor{Group: before.Group, Index: before.Index + 1}
	go func() {
		cut, err := g.ReadIndexAtLeast(context.Background(), want)
		reads <- read{cut, err}
	}()
	select {
	case r := <-reads:
		close(machine.release)
		t.Fatalf("a read with min_cursor %v answered %v, %v while the command was not applied", want, r.cut, r.err)
	case <-time.After(300 * time.Millisecond):
	}
	close(machine.release)
	if err = <-proposed; err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-reads:
		if r.err != nil || r.cut.Index < want.Index {
			t.Fatalf("after the command was applied the read answered %v, %v, want a cut of at least %v", r.cut, r.err, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the read with min_cursor did not return once the command was applied")
	}
}

// The wait is bounded: a cursor the group never reaches is an explicit freshness error, not a hang and not
// a cut below it.
func TestMinCursorBeyondTheGroupIsAFreshnessError(t *testing.T) {
	g, machine := openApplyGated(t)
	if _, err := g.Propose(t.Context(), wholeEntry(machine.current().Rev, map[string]string{"a": "1"})); err != nil {
		t.Fatal(err)
	}
	cut, err := g.ReadIndex(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	began := time.Now()
	if got, err := g.ReadIndexAtLeast(ctx, model.Cursor{Group: cut.Group, Index: cut.Index + 1}); !errors.Is(err, ErrStale) {
		t.Fatalf("a cursor beyond the group answered %v, %v, want ErrStale", got, err)
	}
	if time.Since(began) > 5*time.Second {
		t.Fatal("the wait was not bounded")
	}
	if _, err = g.ReadIndexAtLeast(t.Context(), model.Cursor{Group: model.NewID(), Index: 1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a cursor of another group: %v, want ErrInvalid", err)
	}
}

// chanWire delivers each node's messages on its own goroutine, so a node held in its machine's Apply holds
// no other node.
type chanWire struct {
	mu     sync.Mutex
	queues map[uint64]chan *pb.Message
}

func (w *chanWire) Send(_ model.ID, m *pb.Message) error {
	w.mu.Lock()
	q := w.queues[m.GetTo()]
	w.mu.Unlock()
	if q == nil {
		return nil
	}
	select {
	case q <- m:
	default: // a held node's overflow is a lost message, which Raft tolerates
	}
	return nil
}

// ackGate holds an Apply of a Data command of its node until released.
type ackGate struct {
	*testMachine
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (m *ackGate) Apply(c CommittedEntry) error {
	if c.Entry.Kind == Data && m.armed.Load() {
		m.entered <- struct{}{}
		<-m.release
	}
	return m.testMachine.Apply(c)
}

// On three voters a read of a member that has committed a command but not applied it waits for its apply:
// the read of a follower after the acknowledgement answers a cut at or above the receipt, with the command
// in the machine, never the cut before it.
func TestThreeVoterReadAfterAcknowledgementSeesTheCommandOnAMemberStillApplyingIt(t *testing.T) {
	id := model.NewID()
	wire := &chanWire{queues: map[uint64]chan *pb.Message{}}
	members := Members{Revision: 1, Nodes: []Member{{ID: 1, Address: "https://node1.invalid", FailureDomain: "disk-a", NodeIdentity: "node-1"}, {ID: 2, Address: "https://node2.invalid", FailureDomain: "disk-b", NodeIdentity: "node-2"}, {ID: 3, Address: "https://node3.invalid", FailureDomain: "disk-c", NodeIdentity: "node-3"}}}
	gate := &ackGate{testMachine: &testMachine{rows: map[string]string{}}, entered: make(chan struct{}, 4), release: make(chan struct{})}
	machines := []Machine{&testMachine{rows: map[string]string{}}, gate, &testMachine{rows: map[string]string{}}}
	nodes := map[uint64]*Group{}
	for i := range machines {
		g, err := Open(Config{ID: uint64(i + 1), Group: id, Directory: filepath.Join(t.TempDir(), "raft"), Members: members, Machine: machines[i], Transport: wire})
		if err != nil {
			t.Fatal(err)
		}
		nodes[uint64(i+1)] = g
		wire.queues[uint64(i+1)] = make(chan *pb.Message, 4096)
		t.Cleanup(func() { g.Close() })
	}
	stop := make(chan struct{})
	var delivering sync.WaitGroup
	for n, g := range nodes {
		delivering.Add(1)
		go func() {
			defer delivering.Done()
			for {
				select {
				case m := <-wire.queues[n]:
					_ = g.Step(context.Background(), m)
				case <-stop:
					return
				}
			}
		}()
	}
	t.Cleanup(func() {
		close(stop)
		gate.armed.Store(false)
		select {
		case <-gate.release:
		default:
			close(gate.release)
		}
		delivering.Wait()
	})
	if err := nodes[1].Campaign(); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		if nodes[1].Status().Leader == 1 && nodes[2].Status().Leader == 1 && nodes[3].Status().Leader == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no leader")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := nodes[1].Propose(ctx, Entry{ID: model.NewID(), Kind: Data, Payload: []byte("first")}); err != nil {
		t.Fatal(err)
	}
	gate.armed.Store(true)
	command := Entry{ID: model.NewID(), Kind: Data, Payload: []byte("second")}
	receipt, err := nodes[1].Propose(ctx, command) // acknowledged by the leader and node 3; node 2 is held applying it
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-gate.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the follower never reached the command")
	}
	type read struct {
		cut model.Cursor
		err error
		row bool
	}
	run := func(min *model.Cursor) chan read {
		out := make(chan read, 1)
		go func() {
			rctx, rcancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer rcancel()
			var cut model.Cursor
			var err error
			if min != nil {
				cut, err = nodes[2].ReadIndexAtLeast(rctx, *min)
			} else {
				cut, err = nodes[2].ReadIndex(rctx)
			}
			gate.mu.Lock()
			_, row := gate.rows[command.ID.String()]
			gate.mu.Unlock()
			out <- read{cut, err, row}
		}()
		return out
	}
	plain, atLeast := run(nil), run(&receipt.ApplicationCursor)
	for _, r := range []chan read{plain, atLeast} {
		select {
		case got := <-r:
			gate.armed.Store(false)
			close(gate.release)
			t.Fatalf("a read of the member answered %v, %v (command applied: %v) before it applied the acknowledged command", got.cut, got.err, got.row)
		case <-time.After(300 * time.Millisecond):
		}
	}
	gate.armed.Store(false)
	close(gate.release)
	for name, r := range map[string]chan read{"default": plain, "min_cursor": atLeast} {
		got := <-r
		if got.err != nil {
			t.Fatalf("%s read: %v", name, got.err)
		}
		if got.cut.Index < receipt.ApplicationCursor.Index || !got.row {
			t.Fatalf("%s read answered %v (command applied: %v), want a cut of at least %v with the command applied", name, got.cut, got.row, receipt.ApplicationCursor)
		}
	}
}
