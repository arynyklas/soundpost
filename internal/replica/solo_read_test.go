// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// applyGateMachine holds an Apply of a Control command until released: the state machine's commit
// of a command in flight, which the group runs under g.mu.
type applyGateMachine struct {
	*wholeMachine
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (m *applyGateMachine) Apply(c CommittedEntry) error {
	if c.Entry.Kind == Control && m.armed.Load() {
		m.entered <- struct{}{}
		<-m.release
	}
	return m.wholeMachine.Apply(c)
}

func openApplyGated(t *testing.T) (*Group, *applyGateMachine) {
	t.Helper()
	id := model.NewID()
	machine := &applyGateMachine{wholeMachine: newWholeMachine(id), entered: make(chan struct{}, 1), release: make(chan struct{})}
	transport := NewLoopback()
	g, err := Open(Config{ID: 1, Group: id, Directory: filepath.Join(t.TempDir(), "raft"), Transport: transport, Members: soloMembers(), Machine: machine})
	if err != nil {
		transport.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close(); transport.Close() })
	if err = transport.Register(g); err == nil {
		err = g.Campaign()
	}
	if err != nil {
		t.Fatal(err)
	}
	return g, machine
}

// A read of a single voter that leads waits for neither the journal fsync nor the state machine's
// commit of the command in flight: g.mu is held across both, and every read of the control group
// (five per append of the data engine) queued behind the control commit of every admission
// (L2w20Admission5: 76 ms of a 238 ms append were control reads).
func TestReadIndexOfASingleVoterDoesNotWaitForTheCommandInFlight(t *testing.T) {
	g, machine := openApplyGated(t)
	first := wholeEntry(machine.current().Rev, map[string]string{"a": "1"})
	if _, err := g.Propose(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	before, err := g.ReadIndex(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	machine.armed.Store(true)
	second := wholeEntry(machine.current().Rev, map[string]string{"a": "2"})
	proposed := make(chan error, 1)
	go func() { _, err := g.Propose(context.Background(), second); proposed <- err }()
	select {
	case <-machine.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the command in flight never reached the state machine")
	}
	type read struct {
		cursor model.Cursor
		err    error
	}
	reads := make(chan read, 1)
	go func() {
		c, err := g.ReadIndex(context.Background())
		reads <- read{c, err}
	}()
	select {
	case r := <-reads:
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.cursor != before {
			t.Fatalf("the read answered %v while the command in flight was not applied, want %v", r.cursor, before)
		}
	case <-time.After(500 * time.Millisecond):
		close(machine.release)
		t.Fatal("ReadIndex waited for the command in flight")
	}
	close(machine.release)
	if err = <-proposed; err != nil {
		t.Fatal(err)
	}
	after, err := g.ReadIndex(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if after.Index != before.Index+1 {
		t.Fatalf("after the command was acknowledged a read answers %v, want index %d", after, before.Index+1)
	}
}

// The shortcut belongs to a group that is its own quorum: a member of three voters still confirms
// its leadership with the others on every read.
func TestReadIndexOfAThreeVoterGroupKeepsItsRound(t *testing.T) {
	wire, _, _ := testCluster(t)
	for id, g := range wire.nodes {
		if g.soloRead.Load() != nil {
			t.Fatalf("member %d of three voters published a read without a round", id)
		}
	}
}
