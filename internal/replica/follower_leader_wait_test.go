// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// forwardNode is one member's view of testWire with the forwarding capability of the mTLS
// transport: a follower's proposal goes to the leader that member knows, and to nobody when it
// knows none (MTLS.ForwardPropose reads its own group's status the same way).
type forwardNode struct {
	*testWire
	self uint64
}

func (w forwardNode) ForwardPropose(ctx context.Context, _ model.ID, entry Entry) (CommittedEntry, error) {
	w.mu.Lock()
	own, nodes := w.nodes[w.self], w.nodes
	w.mu.Unlock()
	leader := own.Status().Leader
	if leader == 0 || leader == w.self || nodes[leader] == nil {
		return CommittedEntry{}, ErrNoLeader // as MTLS.ForwardPropose: no leader is known, or it is not another member
	}
	return nodes[leader].Propose(ctx, entry)
}

// leaderlessFollowerCluster is three voters on a hand-pumped wire whose node 2 has been cut off
// from the election: node 1 leads with node 3, and node 2 has heard no leader, which is what a
// follower looks like in the moments after an election that its first message has not reached.
func leaderlessFollowerCluster(t *testing.T) (*testWire, []*testMachine) {
	t.Helper()
	id := model.NewID()
	wire := &testWire{nodes: map[uint64]*Group{}, blocked: map[uint64]bool{}}
	machines := make([]*testMachine, 3)
	members := Members{Revision: 1, Nodes: []Member{{ID: 1, Address: "https://node1.invalid", FailureDomain: "disk-a", NodeIdentity: "node-1"}, {ID: 2, Address: "https://node2.invalid", FailureDomain: "disk-b", NodeIdentity: "node-2"}, {ID: 3, Address: "https://node3.invalid", FailureDomain: "disk-c", NodeIdentity: "node-3"}}}
	for i := range machines {
		machines[i] = &testMachine{rows: map[string]string{}}
		g, err := Open(Config{ID: uint64(i + 1), Group: id, Directory: t.TempDir(), Members: members, Machine: machines[i], Transport: forwardNode{wire, uint64(i + 1)}})
		if err != nil {
			t.Fatal(err)
		}
		wire.nodes[uint64(i+1)] = g
		t.Cleanup(func() { g.Close() })
	}
	wire.block(2)
	if err := wire.nodes[1].Campaign(); err != nil {
		t.Fatal(err)
	}
	wire.pump(t)
	if st := wire.nodes[1].Status(); st.Leader != 1 {
		t.Fatalf("node 1 does not lead: %+v", st)
	}
	if st := wire.nodes[2].Status(); st.Leader != 0 {
		t.Fatalf("node 2 already knows a leader (%d): the fixture is not the state under test", st.Leader)
	}
	return wire, machines
}

// A follower that has not heard the leader yet is not a group without a leader: a proposal made
// there waits for the leader's first message and is then forwarded. Before the wait, it was refused
// as unavailable the instant it was made, which a healthy three-member group does to the first
// request a follower serves after an election (TestTheGroupRecordsWhichMemberProposedACommand
// failed 17 times in 3000 runs under load for this reason).
func TestAFollowerThatHasNotHeardTheLeaderWaitsForItBeforeItForwards(t *testing.T) {
	wire, machines := leaderlessFollowerCluster(t)
	type result struct {
		committed CommittedEntry
		err       error
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entry := Entry{ID: model.NewID(), Kind: Data, Payload: []byte("from a follower that has not heard the leader")}
	go func() {
		c, err := wire.nodes[2].Propose(ctx, entry)
		done <- result{c, err}
	}()
	select {
	case r := <-done:
		t.Fatalf("the proposal was answered (%v) while the follower did not know the leader and the leader was reachable: it has to wait", r.err)
	case <-time.After(60 * time.Millisecond):
	}
	// The leader's next heartbeat reaches node 2: it learns the leader and the proposal goes on.
	wire.mu.Lock()
	delete(wire.blocked, 2)
	wire.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for {
		wire.nodes[1].Tick()
		wire.pump(t)
		select {
		case r := <-done:
			if r.err != nil {
				t.Fatalf("a proposal made on a follower that learned the leader while it waited: %v", r.err)
			}
			if p := r.committed.Entry.Proposer; r.committed.Entry.ID != entry.ID || p == nil || p.Node != 1 {
				t.Fatalf("committed %+v", r.committed.Entry)
			}
			machines[1].mu.Lock()
			_, held := machines[1].rows[entry.ID.String()]
			machines[1].mu.Unlock()
			if !held {
				t.Fatal("the proposing follower did not apply its own command")
			}
			return
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the proposal never completed")
		}
		time.Sleep(time.Millisecond)
	}
}

// The wait is bounded: a follower cut off from every leader answers unavailable within two
// election timeouts, not after the caller's whole deadline.
func TestAFollowerThatNeverHearsALeaderRefusesWithinTheLeaderWait(t *testing.T) {
	wire, _ := leaderlessFollowerCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	_, err := wire.nodes[2].Propose(ctx, Entry{ID: model.NewID(), Kind: Data, Payload: []byte("nobody leads here")})
	elapsed := time.Since(start)
	if !errors.Is(err, ErrNoLeader) {
		t.Fatalf("a follower that never hears a leader answered %v, want unavailable for want of a leader (ErrNoLeader)", err)
	}
	wait := leaderWaitFor(0)
	if elapsed < wait || elapsed > wait+time.Second {
		t.Fatalf("answered after %v, want about the leader wait %v", elapsed, wait)
	}
}
