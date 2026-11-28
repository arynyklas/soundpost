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

// noLeaderCluster is three voters on a hand-pumped wire without a proposal forwarder: node 1 leads, so a proposal
// made on node 2 or 3 meets a leader that is another member and cannot be sent on, the moment a client sees when a
// leader changed under it.
func noLeaderCluster(t *testing.T) *testWire {
	t.Helper()
	id := model.NewID()
	wire := &testWire{nodes: map[uint64]*Group{}, blocked: map[uint64]bool{}}
	members := Members{Revision: 1, Nodes: []Member{{ID: 1, Address: "https://node1.invalid", FailureDomain: "disk-a", NodeIdentity: "node-1"}, {ID: 2, Address: "https://node2.invalid", FailureDomain: "disk-b", NodeIdentity: "node-2"}, {ID: 3, Address: "https://node3.invalid", FailureDomain: "disk-c", NodeIdentity: "node-3"}}}
	for i := range 3 {
		g, err := Open(Config{ID: uint64(i + 1), Group: id, Directory: t.TempDir(), Members: members, Machine: &testMachine{rows: map[string]string{}}, Transport: wire, Domain: NewFailDomain()})
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
	for id := uint64(1); id <= 3; id++ {
		if st := wire.nodes[id].Status(); st.Leader != 1 {
			t.Fatalf("node %d does not know the leader 1: %+v", id, st)
		}
	}
	return wire
}

// A proposal that no leader takes (the leader is another member, an election, a leader transfer) is the
// unavailable that a retry outlasts: ErrNoLeader, which is still an ErrUnavailable for every caller that does not
// care. The unavailable of a group that was closed (the state a failed-closed group is in as well) is not.
func TestAProposalNoLeaderTakesIsNoLeaderAndAClosedGroupIsPlainUnavailable(t *testing.T) {
	wire := noLeaderCluster(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := wire.nodes[3].Propose(ctx, Entry{ID: model.NewID(), Kind: Data, Payload: []byte("a follower that cannot forward")})
	if !errors.Is(err, ErrNoLeader) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a proposal on a follower that cannot forward answered %v, want ErrNoLeader (and ErrUnavailable)", err)
	}
	if err := wire.nodes[3].Close(); err != nil {
		t.Fatal(err)
	}
	_, err = wire.nodes[3].Propose(ctx, Entry{ID: model.NewID(), Kind: Data, Payload: []byte("a closed group")})
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNoLeader) {
		t.Fatalf("a proposal on a closed group answered %v, want ErrUnavailable and not ErrNoLeader", err)
	}
	wire.nodes[2].FailStop(FailEngine)
	_, err = wire.nodes[2].Propose(ctx, Entry{ID: model.NewID(), Kind: Data, Payload: []byte("a failed group")})
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNoLeader) {
		t.Fatalf("a proposal on a fail-stopped group answered %v, want ErrUnavailable and not ErrNoLeader", err)
	}
}

// A leader that answers a forwarded proposal with unavailable (it was deposed since, or it failed closed and the
// others elect again) leaves its forwarder with a gap, not with a failed member. The codes that are not a gap keep
// their own errors.
func TestAForwardedUnavailableIsAGapForTheForwarder(t *testing.T) {
	if err := forwardedError(model.Unavailable); !errors.Is(err, ErrNoLeader) {
		t.Fatalf("a forwarded unavailable became %v, want ErrNoLeader", err)
	}
	if err := forwardedError(model.Conflict); !errors.Is(err, ErrConflict) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("a forwarded conflict became %v", err)
	}
	if err := forwardedError(model.Stale); !errors.Is(err, ErrStale) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("a forwarded stale became %v", err)
	}
}
