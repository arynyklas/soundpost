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

// A follower's proposal that names an application index the leader has moved past is refused from its headers: its body, which for
// the control group is the whole patch of a round (1.8 MB at 5,000 records/s, 98 % of the one-item rounds a follower proposed lost
// the race and carried it to the leader to be refused), is never read, and with Expect: 100-continue never sent. A proposal the
// leader already holds is answered from its table whatever the index says, so a retry of a committed entry is not refused.
func TestAForwardedProposalWhoseApplicationIndexMovedIsRefusedBeforeItsBodyIsRead(t *testing.T) {
	c := newMTLSCluster(t, 1)
	leadOnNode1(t, c)
	leader, follower := c.groups[0][0], c.groups[1][0]
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	index := uint64(leader.Status().ApplicationCursor.Index)
	good := Entry{ID: model.NewID(), Kind: Data, Payload: []byte("names the next index"), ApplicationIndex: index + 1}
	committed, err := follower.Propose(ctx, good)
	if err != nil {
		t.Fatalf("a forwarded proposal that names the next application index: %v", err)
	}
	if uint64(committed.ApplicationCursor.Index) != index+1 {
		t.Fatalf("committed at application index %d, want %d", committed.ApplicationCursor.Index, index+1)
	}

	early, bodies := proposalsRefusedEarly.Load(), proposalBodiesRead.Load()
	stale := Entry{ID: model.NewID(), Kind: Data, Payload: make([]byte, 256<<10), ApplicationIndex: index + 1}
	if _, err = follower.Propose(ctx, stale); !errors.Is(err, ErrStale) {
		t.Fatalf("a forwarded proposal that names an index the leader has moved past: %v, want stale", err)
	}
	if got := proposalsRefusedEarly.Load() - early; got != 1 {
		t.Fatalf("%d proposals refused from their headers, want 1", got)
	}
	if got := proposalBodiesRead.Load() - bodies; got != 0 {
		t.Fatalf("the leader read %d bodies of the proposals it refused as stale", got)
	}
	if _, ok := completedProposer(leader, stale.ID); ok {
		t.Fatal("the stale proposal was committed")
	}

	// The same entry again, as a caller that did not see its answer sends it: answered from the leader's table.
	early = proposalsRefusedEarly.Load()
	again, err := follower.Propose(ctx, good)
	if err != nil || again.Entry.ID != good.ID {
		t.Fatalf("a retry of a committed entry: %+v %v", again, err)
	}
	if proposalsRefusedEarly.Load() != early {
		t.Fatal("the retry of a committed entry was refused as stale from its headers")
	}
}
