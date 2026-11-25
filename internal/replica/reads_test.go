// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	pb "go.etcd.io/raft/v3/raftpb"
)

// Every write asks the leader of its group for a ReadIndex before it is proposed. Asked one by one from a member that does
// not lead, at 5,000 writes a second, that is thousands of MsgReadIndex (and as many answers, and a leader heartbeat round
// for each) on the lanes that also carry the group's appends: 8-22 thousand refusals per node. Callers that arrive while a
// question is in flight share the next one, and the answer to a later question answers an earlier caller; the answer
// must still be at least everything that was acknowledged before the caller began.
func TestConcurrentReadIndexCallsShareTheLeadersAnswerAndStayLinearizable(t *testing.T) {
	c := newAsyncCluster(t, 1, nil)
	if err := c.groups[0][0].Campaign(); err != nil {
		t.Fatal(err)
	}
	await(t, 10*time.Second, "a leader", func() bool { return c.leader(0) == 1 })
	leader, follower := c.groups[0][0], c.groups[1][0]
	await(t, 10*time.Second, "the follower knows its leader", func() bool { return follower.Status().Leader == 1 })

	const (
		readers   = 64
		perReader = 60
		writers   = 4
	)
	var calls, stale atomic.Int64
	stop := make(chan struct{})
	var violation atomic.Value
	var wg sync.WaitGroup
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				acked, err := leader.Propose(ctx, Entry{ID: model.NewID(), Kind: Data, Payload: []byte("w")})
				cancel()
				if err != nil {
					continue
				}
				// Asked after the write was acknowledged: the answer must have applied it.
				ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
				cursor, err := follower.ReadIndex(ctx)
				cancel()
				calls.Add(1)
				if err != nil {
					continue
				}
				if cursor.Index < acked.ApplicationCursor.Index {
					violation.CompareAndSwap(nil, [2]uint64{uint64(cursor.Index), uint64(acked.ApplicationCursor.Index)})
				}
			}
		}()
	}
	before := c.wire.sent(1, pb.MsgReadIndex)
	var readerWG sync.WaitGroup
	for range readers {
		readerWG.Add(1)
		go func() {
			defer readerWG.Done()
			for range perReader {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				_, err := follower.ReadIndex(ctx)
				cancel()
				calls.Add(1)
				if err != nil {
					stale.Add(1)
				}
			}
		}()
	}
	readerWG.Wait()
	close(stop)
	wg.Wait()
	questions := c.wire.sent(1, pb.MsgReadIndex) - before
	if v := violation.Load(); v != nil {
		got := v.([2]uint64)
		t.Fatalf("a ReadIndex asked after a write was acknowledged answered application index %d, the write is %d", got[0], got[1])
	}
	if stale.Load() != 0 {
		t.Fatalf("%d of the ReadIndex calls failed on a healthy group", stale.Load())
	}
	// One question in flight at a time and the rest share the next: a small multiple of the rounds, not one per call.
	if total := calls.Load(); questions*4 > total {
		t.Fatalf("%d ReadIndex calls put %d questions to the leader: callers must share them", total, questions)
	}
	t.Logf("%d ReadIndex calls put %d questions to the leader", calls.Load(), questions)
}
