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
)

// A ReadIndex round is shared by every caller that arrives while the one before it is in flight (reads.go), and a
// caller that holds a receipt (ReadIndexAtLeast) asks for a cut of at least the cursor it was acknowledged at. The
// answer of a shared round is computed for the callers that began it, so it can be below one caller's min: that
// caller must be made to wait for the group to apply min and ask again, never be handed the low cut.
//
// holdMin keeps plain ReadIndex callers in a round on every noise group, then
//  1. drives acknowledged writes on writer and, for each receipt, asks every read function for a cut of at least the
//     receipt's cursor, several callers at a time;
//  2. asks for a min that is ahead of the group (the application index after the one it has applied) before the write
//     that reaches it exists: the rounds in flight answer a cut below min, and the read must wait for the write.
//
// No read may answer below its min, and none may fail on a healthy group.
func holdMin(t *testing.T, writer *Group, reads map[string]func(context.Context, model.Cursor) (model.Cursor, error), noise []*Group) (rounds uint64, noiseCalls int64) {
	t.Helper()
	const (
		writers   = 4
		perReader = 6
		duration  = 2 * time.Second
		ahead     = 300
	)
	var calls atomic.Int64
	stop := make(chan struct{})
	var noisy sync.WaitGroup
	for _, g := range noise {
		for range 8 {
			noisy.Add(1)
			go func() {
				defer noisy.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					_, _ = g.readThroughRound(ctx)
					cancel()
					calls.Add(1)
				}
			}()
		}
	}
	defer func() {
		close(stop)
		noisy.Wait()
	}()

	// 1: reads with the receipt of an acknowledged write.
	var violation, failure atomic.Value
	var wg sync.WaitGroup
	deadline := time.Now().Add(duration)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				receipt, err := writer.Propose(ctx, Entry{ID: model.NewID(), Kind: Data, Payload: []byte("w")})
				cancel()
				if err != nil {
					continue
				}
				min := receipt.ApplicationCursor
				var asks sync.WaitGroup
				for name, read := range reads {
					for range perReader {
						asks.Add(1)
						go func() {
							defer asks.Done()
							rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
							defer rcancel()
							cut, err := read(rctx, min)
							if err != nil {
								failure.CompareAndSwap(nil, name+": "+err.Error())
							} else if cut.Index < min.Index {
								violation.CompareAndSwap(nil, name)
							}
						}()
					}
				}
				asks.Wait()
			}
		}()
	}
	wg.Wait()
	if v := violation.Load(); v != nil {
		t.Fatalf("%v answered a cut below the cursor of the acknowledged write", v)
	}
	if f := failure.Load(); f != nil {
		t.Fatalf("a read with a receipt failed on a healthy group: %v", f)
	}

	// 2: a min ahead of the group. One writer, so the write is the next application index.
	type answer struct {
		name string
		cut  model.Cursor
		err  error
	}
	for range ahead {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		now, err := writer.ReadIndex(ctx)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		min := model.Cursor{Group: now.Group, Index: now.Index + 1}
		answers := make(chan answer, len(reads)*perReader)
		for name, read := range reads {
			for range perReader {
				go func() {
					cut, err := read(ctx, min)
					answers <- answer{name, cut, err}
				}()
			}
		}
		time.Sleep(time.Millisecond) // the reads are in their rounds before the write exists
		if _, err = writer.Propose(ctx, Entry{ID: model.NewID(), Kind: Data, Payload: []byte("f")}); err != nil {
			cancel()
			t.Fatal(err)
		}
		for range len(reads) * perReader {
			a := <-answers
			if a.err != nil {
				cancel()
				t.Fatalf("%s: a read with a min ahead of the group failed: %v", a.name, a.err)
			}
			if a.cut.Index < min.Index {
				cancel()
				t.Fatalf("%s: a read with min %d answered the cut %d, below the write it had to wait for", a.name, min.Index, a.cut.Index)
			}
		}
		cancel()
	}
	for _, g := range noise {
		rounds += g.phases.readRounds.Load()
	}
	return rounds, calls.Load()
}

// Three voters: the readers are the two followers and the leader; the plain callers keep a round in flight on the
// followers, so the readers with a receipt are the callers that join a round that began before them.
func TestCoalescedReadIndexNeverAnswersBelowTheMinOfAReceiptThreeVoters(t *testing.T) {
	c := newAsyncCluster(t, 1, nil)
	if err := c.groups[0][0].Campaign(); err != nil {
		t.Fatal(err)
	}
	await(t, 10*time.Second, "a leader", func() bool { return c.leader(0) == 1 })
	await(t, 10*time.Second, "the followers know their leader", func() bool {
		return c.groups[1][0].Status().Leader == 1 && c.groups[2][0].Status().Leader == 1
	})
	leader, f2, f3 := c.groups[0][0], c.groups[1][0], c.groups[2][0]
	reads := map[string]func(context.Context, model.Cursor) (model.Cursor, error){
		"leader":     leader.ReadIndexAtLeast,
		"follower 2": f2.ReadIndexAtLeast,
		"follower 3": f3.ReadIndexAtLeast,
		// the shared round alone, held to min by the same wait the group uses
		"follower 2 round": func(ctx context.Context, min model.Cursor) (model.Cursor, error) {
			return f2.cutAtLeast(ctx, min, f2.readThroughRound)
		},
	}
	rounds, calls := holdMin(t, leader, reads, []*Group{f2, f3})
	if rounds >= uint64(calls) {
		t.Fatalf("%d plain calls put %d rounds: callers must share them", calls, rounds)
	}
	t.Logf("three voters: %d plain calls, %d rounds", calls, rounds)
}

// One voter: the lock-free cursor answers most reads, and the shared round answers a read while that cursor is not
// published (a configuration change, entries committed and not yet applied): the round path is driven directly too.
func TestCoalescedReadIndexNeverAnswersBelowTheMinOfAReceiptOneVoter(t *testing.T) {
	g, _ := openApplyGated(t)
	await(t, 10*time.Second, "a leader", func() bool { return g.Status().Leader == 1 })
	reads := map[string]func(context.Context, model.Cursor) (model.Cursor, error){
		"public": g.ReadIndexAtLeast,
		"round only": func(ctx context.Context, min model.Cursor) (model.Cursor, error) {
			return g.cutAtLeast(ctx, min, g.readThroughRound)
		},
	}
	rounds, calls := holdMin(t, g, reads, []*Group{g})
	// A lone voter answers a round inside the call that puts it, so rounds are rarely shared here: this test holds the
	// round path and the min logic to the same contract, the sharing itself is asserted with three voters.
	t.Logf("one voter: %d plain calls, %d rounds", calls, rounds)
}
