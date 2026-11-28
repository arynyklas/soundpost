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

// Raft's clock is the tick: a leader's heartbeats leave with the Ready its tick makes, and a follower that has not heard
// one for an election timeout campaigns. A group whose tick waits for the group's lock (held by every proposer, across the
// journal write and the state machine's Apply of its own command) has a clock that runs seconds late under load, and its
// followers elect a new leader against a healthy one (a 100 ms tick: 0.6 s late on a plain build, 2.3 s under the race
// detector, against an election timeout of 1 to 2 s). The ready stage (ready.go) moves the journal write and the Apply out
// of the group lock and the proposers out of its way (proposals.go): the tick takes the lock for the clock and nothing else.
//
// Three voters over the production transport, one hot group written by 200 concurrent proposers, every Apply 4 ms (a slow
// disk): the tick must stay far below the election timeout, a probe that asks the group for its status (what Fence, Status
// and every protocol gate do) must be answered promptly, and no leader change may happen.
func TestTickDoesNotWaitBehindProposers(t *testing.T) {
	const (
		workers = 200
		payload = 8 << 10
		window  = 6 * time.Second
	)
	defer func(previous time.Duration) { meshTestTick = previous }(meshTestTick)
	meshTestTick = 100 * time.Millisecond
	electionTimeout := electionTicks * meshTestTick
	c := newMTLSClusterWith(t, 1, nil)
	for node := range 3 {
		c.machines[node][0].delay = 4 * time.Millisecond
	}
	if err := c.groups[0][0].Campaign(); err != nil {
		t.Fatal(err)
	}
	var leader int
	await(t, 20*time.Second, "a leader", func() bool {
		for node := range 3 {
			if c.groups[node][0].Status().Leader != 0 {
				leader = int(c.groups[node][0].Status().Leader) - 1
				return true
			}
		}
		return false
	})
	// The cluster is formed once every member knows the leader; the lags of the start (an election's first ticks) are not
	// what is measured.
	await(t, 20*time.Second, "every member to know the leader", func() bool {
		for node := range 3 {
			if c.groups[node][0].Status().Leader != uint64(leader+1) {
				return false
			}
		}
		return true
	})
	var terms [3]uint64
	for node := range 3 {
		terms[node] = c.groups[node][0].Status().Term
		c.groups[node][0].TickLagMax()
	}

	deadline := time.Now().Add(window)
	var committed atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := make([]byte, payload)
			for time.Now().Before(deadline) {
				ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
				_, err := c.groups[leader][0].Propose(ctx, Entry{ID: model.NewID(), Kind: Data, Payload: body})
				stop()
				if err == nil {
					committed.Add(1)
				}
			}
		}()
	}
	var probeMax atomic.Int64
	probing := make(chan struct{})
	go func() {
		defer close(probing)
		for time.Now().Before(deadline) {
			for node := range 3 {
				began := time.Now()
				c.groups[node][0].Status()
				if d := int64(time.Since(began)); d > probeMax.Load() {
					probeMax.Store(d)
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	wg.Wait()
	<-probing

	var lagMax time.Duration
	for node := range 3 {
		if lag := c.groups[node][0].TickLagMax(); lag > lagMax {
			lagMax = lag
		}
		if status := c.groups[node][0].Status(); status.Term != terms[node] || status.Leader != uint64(leader+1) {
			t.Errorf("node %d: leader %d term %d after the burst, leader %d term %d before it: the group changed leader", node+1, status.Leader, status.Term, leader+1, terms[node])
		}
	}
	t.Logf("committed %d entries in %v; the tick was at most %v late, a status call waited at most %v (election timeout %v)", committed.Load(), window, lagMax, time.Duration(probeMax.Load()), electionTimeout)
	if committed.Load() == 0 {
		t.Fatalf("nothing committed in %v", window)
	}
	if lagMax > electionTimeout/8 {
		t.Errorf("a tick ran %v late with %d proposers on the group: more than an eighth of the %v election timeout", lagMax, workers, electionTimeout)
	}
	if wait := time.Duration(probeMax.Load()); wait > electionTimeout/8 {
		t.Errorf("a status call waited %v behind the proposers: more than an eighth of the %v election timeout", wait, electionTimeout)
	}
}
