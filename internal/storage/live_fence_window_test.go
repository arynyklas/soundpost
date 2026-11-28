// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// Subscribe fences with a ReadIndex round on every group (64 of them, one after the other) before it
// registers the subscription. A commit that lands in between (an erasure declaration, a background
// verification, a deletion: anything applied on the node) is not owed to a fresh subscription, which
// asked for what happens from now on, yet it used to open the stream with a catch_up_required gap
// (live reason feed_catch_up): TestDistributedLiveSmokeRunsOnThreeVoters failed on ~5 % of its runs
// with a gap that took sequence 1, shifting every later sequence by one.
func TestFreshSubscriptionOpensCleanWhenACommitLandsBetweenItsFenceAndItsRegistration(t *testing.T) {
	f := newMaintenanceFixture(t, 4)
	f.v.lead(t, func(int) uint64 { return 1 })
	f.ack(f.take(1))
	f.v.converge(t, f.acks.perSlot())
	read := scanScope(t, f.store, f.service, f.descriptor)
	e := f.v.engines[1]
	var landed model.ID
	var once sync.Once
	e.afterSubscribeFence = func() {
		once.Do(func() {
			batch := f.take(1)
			landed = batch[0].Records[0].ID
			f.ack(batch)
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	it, err := e.Subscribe(ctx, read, SubscribeRequest{Projects: []model.ID{f.descriptor.Project}, Signal: model.Metric})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	if landed == (model.ID{}) {
		t.Fatal("the commit never landed inside Subscribe")
	}
	batch := f.take(1)
	f.ack(batch)
	change, err := it.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if change.Gap != nil {
		t.Fatalf("a fresh subscription opened with a %s gap for a commit that was not acknowledged before the call", change.Gap.Reason)
	}
	if change.Page.Len() != 1 || change.Page.IDs[0] != batch[0].Records[0].ID {
		t.Fatalf("the first change of the subscription is %d rows %v, want only the row committed after it (%v; the one that landed in the fence window is %v)", change.Page.Len(), change.Page.IDs, batch[0].Records[0].ID, landed)
	}
}
