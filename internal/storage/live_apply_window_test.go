// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// A commit reaches the live subscribers from inside the slot machine's Apply, and the group records the
// command as applied (and lets a lone voter's reads see it) only after Apply returns. A subscription that
// takes the event in that gap certifies the commit against a group that still reports the state before
// it: the commit is behind nothing, the group has merely not caught up with its own Apply yet. That is not
// a stale subscription. It must wait for the group and deliver the commit; it ended with Stale, which made
// a live subscription over healthy shards fail under load (TestLiveSubscriptionEndsWhenAShardStops...).
func TestLiveSubscriptionWaitsForAGroupThatIsStillApplyingTheCommitItWasHanded(t *testing.T) {
	store, a, c, d := fixture(t)
	write, b := normalized(t, store, a, c, d)
	read := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	it, err := e.Subscribe(context.Background(), read, SubscribeRequest{Projects: []model.ID{d.Project}, Signal: model.Metric})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()

	published := make(chan struct{})
	release := make(chan struct{})
	armed := true
	e.mu.Lock()
	e.afterApplyPublished = func() {
		if !armed {
			return
		}
		armed = false
		close(published)
		<-release // the group is held between its machine's Apply and its own record of the command
	}
	e.mu.Unlock()

	appended := make(chan error, 1)
	go func() {
		_, err := e.Append(context.Background(), write, b)
		appended <- err
	}()
	select {
	case <-published:
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("the commit never reached the slot machine's Apply")
	}

	type next struct {
		change ChangePage
		err    error
	}
	got := make(chan next, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		change, err := it.Next(ctx)
		got <- next{change, err}
	}()
	select {
	case n := <-got:
		close(release)
		t.Fatalf("the subscription answered while its group had not recorded the commit as applied: rows %d, error %v", n.change.Page.Len(), n.err)
	case <-time.After(300 * time.Millisecond): // waiting for the group, as it must
	}
	close(release)
	n := <-got
	if n.err != nil {
		t.Fatalf("the commit was not delivered once its group had applied it: %v", n.err)
	}
	if n.change.Page.Len() != 1 {
		t.Fatalf("the commit was delivered as %d rows, want 1", n.change.Page.Len())
	}
	if err = <-appended; err != nil {
		t.Fatal(err)
	}
}
