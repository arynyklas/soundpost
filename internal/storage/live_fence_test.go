// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// A live subscription that sees no commit must still notice a shard that stopped answering: without
// the periodic fence it would look healthy for as long as the shard stayed silent.
func TestLiveSubscriptionEndsWhenAShardStopsAnsweringWithoutAnyCommit(t *testing.T) {
	old := liveFenceEvery
	liveFenceEvery = 50 * time.Millisecond
	defer func() { liveFenceEvery = old }()
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

	// While every shard answers, an idle subscription stays open and still delivers the next commit.
	got := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		change, err := it.Next(ctx)
		if err == nil && change.Page.Len() != 1 {
			err = model.Fail(model.Corrupt)
		}
		got <- err
	}()
	time.Sleep(400 * time.Millisecond) // eight fence periods with nothing committed
	select {
	case err := <-got:
		t.Fatalf("an idle subscription over healthy shards ended: %v", err)
	default:
	}
	if _, err = e.Append(context.Background(), write, b); err != nil {
		t.Fatal(err)
	}
	if err = <-got; err != nil {
		t.Fatalf("the commit after an idle period was not delivered: %v", err)
	}

	// A shard goes away and nothing is committed: the subscription says so by itself.
	if err = e.repl.groups[7].Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	change, err := it.Next(ctx)
	if err == nil {
		t.Fatalf("a subscription over a removed shard kept looking healthy (revoked %v, rows %d)", change.Revoked, change.Page.Len())
	}
	if f, ok := err.(*model.Fault); !ok || f.Code == model.Cancelled {
		t.Fatalf("the subscription was not ended by the missing shard but by %v", err)
	}
	if change.Revoked {
		t.Fatal("a missing shard was reported as a revocation")
	}
}
