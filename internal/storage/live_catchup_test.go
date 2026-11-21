// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

type catchUpIterator interface {
	ChangeIterator
	WaitCaughtUp(ctx context.Context) error
}

func waitCaughtUp(t *testing.T, it ChangeIterator, d time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return it.(catchUpIterator).WaitCaughtUp(ctx)
}

// The iterator is caught up when the consumer has finished with every commit it already holds: a
// commit that was acknowledged and not yet handed over keeps it waiting, and the consumer asking for
// the page after the last one (its handling of the page is done) ends the wait.
func TestChangeIteratorWaitCaughtUpCoversAnAcknowledgedCommit(t *testing.T) {
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
	if err = waitCaughtUp(t, it, 5*time.Second); err != nil {
		t.Fatalf("an iterator that holds nothing is caught up: %v", err)
	}
	if _, err = e.Append(context.Background(), write, b); err != nil {
		t.Fatal(err)
	}
	if err = waitCaughtUp(t, it, 200*time.Millisecond); err == nil {
		t.Fatal("caught up with an acknowledged commit that was never handed to the consumer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	change, err := it.Next(ctx)
	if err != nil || change.Page.Len() != 1 {
		t.Fatalf("the commit was not handed over: %v", err)
	}
	if err = waitCaughtUp(t, it, 200*time.Millisecond); err == nil {
		t.Fatal("caught up while the consumer still holds the page (it has not come back for more)")
	}
	next := make(chan error, 1)
	go func() {
		_, err := it.Next(ctx)
		next <- err
	}()
	if err = waitCaughtUp(t, it, 10*time.Second); err != nil {
		t.Fatalf("the consumer came back for more and the iterator is still not caught up: %v", err)
	}
	it.Close()
	if err = <-next; err == nil {
		t.Fatal("the pending Next of a closed iterator must fail")
	}
	if err = waitCaughtUp(t, it, time.Second); err != nil {
		t.Fatalf("a closed iterator is caught up: %v", err)
	}
}

// An overrun discards the queued events, and a consumer that was told about it (the slow_consumer gap)
// has nothing left to absorb: the accounting must not wait for the discarded ones.
func TestChangeIteratorWaitCaughtUpAfterAnOverrun(t *testing.T) {
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
	if _, err = e.Append(context.Background(), write, b); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if change, err := it.Next(ctx); err != nil || change.Page.Len() != 1 {
		t.Fatalf("committed row absent: %v", err)
	}
	for i := range liveCapacity + 2 {
		row := b.Records[0]
		row.ID = model.NewID()
		row.ObservedAt = model.UnixNano(i + 2)
		appendTyped(t, e, store, a, c, d, row)
	}
	pumped := make(chan error, 1)
	go func() {
		change, err := it.Next(ctx)
		if err == nil && (change.Gap == nil || change.Gap.Reason != "slow_consumer") {
			t.Errorf("want the slow_consumer gap, got %+v", change)
		}
		for err == nil {
			_, err = it.Next(ctx)
		}
		pumped <- err
	}()
	if err = waitCaughtUp(t, it, 20*time.Second); err != nil {
		t.Fatalf("the consumer took the overrun gap and the iterator is still not caught up: %v", err)
	}
	it.Close()
	<-pumped
}
