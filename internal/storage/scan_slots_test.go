// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// D105. The numbers below are the documented budgets (docs/queries/admission.md): 16 admitted queries x
// 128 projects of scan slots, and 32 live subscriptions. They are literals on purpose: a test that
// tracked the constants would follow a regression.
const (
	slotsScan = 16 * 128
	slotsLive = 32
)

func slotScanReq(x *eraseEnv) ScanRequest {
	return ScanRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric, End: 1 << 40}
}

func requireCode(t *testing.T, err error, want model.Code) {
	t.Helper()
	var f *model.Fault
	if !errors.As(err, &f) || f.Code != want {
		t.Fatalf("error %v, want code %s", err, want)
	}
}

func requireNoIterators(t *testing.T, x *eraseEnv) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for x.e.Stats().ActiveIterators != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("ActiveIterators %d, want 0", x.e.Stats().ActiveIterators)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// An admitted query mix at the admission limit (16 queries x 128 projects) is never answered too_large.
func TestScansOfEveryAdmittedQueryHoldTheirSlots(t *testing.T) {
	x := newEraseEnv(t)
	seedScanRows(x, 1, 3)
	var mu sync.Mutex
	var open []RowIterator
	var wg sync.WaitGroup
	errs := make(chan error, slotsScan)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 128 {
				it, err := x.e.Scan(context.Background(), x.read, slotScanReq(x))
				if err != nil {
					errs <- err
					return
				}
				mu.Lock()
				open = append(open, it)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("a scan of an admitted query was refused: %v (%d open)", err, len(open))
	}
	if len(open) != slotsScan {
		t.Fatalf("%d scans open, want %d", len(open), slotsScan)
	}
	for _, it := range open {
		it.Close()
	}
	requireNoIterators(t, x)
}

// A scan with no free slot waits for one, never holding e.mu, and honours its deadline.
func TestScanWaitingForASlotHonoursItsDeadlineAndLeavesTheEngineFree(t *testing.T) {
	x := newEraseEnv(t)
	seedScanRows(x, 1, 3)
	var open []RowIterator
	for i := range slotsScan {
		it, err := x.e.Scan(context.Background(), x.read, slotScanReq(x))
		if err != nil {
			t.Fatalf("scan %d: %v", i, err)
		}
		open = append(open, it)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := x.e.Scan(ctx, x.read, slotScanReq(x)); done <- err }()
	// While it waits the engine is free: an append and Stats complete.
	n, scope := x.admit(model.NewID(), metricRetention, x.metric("slot_wait_append", 500))
	appended := make(chan error, 1)
	go func() { _, err := x.e.Append(context.Background(), scope, n); appended <- err }()
	select {
	case err := <-appended:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an append did not complete while a scan waits for a slot: e.mu is held across the wait")
	}
	select {
	case err := <-done:
		requireCode(t, err, model.Timeout)
	case <-time.After(5 * time.Second):
		t.Fatal("a scan waiting for a slot ignored its deadline")
	}
	for _, it := range open {
		it.Close()
	}
	requireNoIterators(t, x)
}

// Slots go to waiters in arrival order, and a slot is released by Close, by cancellation of the scan's
// context and by an iterator that failed.
func TestScanSlotsAreGrantedInArrivalOrderAndReleasedOnEveryPath(t *testing.T) {
	x := newEraseEnv(t)
	seedScanRows(x, 1, 3)
	var open []RowIterator
	cancels := make([]context.CancelFunc, 0, slotsScan)
	for i := range slotsScan {
		ctx, cancel := context.WithCancel(context.Background())
		cancels = append(cancels, cancel)
		it, err := x.e.Scan(ctx, x.read, slotScanReq(x))
		if err != nil {
			t.Fatalf("scan %d: %v", i, err)
		}
		open = append(open, it)
	}
	order := make(chan int, 3)
	results := make([]RowIterator, 3)
	for w := range 3 {
		go func() {
			it, err := x.e.Scan(context.Background(), x.read, slotScanReq(x))
			if err != nil {
				t.Errorf("waiter %d: %v", w, err)
			}
			results[w] = it
			order <- w
		}()
		time.Sleep(100 * time.Millisecond) // arrival order is the start order
	}
	// 1. Close frees the slot for the oldest waiter.
	open[0].Close()
	expect := func(want int, how string) {
		t.Helper()
		select {
		case got := <-order:
			if got != want {
				t.Fatalf("after %s waiter %d got the slot, want the oldest, %d", how, got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no waiter got the slot freed by %s", how)
		}
	}
	expect(0, "Close")
	// 2. Cancelling the context of an open scan frees its slot.
	cancels[1]()
	expect(1, "a cancelled context")
	// 3. A failed iterator (its engine view closed under it) frees its slot too: Next returns an error and
	// the iterator is closed by the error path.
	if _, err := open[2].Next(ctxCancelled()); err == nil {
		t.Fatal("Next on a cancelled context must fail")
	}
	open[2].Close()
	expect(2, "a failed iterator")
	for _, it := range results {
		it.Close()
	}
	for _, it := range open {
		it.Close()
	}
	for _, c := range cancels {
		c()
	}
	requireNoIterators(t, x)
	if used, waiting := x.e.scanPages.scanSlots.slotUse(); used != 0 || waiting != 0 {
		t.Fatalf("slot pool leaked: used %d waiting %d", used, waiting)
	}
}

func ctxCancelled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// Live subscriptions have a budget of their own: a full set of tails neither starves interactive scans
// nor is starved by them, and the subscription over the budget waits and honours its context.
func TestLiveSubscriptionsNeverStarveScans(t *testing.T) {
	x := newEraseEnv(t)
	seedScanRows(x, 1, 3)
	var subs []ChangeIterator
	for i := range slotsLive {
		it, err := x.e.Subscribe(context.Background(), x.read, SubscribeRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric})
		if err != nil {
			t.Fatalf("subscription %d: %v", i, err)
		}
		subs = append(subs, it)
	}
	for i := range 3 {
		rows, err := drainRows(x, slotScanReq(x))
		if err != nil || rows < 3 {
			t.Fatalf("scan %d with %d live subscriptions open: %d rows, %v", i, slotsLive, rows, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := x.e.Subscribe(ctx, x.read, SubscribeRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric})
	requireCode(t, err, model.Timeout)
	subs[0].Close()
	again, err := x.e.Subscribe(context.Background(), x.read, SubscribeRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric})
	if err != nil {
		t.Fatalf("a freed live slot was not reusable: %v", err)
	}
	again.Close()
	for _, s := range subs {
		s.Close()
	}
	requireNoIterators(t, x)
	if used, waiting := x.e.scanPages.liveSlots.slotUse(); used != 0 || waiting != 0 {
		t.Fatalf("live pool leaked: used %d waiting %d", used, waiting)
	}
}
