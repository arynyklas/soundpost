// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"errors"
	"soundpost/internal/model"
	"sync"
	"testing"
)

func quotaRefusal(t *testing.T, err error) {
	t.Helper()
	var f *model.Fault
	if !errors.As(err, &f) || f.Code != model.Quota || !f.Retryable {
		t.Fatalf("want retryable quota fault, got %v", err)
	}
}

func TestUploadBudgetGlobalAndPerPrincipal(t *testing.T) {
	b := newUploadBudget(100, 60)
	a, c := model.NewID(), model.NewID()
	ra, err := b.acquire(a, 50)
	if err != nil {
		t.Fatal(err)
	}
	// Same principal: 50+20 > 60 per-principal, though global has room.
	if _, err = b.acquire(a, 20); err == nil {
		t.Fatal("per-principal bound not enforced")
	} else {
		quotaRefusal(t, err)
	}
	rc, err := b.acquire(c, 50)
	if err != nil {
		t.Fatal(err)
	}
	// Global full (100): a third principal is refused though it has no usage.
	if _, err = b.acquire(model.NewID(), 1); err == nil {
		t.Fatal("global bound not enforced")
	} else {
		quotaRefusal(t, err)
	}
	// A single request larger than either bound can never be admitted.
	if _, err = newUploadBudget(100, 60).acquire(a, 61); err == nil {
		t.Fatal("oversized single admission accepted")
	}
	ra()
	ra() // idempotent
	if _, err = b.acquire(model.NewID(), 50); err != nil {
		t.Fatalf("released bytes not reusable (double release must not over-credit): %v", err)
	}
	if _, err = b.acquire(model.NewID(), 1); err == nil {
		t.Fatal("double release over-credited the budget")
	}
	rc()
	if len(b.perUser) != 1 {
		t.Fatalf("per-principal map leaked: %d", len(b.perUser))
	}
}

func TestUploadBudgetConcurrentNeverExceeds(t *testing.T) {
	b := newUploadBudget(1000, 1000)
	var wg sync.WaitGroup
	var mu sync.Mutex
	held, peak := uint64(0), uint64(0)
	who := model.NewID()
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := b.acquire(who, 300)
			if err != nil {
				return
			}
			mu.Lock()
			held += 300
			if held > peak {
				peak = held
			}
			mu.Unlock()
			mu.Lock()
			held -= 300
			mu.Unlock()
			rel()
		}()
	}
	wg.Wait()
	if peak > 900 {
		t.Fatalf("peak %d exceeds budget", peak)
	}
	if b.used != 0 {
		t.Fatalf("leaked %d", b.used)
	}
}
