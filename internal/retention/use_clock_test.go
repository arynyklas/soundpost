// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"context"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// UseClock replaces the time source a Service was built with: the expiry pass of
// RunOnce erases at the installed clock's instant, not at the builder's. A nil clock
// is refused, and so is a replacement while the worker is started.
func TestUseClockDrivesTheExpiryPassAndIsRefusedWhileStarted(t *testing.T) {
	f := newFx(t, options{})
	if got := code(f.svc.UseClock(nil)); got != model.Invalid {
		t.Fatalf("a nil clock: %v", got)
	}
	var seen []model.UnixNano
	f.plane.expired = func(_ context.Context, now model.UnixNano, _ storage.EraseGuard) (storage.EraseReport, error) {
		seen = append(seen, now)
		return storage.EraseReport{}, nil
	}
	later := f.at().Add(400 * 24 * time.Hour)
	if err := f.svc.UseClock(func() time.Time { return later }); err != nil {
		t.Fatal(err)
	}
	f.run()
	if len(seen) == 0 {
		t.Fatal("the pass did not run the expiry")
	}
	for _, now := range seen {
		if now != model.UnixNano(later.UnixNano()) {
			t.Fatalf("expiry ran at %d, want the installed clock's %d", now, later.UnixNano())
		}
	}

	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	if err := f.svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer f.svc.Close()
	if got := code(f.svc.UseClock(func() time.Time { return later })); got != model.Conflict {
		t.Fatalf("a clock replaced under a started worker: %v", got)
	}
}
