// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/control"
)

// The worker bounds the control log on its expiry schedule (01.08-W2): audit rows past their 365 days
// go, and the worker status counts them.
func TestWorkerExpiresTheControlLogOnItsExpirySchedule(t *testing.T) {
	f := newFx(t, options{})
	if st := f.svc.Status(); st.ExpiredAudits != 0 || st.ExpiredCommands != 0 {
		t.Fatalf("setup: %+v", st)
	}
	var before int
	if err := f.store.View(f.ctx, func(s control.State) error { before = len(s.Audits); return nil }); err != nil {
		t.Fatal(err)
	}
	f.advance(400 * 24 * time.Hour) // every audit row the fixture wrote is now older than a year
	f.run()
	st := f.svc.Status()
	var left int
	if err := f.store.View(f.ctx, func(s control.State) error { left = len(s.Audits); return nil }); err != nil {
		t.Fatal(err)
	}
	if before == 0 || st.ExpiredAudits == 0 || left >= before {
		t.Fatalf("a worker pass 400 days later: %d audit rows before, %d left, status %+v", before, left, st)
	}
}
