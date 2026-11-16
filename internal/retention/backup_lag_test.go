// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
)

// MN-4: backup_deadline_ns is compared with the clock. The worker counts the completed erasure
// operations whose backup deadline has passed (WorkerStatus.BackupLagOps), next to
// PhysicalLagOps; an operation whose deadline is still ahead is not counted.
func TestWorkerCountsOperationsWhoseBackupDeadlinePassed(t *testing.T) {
	f := newFx(t, options{})
	rangeDelete := func(start, end model.UnixNano) retention.DeleteReceipt {
		t.Helper()
		receipt, err := f.del(model.DeleteHistoricalRange, func(r *retention.DeleteRequest) {
			r.ProjectIDs, r.Signals, r.Start, r.End = []model.ID{f.project}, []model.Kind{model.Metric}, start, end
		})
		if err != nil {
			t.Fatal(err)
		}
		return receipt
	}
	complete := func(r retention.DeleteReceipt) {
		t.Helper()
		f.run()
		if done := f.poll(r.OperationID); done.Phase != model.DeletePhaseComplete || done.Physical != retention.PhysicalDone {
			t.Fatalf("fixture: the operation did not complete: %+v", done)
		}
	}
	lag := func(at time.Time) int {
		t.Helper()
		if err := f.svc.UseClock(func() time.Time { return at }); err != nil {
			t.Fatal(err)
		}
		f.run()
		return f.svc.Status().BackupLagOps
	}

	start := f.at()
	first := rangeDelete(0, 100)
	complete(first)
	f.advance(time.Hour)
	second := rangeDelete(100, 200) // requested an hour later: its deadline is an hour later
	complete(second)
	firstDeadline, secondDeadline := time.Unix(0, int64(first.BackupDeadline)), time.Unix(0, int64(second.BackupDeadline))
	if got := firstDeadline.Sub(start); got != 30*24*time.Hour {
		t.Fatalf("fixture: the first deadline is %v after the request, want the 30-day default", got)
	}
	if got := secondDeadline.Sub(firstDeadline); got != time.Hour {
		t.Fatalf("fixture: the deadlines are %v apart, want 1h", got)
	}

	if got := lag(firstDeadline.Add(-time.Minute)); got != 0 {
		t.Fatalf("a minute before the first deadline the gauge says %d operations lag", got)
	}
	if got := lag(firstDeadline.Add(time.Minute)); got != 1 {
		t.Fatalf("a minute after the first deadline the gauge says %d operations lag, want 1", got)
	}
	if got := lag(secondDeadline.Add(-time.Minute)); got != 1 {
		t.Fatalf("a minute before the second deadline the gauge says %d operations lag, want 1", got)
	}
	if got := lag(secondDeadline.Add(time.Minute)); got != 2 {
		t.Fatalf("both deadlines passed and the gauge says %d, want 2", got)
	}
}
