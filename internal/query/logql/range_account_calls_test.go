// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"io"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
)

type countingAccount struct {
	value.Account
	calls int
}

func (c *countingAccount) Reserve(n int64) error {
	c.calls++
	return c.Account.Reserve(n)
}

func (c *countingAccount) Release(n int64) {
	c.calls++
	c.Account.Release(n)
}

type fakeRangeRows struct {
	n, i   int
	labels *rangeLabels
}

func (f *fakeRangeRows) next(context.Context) (rangeRow, error) {
	if f.i >= f.n {
		return rangeRow{}, io.EOF
	}
	f.i++
	return rangeRow{retained: true, at: model.UnixNano(f.i), multiplicity: 1, labels: f.labels, bytes: 512}, nil
}

func (f *fakeRangeRows) close() error { return nil }

func (f *fakeRangeRows) partial() bool { return false }

func (f *fakeRangeRows) watermarks() []model.Cursor { return nil }

// A 24 h log query accumulates a million rows, and each took four calls on the shared account (two locks each
// at the project view): the scratch and the accumulation charged apart, the row and the scratch released apart.
// The charges of a row are one reserve and one release; the account sees the same peak.
func TestRangeAccumulationChargesAccountTwicePerRow(t *testing.T) {
	const n = 1000
	acct := &countingAccount{Account: value.NewBoundedAccount(1 << 30)}
	rows := &fakeRangeRows{n: n, labels: newRangeLabels(model.Labels{{Name: "app", Value: "api"}})}
	plan := RangePlan{Function: "count_over_time", Range: &RangeExpr{Log: &LogExpr{}, Interval: 1 << 40}, checked: true}
	res, err := evaluateRange(context.Background(), plan, rows, Frame{Time: model.UnixNano(n + 1), Project: model.NewID(), Account: acct})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Vector) != 1 {
		t.Fatalf("%d series, want one", len(res.Vector))
	}
	// 2 per row, and a handful for the result and the final release.
	if acct.calls > 2*n+10 {
		t.Fatalf("%d account calls for %d rows, want at most %d", acct.calls, n, 2*n+10)
	}
}
