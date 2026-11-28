// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package scan

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
	"github.com/arynyklas/soundpost/internal/storage"
)

// countingAccount counts the reservations a selection makes of the memory pool.
type countingAccount struct {
	*value.BoundedAccount
	reserves int
}

func (a *countingAccount) Reserve(n int64) error { a.reserves++; return a.BoundedAccount.Reserve(n) }

// The memory a page of samples takes is reserved from the process-wide pool once per page, not once per
// sample and series: the pool's lock taken per sample was 4 % of the CPU of ten queries at the Queries
// gate. The bytes reserved, and the failure of a page that does not fit, are the same as before.
func TestMetricSelectReservesMemoryOncePerPage(t *testing.T) {
	var project model.ID
	project[0] = 1
	const rows = 100
	bits := model.FloatBits(math.Float64bits(4))
	mk := func() storage.Page {
		page := storage.Page{}
		for i := range rows {
			page.IDs = append(page.IDs, model.ID{byte(i + 1)})
			page.Projects = append(page.Projects, project)
			page.Times = append(page.Times, model.UnixNano(10+i))
			page.ObservedTimes = append(page.ObservedTimes, model.UnixNano(10+i))
			page.Values = append(page.Values, model.Payload{Metric: &model.MetricPoint{Name: "a", Labels: model.Labels{{Name: "route", Value: string(rune('a' + i%3))}}, Value: &bits}})
		}
		return page
	}
	account := &countingAccount{BoundedAccount: value.NewBoundedAccount(1 << 20)}
	src := NewMetricSource(&borrowedMemoryScanner{it: &borrowedRows{page: mk()}}, auth.Scope{}, project, storage.ReadFence{})
	it, err := src.Select(context.Background(), MetricSelection{Start: 0, End: 1000, Account: account})
	if err != nil {
		t.Fatal(err)
	}
	used := account.Used()
	if account.reserves > 4 { // the page, plus the cut's accounting
		t.Fatalf("%d reservations for one page of %d samples", account.reserves, rows)
	}
	if used <= 0 {
		t.Fatalf("nothing reserved for %d samples", rows)
	}
	_ = it.Close()
	if account.Used() != 0 {
		t.Fatalf("%d bytes leaked after Close", account.Used())
	}
	// A page that does not fit still fails the selection, and leaks nothing.
	small := &countingAccount{BoundedAccount: value.NewBoundedAccount(used - 1)}
	src = NewMetricSource(&borrowedMemoryScanner{it: &borrowedRows{page: mk()}}, auth.Scope{}, project, storage.ReadFence{})
	if _, err = src.Select(context.Background(), MetricSelection{Start: 0, End: 1000, Account: small}); err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("a page over the budget: %v, want the resource error", err)
	}
	if small.Used() != 0 {
		t.Fatalf("%d bytes leaked by the failed selection", small.Used())
	}
}
