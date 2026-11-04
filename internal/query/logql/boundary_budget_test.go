// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"soundpost/internal/model"
	"soundpost/internal/query/scan"
	"soundpost/internal/query/value"
)

// A stored multiplicity is attacker-sized CPU for the bit-exact accumulators;
// every one of them ends in the typed quota fault, quickly, with the account
// balanced.
func TestHostileMultiplicityFailsWithTypedQuota(t *testing.T) {
	for _, fn := range []string{"avg_over_time", "stddev_over_time", "stdvar_over_time", "sum_over_time", "rate"} {
		plan := metricPlan(t, fn+`({app="api"}|logfmt|unwrap n[5s])`, value.Evaluation{Instant: true, Time: 6e9})
		account := value.NewBoundedAccount(32 << 20)
		row := variantHostRow(1, 5e9, 1e18, "a", "n=1.5")
		start := time.Now()
		r, _, err := Evaluate(context.Background(), plan, &metricSource{rows: []scan.LogRow{row}}, account)
		elapsed := time.Since(start)
		var fault *model.Fault
		if !errors.As(err, &fault) || fault.Code != model.Quota {
			t.Fatalf("%s: err=%v want typed quota", fn, err)
		}
		if elapsed > time.Second {
			t.Fatalf("%s: took %s", fn, elapsed)
		}
		account.Release(value.ResultBytes(r))
		if account.Used() != 0 {
			t.Fatalf("%s: leaked %d", fn, account.Used())
		}
	}
}

// The budget is per query: many windows each below it still add up.
func TestRepetitionBudgetIsSharedAcrossSteps(t *testing.T) {
	b := newRepetitionBudget()
	if err := b.charge(MaxAccumulatorRepetitions); err != nil {
		t.Fatal(err)
	}
	var fault *model.Fault
	if err := b.charge(1); !errors.As(err, &fault) || fault.Code != model.Quota {
		t.Fatalf("err=%v", err)
	}
}

// Ordinary multiplicities keep the exact sequential result.
func TestOrdinaryMultiplicityStillExact(t *testing.T) {
	const m = 1000
	plan := metricPlan(t, `sum_over_time({app="api"}|logfmt|unwrap n[5s])`, value.Evaluation{Instant: true, Time: 6e9})
	account := value.NewBoundedAccount(32 << 20)
	r, _, err := Evaluate(context.Background(), plan, &metricSource{rows: []scan.LogRow{variantHostRow(1, 5e9, m, "a", "n=0.1")}}, account)
	if err != nil || len(r.Vector) != 1 {
		t.Fatal(err)
	}
	want := 0.0
	for range m {
		want += 0.1
	}
	if got := math.Float64frombits(uint64(r.Vector[0].Samples[0].Float)); got != want {
		t.Fatalf("got %v want %v", got, want)
	}
}

// Cancellation leaves the engine as the typed model fault and still answers to
// the context sentinels.
func TestCancellationIsTypedAtEngineBoundary(t *testing.T) {
	plan := metricPlan(t, `sum_over_time({app="api"}|logfmt|unwrap n[5s])`, value.Evaluation{Instant: true, Time: 6e9})
	for _, c := range []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		is   error
		code model.Code
	}{
		{"canceled", func() (context.Context, context.CancelFunc) {
			c, f := context.WithCancel(context.Background())
			f()
			return c, f
		}, context.Canceled, model.Cancelled},
		{"deadline", func() (context.Context, context.CancelFunc) {
			return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		}, context.DeadlineExceeded, model.Timeout},
	} {
		ctx, cancel := c.ctx()
		account := value.NewBoundedAccount(32 << 20)
		_, _, err := Evaluate(ctx, plan, &metricSource{rows: []scan.LogRow{variantHostRow(1, 5e9, 1, "a", "n=1")}}, account)
		cancel()
		var fault *model.Fault
		if !errors.As(err, &fault) || fault.Code != c.code || !errors.Is(err, c.is) {
			t.Fatalf("%s: err=%#v", c.name, err)
		}
		if account.Used() != 0 {
			t.Fatalf("%s: leaked %d", c.name, account.Used())
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	account := value.NewBoundedAccount(1 << 20)
	var fault *model.Fault
	if _, err := MergeLogs(ctx, nil, Forward, 10, &cancelAccount{BoundedAccount: account, cancelAt: -1, cancel: func() {}}); err != nil && (!errors.As(err, &fault) || fault.Code != model.Cancelled || !errors.Is(err, context.Canceled)) {
		t.Fatalf("MergeLogs: %#v", err)
	}
}
