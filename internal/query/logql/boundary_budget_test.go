// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/value"
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
		// The product budget is MaxAccumulatorRepetitions steps (a count), not a duration: the
		// one-second bound is this test's own guard against an unbounded loop. Under -race the
		// same 2^26 steps cost several times more CPU, so the duration is logged, not asserted.
		if raceEnabled {
			t.Logf("%s: typed quota after %s (race build: wall-clock bound not asserted)", fn, elapsed)
		} else if elapsed > time.Second {
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
}

// interruptedShard serves ok rows and then fails its read with failure, first
// running onFail (a cancel func, say), as a shard whose context ended mid-read.
type interruptedShard struct {
	ok      int
	failure func() error
	onFail  func()
	reads   int
	closed  int
}

func (s *interruptedShard) Next(context.Context) (PipelineResult, error) {
	if s.reads >= s.ok {
		if s.onFail != nil {
			s.onFail()
		}
		return PipelineResult{}, s.failure()
	}
	s.reads++
	return limitRow(s.reads), nil
}
func (s *interruptedShard) Watermarks() []model.Cursor { return nil }
func (s *interruptedShard) Partial() bool              { return false }
func (s *interruptedShard) Close() error               { s.closed++; return nil }

// A merge interrupted in the middle of a multi-shard read, by a shard whose Next
// returns the context error, leaves as the typed fault that still answers to
// the context sentinel; every shard is closed and nothing stays charged.
func TestMergeLogsMidReadInterruptionIsTyped(t *testing.T) {
	for _, c := range []struct {
		name string
		fail func(cancel context.CancelFunc) (failure func() error, onFail func())
		is   error
		code model.Code
	}{
		{"canceled", func(cancel context.CancelFunc) (func() error, func()) {
			return func() error { return context.Canceled }, cancel
		}, context.Canceled, model.Cancelled},
		{"deadline", func(cancel context.CancelFunc) (func() error, func()) {
			return func() error { return fmt.Errorf("shard read: %w", context.DeadlineExceeded) }, nil
		}, context.DeadlineExceeded, model.Timeout},
	} {
		for _, limit := range []uint64{3, math.MaxUint64} {
			ctx, cancel := context.WithCancel(context.Background())
			failure, onFail := c.fail(cancel)
			first := &interruptedShard{ok: 50, failure: func() error { return io.EOF }}
			second := &interruptedShard{ok: 7, failure: failure, onFail: onFail}
			third := &interruptedShard{ok: 50, failure: func() error { return io.EOF }}
			account := value.NewBoundedAccount(1 << 30)
			out, err := MergeLogs(ctx, []EntryIterator{first, second, third}, Forward, limit, account)
			cancel()
			var fault *model.Fault
			if !errors.As(err, &fault) || fault.Code != c.code || !errors.Is(err, c.is) {
				t.Fatalf("%s limit=%d: err=%#v", c.name, limit, err)
			}
			if out != nil {
				t.Fatalf("%s limit=%d: a failed merge returned an iterator", c.name, limit)
			}
			if first.reads != 50 || second.reads != 7 || third.reads != 0 {
				t.Fatalf("%s limit=%d: the read was not in progress when it failed: %d %d %d", c.name, limit, first.reads, second.reads, third.reads)
			}
			if first.closed != 1 || second.closed != 1 || third.closed != 1 {
				t.Fatalf("%s limit=%d: shards left open: %d %d %d", c.name, limit, first.closed, second.closed, third.closed)
			}
			if account.Used() != 0 {
				t.Fatalf("%s limit=%d: leaked %d", c.name, limit, account.Used())
			}
		}
	}
}

// Reading a merge after the context ended is typed too, and releases what the
// merge still held.
func TestMergeLogsNextAfterInterruptionIsTyped(t *testing.T) {
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
		account := value.NewBoundedAccount(1 << 30)
		it, err := MergeLogs(context.Background(), []EntryIterator{&genIter{n: 20, row: limitRow}}, Forward, 5, account)
		if err != nil {
			t.Fatal(err)
		}
		if account.Used() == 0 {
			t.Fatal("the merge holds nothing: the release below proves nothing")
		}
		ctx, cancel := c.ctx()
		_, err = it.Next(ctx)
		cancel()
		var fault *model.Fault
		if !errors.As(err, &fault) || fault.Code != c.code || !errors.Is(err, c.is) {
			t.Fatalf("%s: err=%#v", c.name, err)
		}
		if account.Used() != 0 {
			t.Fatalf("%s: leaked %d", c.name, account.Used())
		}
	}
}
