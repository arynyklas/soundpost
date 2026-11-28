// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"context"
	"errors"
	"testing"
)

func TestRetryWhileStaleWaitsOutTheFreshnessWindows(t *testing.T) {
	calls := 0
	err := RetryWhileStale(context.Background(), func() error {
		calls++
		if calls < 3 {
			return Fail(Stale)
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("err %v after %d calls, want nil after 3", err, calls)
	}
}

func TestRetryWhileStaleReturnsEveryOtherFaultAtOnce(t *testing.T) {
	calls := 0
	err := RetryWhileStale(context.Background(), func() error { calls++; return Fail(Corrupt) })
	var fault *Fault
	if !errors.As(err, &fault) || fault.Code != Corrupt || calls != 1 {
		t.Fatalf("err %v after %d calls, want corrupt after 1", err, calls)
	}
}

func TestRetryWhileStaleStopsWhenItsBudgetIsSpent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := RetryWhileStale(ctx, func() error {
		calls++
		if calls == 2 {
			cancel()
		}
		return Fail(Stale)
	})
	var fault *Fault
	if !errors.As(err, &fault) || fault.Code != Stale || calls != 2 {
		t.Fatalf("err %v after %d calls, want stale after 2", err, calls)
	}
}
