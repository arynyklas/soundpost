// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"context"
	"errors"
)

// RetryWhileStale runs fn again for as long as it fails with the typed Stale fault and ctx is
// alive. A quorum read that reports stale means the node is still catching up with the cluster
// (its freshness window of five seconds passed), not that anything is wrong: a node that is being
// started has a startup budget, and that budget, not one freshness window, bounds how long it
// waits. Every other result, including ctx ending, is returned as it is.
func RetryWhileStale(ctx context.Context, fn func() error) error {
	for {
		err := fn()
		var fault *Fault
		if err == nil || ctx.Err() != nil || !errors.As(err, &fault) || fault.Code != Stale {
			return err
		}
	}
}
