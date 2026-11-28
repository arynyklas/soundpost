// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"errors"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// readBarrier is the linearizable read barrier of a control read: one ReadIndex round of the control group, which the read
// waits for before it reads the applied state. The reads of one request that share a barrier (model.WithReadShare) make
// it once; every other read makes its own.
func (s *Store) readBarrier(ctx context.Context) error {
	if s.repl == nil {
		return nil
	}
	err := model.SharedReadBarrier(ctx, func(ctx context.Context) error {
		_, err := s.repl.group.ReadIndex(ctx)
		return err
	})
	if err == nil {
		return nil
	}
	if cerr := ctx.Err(); cerr != nil && errors.Is(err, cerr) {
		err = replica.ErrStale // the caller gave up while waiting for the barrier another read of its request was making
	}
	return replicaFaultUnder(ctx, err)
}
