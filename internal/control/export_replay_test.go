// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package control

import (
	"context"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// TransactAfterReplayRead is Transact without its read-first replay check: the call of a first
// submission that raced another of the same CommandID past that check and now meets the other's
// result inside the update (the 10.11 branch).
func (s *Store) TransactAfterReplayRead(ctx context.Context, scope auth.Scope, cmd Command) (Result, error) {
	return s.transactCommit(ctx, scope, cmd, model.RequestCorrelationID(ctx, cmd.CommandID))
}
