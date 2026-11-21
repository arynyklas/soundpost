// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"errors"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// replicaFaultUnder is replicaFault for the error of a read made under ctx. Group.ReadIndex answers
// replica.ErrStale when ctx ends before its freshness fence is reached: that is the caller giving up,
// not evidence that the data moved, and it reads as the caller's cancellation or deadline. A query
// that has failed one project cancels the others, and a typed Stale from one of them is fatal for the
// whole request and, when that project sorts first, would replace the failure that caused the
// cancellation (a corrupt page answered as stale).
func replicaFaultUnder(ctx context.Context, err error) error {
	if errors.Is(err, replica.ErrStale) {
		switch cerr := ctx.Err(); {
		case errors.Is(cerr, context.DeadlineExceeded):
			return model.Fail(model.Timeout)
		case cerr != nil:
			return model.Fail(model.Cancelled)
		}
	}
	return replicaFault(err)
}
