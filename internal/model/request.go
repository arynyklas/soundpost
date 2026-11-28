// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"context"
)

type requestIDContextKey struct{}

func WithRequestID(ctx context.Context, id ID) context.Context {
	if id == (ID{}) {
		return ctx
	}
	return context.WithValue(ctx, requestIDContextKey{}, id)
}
func RequestIDFromContext(ctx context.Context) (ID, bool) {
	id, ok := ctx.Value(requestIDContextKey{}).(ID)
	return id, ok && id != (ID{})
}

// RequestCorrelationID is called at request/command admission, never during
// deterministic apply. A non-HTTP command supplies its actual command ID.
func RequestCorrelationID(ctx context.Context, commandID ID) ID {
	if id, ok := RequestIDFromContext(ctx); ok {
		return id
	}
	if commandID != (ID{}) {
		return commandID
	}
	return NewID()
}
