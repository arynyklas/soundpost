// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"errors"

	"soundpost/internal/model"
)

// boundaryError is the typed form of a cancellation or deadline leaving the
// engine. It reads as the model fault (errors.As finds *model.Fault) and still
// answers to the context sentinel it replaces (errors.Is).
type boundaryError struct {
	fault *model.Fault
	cause error
}

func (e *boundaryError) Error() string   { return e.fault.Error() }
func (e *boundaryError) Unwrap() []error { return []error{e.fault, e.cause} }

// boundaryErr types cancellation (model.Cancelled) and deadline (model.Timeout)
// failures; every other error is returned unchanged.
func boundaryErr(err error) error {
	var typed *boundaryError
	switch {
	case err == nil, errors.As(err, &typed):
		return err
	case errors.Is(err, context.Canceled):
		return &boundaryError{fault: model.Fail(model.Cancelled), cause: context.Canceled}
	case errors.Is(err, context.DeadlineExceeded):
		return &boundaryError{fault: model.Fail(model.Timeout), cause: context.DeadlineExceeded}
	}
	return err
}
