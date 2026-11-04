// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"context"
	"errors"

	"soundpost/internal/model"
	"soundpost/internal/query/regexcompat"
	"soundpost/internal/query/syntax"
)

func timeError() error {
	return &syntax.LanguageError{Code: "time.bounds", Category: "execution", SafeMessage: "evaluation time or duration is out of bounds"}
}
func operatorError(n *Node, code, message string) error {
	return &syntax.LanguageError{Code: code, Category: "execution", Range: n.OperatorRange, SafeMessage: message}
}

// Annotation order follows depth-first source evaluation and then sample order.
// Repeated annotations from evaluation steps are emitted once at first occurrence.
func appendAnnotations(dst []syntax.Diagnostic, src ...syntax.Diagnostic) []syntax.Diagnostic {
	for _, d := range src {
		seen := false
		for _, old := range dst {
			if old == d {
				seen = true
				break
			}
		}
		if !seen {
			dst = append(dst, d)
		}
	}
	return dst
}

// engineBoundaryError gives every failure that leaves Evaluate a typed form:
// cancellation, deadline and regex budget errors of the packages below do not
// escape as raw sentinel errors.
func engineBoundaryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		return model.Fail(model.Cancelled)
	case errors.Is(err, context.DeadlineExceeded):
		return model.Fail(model.Timeout)
	case errors.Is(err, regexcompat.ErrBudget):
		return model.Fail(model.Quota)
	case errors.Is(err, regexcompat.ErrScope):
		return model.Fail(model.Invalid)
	}
	return err
}
