// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
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
