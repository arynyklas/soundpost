//go:build soundpost_evaluation_oracle

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"strings"

	"github.com/prometheus/prometheus/promql/parser"
)

// ParseErrors is the native transport for grammar construction AND checkAST
// errors in both exact pins. It is not an independently exposed syntax/type
// stage. Preserve that actual native class and its genuine PositionRange, while
// the source-defined production supplies a stable semantic family.
func observeError(err error, category string) *languageError {
	out := &languageError{Category: category, CategoryExposed: category == "execution", Message: err.Error(), ID: classifyNativeError(err.Error())}
	var list parser.ParseErrors
	if errors.As(err, &list) && len(list) > 0 {
		observeNativeParseCause(&list[0], out)
		return out
	}
	var single *parser.ParseErr
	if errors.As(err, &single) && single != nil {
		observeNativeParseCause(single, out)
		return out
	}
	// NewRangeQuery explicitly validates the already parsed expression's result
	// type in promql/engine.go in each pin; this category is source-proven.
	if out.ID == "evaluation.range-type" {
		out.Category = "type"
		out.CategoryExposed = true
	}
	return out
}
func observeNativeParseCause(cause *parser.ParseErr, out *languageError) {
	out.Category = "parse-error"
	out.CategoryExposed = false
	out.ID = classifyNativeError(cause.Err.Error())
	out.Start = int(cause.PositionRange.Start)
	out.End = int(cause.PositionRange.End)
	out.RangeExposed = out.Start >= 0 && out.End >= out.Start
}

// These are independently authored identities for actual error productions, not
// case-ID matches, expected-answer rewrites, or a demand for HTTP/prose parity.
// Source evidence in BOTH pinned modules:
//
//	promql/parser/parse.go: expectType/checkAST (function and aggregation types,
//	  call arity), newAggregateExpr (aggregate arity and experimental gating);
//	promql/parser/generated_parser.y: function_call (unknown/disabled functions);
//	promql/parser/parse.go: unexpected (unexpected token productions);
//	promql/engine.go: NewRangeQuery and VectorBinop (range/cardinality failures).
//
// Unknown text deliberately yields no identity and must remain a hard mismatch.
func classifyNativeError(message string) string {
	switch {
	case strings.HasPrefix(message, "unknown function with name "):
		return "function.unknown"
	case strings.HasPrefix(message, "function \"") && strings.HasSuffix(message, "\" is not enabled"):
		return "function.feature-disabled"
	case strings.HasPrefix(message, "expected ") && strings.Contains(message, " argument(s) in call to "):
		return "function.arity"
	case strings.HasPrefix(message, "expected type ") && strings.Contains(message, " in call to function "):
		return "function.argument-type"
	case strings.HasPrefix(message, "expected type ") && strings.Contains(message, " in aggregation expression, got "):
		return "aggregation.input-type"
	case strings.HasPrefix(message, "expected type ") && strings.Contains(message, " in aggregation parameter, got "):
		return "aggregation.parameter-type"
	case strings.HasPrefix(message, "wrong number of arguments for aggregate expression provided,") || message == "no arguments for aggregate expression provided":
		return "aggregation.arity"
	case strings.HasSuffix(message, "() is experimental and must be enabled with --enable-feature=promql-experimental-functions"):
		return "aggregation.feature-disabled"
	case message == "binary expression must contain only scalar and instant vector types":
		return "binary.operand-type"
	case strings.HasPrefix(message, "unexpected "):
		return "syntax.unexpected-token"
	case strings.Contains(message, "many-to-many matching not allowed"):
		return "binary.many-to-many"
	case strings.HasPrefix(message, "multiple matches for labels:"):
		return "binary.matching-cardinality"
	case strings.Contains(message, " modifier can only be used with: "):
		return "function.range-extension"
	case strings.HasSuffix(message, " modifier is not supported for subqueries"):
		return "range.extension-subquery"
	case strings.HasPrefix(message, "Scalar value ") && strings.HasSuffix(message, " overflows int64"):
		return "aggregation.parameter-range"
	case message == "vector cannot contain metrics with the same labelset" || message == "matrix cannot contain metrics with the same labelset":
		return "result.duplicate-labelset"
	case strings.HasPrefix(message, "invalid expression type ") && strings.HasSuffix(message, " for range query, must be Scalar or instant Vector"):
		return "evaluation.range-type"
	default:
		return ""
	}
}
