// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"regexp"
	"strconv"
	"strings"
)

// This file deliberately has no build tag and no upstream imports so the
// classifier can be unit tested in the nested module without the pinned Loki tree.

// nativeDurationLexError matches the lexer's duration failures, which the
// native parser reports with line 0 and a column that is a byte offset into the
// (single-line) source: an empty duration, or a unit the duration grammar does
// not know. Anchored on the fixed prefix and wording so a real syntax error on
// a source line (line >= 1) is never swept in.
var nativeDurationLexError = regexp.MustCompile(`^parse error at line 0, col ([0-9]+): (?:empty duration string|unknown unit .+ in duration .+|missing closing '\]' in duration|not a valid duration string: .+)$`)

// nativeLiteralNotTerminated matches the scanner's unterminated string/raw-string
// failure on a real source line. Its column is converted by the caller from the
// supplied source, so no start is returned here.
var nativeLiteralNotTerminated = regexp.MustCompile(`^parse error at line [1-9][0-9]*, col [0-9]+: literal not terminated$`)

// nativeScannerNumberError matches the fixed wording the Go text/scanner number
// scanner reports through the native lexer's error callback on a real source
// line (line >= 1). The column is converted by the caller from the supplied
// source, so no start is returned here.
var nativeScannerNumberError = regexp.MustCompile(`^parse error at line [1-9][0-9]*, col [0-9]+: (?:exponent has no digits|'[eEpP]' exponent requires (?:decimal|binary|octal|hexadecimal) mantissa|hexadecimal mantissa requires a 'p' exponent|(?:decimal|hexadecimal|octal|binary) literal has no digits|invalid digit '.+' in (?:octal|binary|decimal|hexadecimal) literal|'_' must separate successive digits)$`)

// nativeScannerEscapeError matches the text/scanner string-escape failure on a
// real source line.
var nativeScannerEscapeError = regexp.MustCompile(`^parse error at line [1-9][0-9]*, col [0-9]+: invalid char escape$`)

// nativeFloatLiteralError matches the native parser's reduction-time failure to
// convert a metric-expression numeric literal with strconv.ParseFloat. It
// exposes no position.
var nativeFloatLiteralError = regexp.MustCompile(`^parse error : unable to parse (?:literal|vectorExpr) as a float: strconv\.ParseFloat: parsing ".*": (?:invalid syntax|value out of range)$`)

// nativeAggregationParameterError matches the native parser's reduction-time
// rejection of a topk/bottomk parameter that is not a positive integer literal.
// It exposes no position.
var nativeAggregationParameterError = regexp.MustCompile(`^parse error : invalid parameter(?: \(must be greater than 0\))? [a-z_]+\(.*$`)

// classifyNativeParseMessage projects the fixed constructor wording of native
// parse-stage errors that carry no exported identity onto semantic families.
// It returns the family and, only when the native text itself exposes a position,
// a start byte. Unknown text returns "" and nil; it is never collapsed to a
// generic family. The named-capture and IP errors expose no position, so start
// stays nil for them.
func classifyNativeParseMessage(text string) (semantic string, start *int) {
	if m := nativeDurationLexError.FindStringSubmatch(text); m != nil {
		col, err := strconv.Atoi(m[1])
		if err != nil {
			return "", nil
		}
		return "syntax.duration", &col
	}
	if nativeLiteralNotTerminated.MatchString(text) {
		return "syntax.string", nil
	}
	if nativeScannerNumberError.MatchString(text) {
		return "syntax.number", nil
	}
	if nativeScannerEscapeError.MatchString(text) {
		return "syntax.string-escape", nil
	}
	if nativeFloatLiteralError.MatchString(text) {
		return "syntax.number", nil
	}
	if nativeAggregationParameterError.MatchString(text) {
		return "function.arguments", nil
	}
	switch {
	case strings.Contains(text, ": named captures are not allowed"):
		return "pattern.invalid", nil
	case strings.Contains(text, ": ip: invalid pattern"):
		return "ip.pattern-invalid", nil
	case strings.Contains(text, ": ip: invalid operation"):
		return "ip.operator-invalid", nil
	}
	return "", nil
}
