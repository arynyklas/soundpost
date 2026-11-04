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
var nativeDurationLexError = regexp.MustCompile(`^parse error at line 0, col ([0-9]+): (?:empty duration string|unknown unit .+ in duration .+)$`)

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
