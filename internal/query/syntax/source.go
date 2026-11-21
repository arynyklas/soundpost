// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package syntax

import "unicode/utf8"

// SourceRange is half-open, with zero-based UTF-8 byte and Unicode rune offsets.
type SourceRange struct{ StartByte, EndByte, StartRune, EndRune int }

func Range(source string, start, end int) SourceRange {
	return SourceRange{start, end, utf8.RuneCountInString(source[:start]), utf8.RuneCountInString(source[:end])}
}
