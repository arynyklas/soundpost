// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package regexcompat

import (
	"strings"

	syn123 "github.com/arynyklas/soundpost/third_party/regex/go123/forksyntax"
)

// foldQuirk is the 3.1.0 FastRegexMatcher fast path for a case-insensitive
// literal next to an any-string remainder: `(?i)lit.*`, `(?i)lit.+`, `.*(?i)lit`
// and `.+(?i)lit`. The reference compares a byte slice of len(literal) with
// strings.EqualFold and slices the residual with the same byte length, so a
// fold-equivalent rune whose UTF-8 form has a different length (the Kelvin sign
// U+212A against k) fails this path although the compiled regexp would match.
// Only label-value selector matching takes this path; captures and replacement
// always use the compiled regexp. 3.13.5 consumes the actual input bytes and
// needs no emulation.
type foldQuirk struct {
	literal  string
	leading  bool // the literal is the prefix; otherwise it is the suffix
	nonEmpty bool // the remainder is .+ rather than .*
}

func (q *foldQuirk) match(s string) bool {
	n := len(q.literal)
	if len(s) < n {
		return false
	}
	head, rest := s[:n], s[n:]
	if !q.leading {
		head, rest = s[len(s)-n:], s[:len(s)-n]
	}
	return strings.EqualFold(head, q.literal) && (!q.nonEmpty || rest != "")
}

// foldQuirkFor recognises the optimized shape in a simplified tree parsed with
// Perl|DotNL, or returns nil.
func foldQuirkFor(tree *syn123.Regexp) *foldQuirk {
	if tree.Op != syn123.OpConcat || len(tree.Sub) != 2 {
		return nil
	}
	first, second := tree.Sub[0], tree.Sub[1]
	literal, remainder, leading := first, second, true
	if first.Op != syn123.OpLiteral {
		literal, remainder, leading = second, first, false
	}
	if literal.Op != syn123.OpLiteral || literal.Flags&syn123.FoldCase == 0 {
		return nil
	}
	if (remainder.Op != syn123.OpStar && remainder.Op != syn123.OpPlus) || len(remainder.Sub) != 1 || remainder.Sub[0].Op != syn123.OpAnyChar {
		return nil
	}
	return &foldQuirk{literal: string(literal.Rune), leading: leading, nonEmpty: remainder.Op == syn123.OpPlus}
}
