// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/arynyklas/soundpost/internal/query/syntax"
)

// The reference reads a number with the Go scanner's number grammar and then
// asks whether the characters that follow, up to white space, extend it into a
// duration or a byte quantity. Anything else about the text after the number
// is lexed on its own: `1x` is the number 1 and the word x, and `5s5m` (not a
// valid duration, units out of order) is the number 5 and the word s5m.

// numberToken scans the number, duration or byte-quantity token starting at
// l.pos (a decimal digit, or a `.` followed by one).
func (l *lexer) numberToken() (token, error) {
	source, start := l.source, l.pos
	end, bad := scanNumberText(source, start)
	if bad != "" {
		l.pos = end
		return token{}, languageErrorCode("syntax.number", "syntax", bad, syntax.Range(source, start, end))
	}
	l.pos = end
	if to, ok := l.extendNumber(start, end, isDurationRune, func(s string) bool { _, err := parseQueryDuration(s); return err == nil }); ok {
		l.pos = to
		return l.numberKind("duration", start, to), nil
	}
	if to, ok := l.extendNumber(start, end, isByteSizeRune, func(s string) bool { _, err := parseByteQuantity(s); return err == nil }); ok {
		l.pos = to
		return l.numberKind("bytes", start, to), nil
	}
	return l.numberKind("number", start, end), nil
}

func (l *lexer) numberKind(kind string, start, end int) token {
	s := l.source[start:end]
	return token{kind: kind, text: s, value: s, span: syntax.Range(l.source, start, end)}
}

// extendNumber reads the characters after the number that the unit alphabet
// allows (digits, a dot, unit letters) up to white space and reports whether
// the whole text is a valid quantity.
func (l *lexer) extendNumber(start, end int, unit func(rune) bool, valid func(string) bool) (int, bool) {
	pos := end
	for pos < len(l.source) {
		r, w := utf8.DecodeRuneInString(l.source[pos:])
		if r == utf8.RuneError && w == 1 || unicode.IsSpace(r) || !unicode.IsNumber(r) && !unit(r) && r != '.' {
			break
		}
		pos += w
	}
	if pos == end || !valid(l.source[start:pos]) {
		return end, false
	}
	return pos, true
}

func isDurationRune(r rune) bool { return strings.ContainsRune("nuµmshdwy", r) }

// isByteSizeRune is the alphabet a byte quantity is read from. It is not the
// alphabet of every unit humanize accepts: the scan stops at the first rune
// outside it, so `1kb` is the byte quantity `1k` followed by the word `b`
// (op11 rows: the error sits at the token after `b`), while `1B`, `1KiB` and
// `1MB` are single tokens. Lower-case `b` and the exa units are outside it.
func isByteSizeRune(r rune) bool { return strings.ContainsRune("BikKMGTP", r) }

// scanNumberText mirrors the Go text scanner's number grammar (integer, octal,
// hexadecimal, binary and float forms with `_` separators and an exponent) for
// the number beginning at start. It returns the end of the token and, for a
// malformed literal, the scanner's complaint; the token is still consumed.
func scanNumberText(src string, start int) (end int, bad string) {
	i := start
	at := func(i int) byte {
		if i < len(src) {
			return src[i]
		}
		return 0
	}
	lower := func(c byte) byte { return c | 0x20 }
	isDec := func(c byte) bool { return c >= '0' && c <= '9' }
	isHex := func(c byte) bool { return isDec(c) || lower(c) >= 'a' && lower(c) <= 'f' }
	fail := func(msg string) {
		if bad == "" {
			bad = msg
		}
	}
	var invalid byte
	digits := func(base int) (ds int) {
		for {
			c := at(i)
			switch {
			case c == '_':
				ds |= 2
			case base <= 10 && isDec(c):
				if int(c-'0') >= base && invalid == 0 {
					invalid = c
				}
				ds |= 1
			case base > 10 && isHex(c):
				ds |= 1
			default:
				return ds
			}
			i++
		}
	}
	prefix := byte(0)
	base := 10
	digsep := 0
	isFloat := false
	seenDot := src[start] == '.'
	if seenDot {
		i++
	} else if src[start] == '0' {
		i++
		switch lower(at(i)) {
		case 'x':
			i++
			base, prefix = 16, 'x'
		case 'o':
			i++
			base, prefix = 8, 'o'
		case 'b':
			// The reference scanner does not read a binary literal: the
			// `0b` prefix fails at the literal's start in every context
			// (un12 rows `x == 0b11`, `rate(..) > 0B11`).
			i++
			base, prefix = 2, 'b'
			fail("binary literals are not supported")
		default:
			base, prefix = 8, '0'
			digsep = 1
		}
	}
	if !seenDot {
		digsep |= digits(base)
		if at(i) == '.' {
			i++
			seenDot = true
		}
	}
	if seenDot {
		isFloat = true
		if prefix == 'o' || prefix == 'b' {
			fail("invalid radix point")
		}
		digsep |= digits(base)
	}
	if digsep&1 == 0 {
		fail("number has no digits")
	}
	switch e := lower(at(i)); {
	case e == 'e' || e == 'p':
		switch {
		case e == 'e' && prefix != 0 && prefix != '0':
			fail("exponent requires decimal mantissa")
		case e == 'p' && prefix != 'x':
			fail("exponent requires hexadecimal mantissa")
		}
		i++
		isFloat = true
		if at(i) == '+' || at(i) == '-' {
			i++
		}
		if ds := digits(10); ds&1 == 0 {
			fail("exponent has no digits")
		} else {
			digsep |= ds
		}
	case prefix == 'x' && isFloat:
		fail("hexadecimal mantissa requires a 'p' exponent")
	}
	if !isFloat && invalid != 0 {
		fail("invalid digit in number")
	}
	if digsep&2 != 0 && invalidSeparator(src[start:i]) >= 0 {
		fail("'_' must separate successive digits")
	}
	return i, bad
}

// invalidSeparator reports the index of a misplaced `_` in a number literal.
func invalidSeparator(x string) int {
	x1 := byte(' ')
	d := byte('.')
	i := 0
	if len(x) >= 2 && x[0] == '0' {
		x1 = x[1] | 0x20
		if x1 == 'x' || x1 == 'o' || x1 == 'b' {
			d = '0'
			i = 2
		}
	}
	for ; i < len(x); i++ {
		p := d
		d = x[i]
		switch {
		case d == '_':
			if p != '0' {
				return i
			}
		case d >= '0' && d <= '9' || x1 == 'x' && (d|0x20 >= 'a' && d|0x20 <= 'f'):
			d = '0'
		default:
			if p == '_' {
				return i - 1
			}
			d = '.'
		}
	}
	if d == '_' {
		return len(x) - 1
	}
	return -1
}
