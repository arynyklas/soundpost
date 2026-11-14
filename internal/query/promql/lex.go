// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/syntax"
)

// lex scans s like the pinned promql/parser lexer. A lexical error is never
// raised ahead of the parser: tokens preceding it stay valid and the error is
// represented by a final "lexerr" token (instead of eof), so a grammar error in
// an earlier token wins exactly as it does when the reference lexer is driven
// lazily. The error is returned alongside the tokens for the parser to adopt
// when it reaches that token. Numbers and durations are scanned together
// (scanNumber, then acceptRemainingDuration) into "number" and "duration"
// tokens; quoted strings keep their decoded value.
func lex(s string, p profile.Profile) ([]token, *syntax.LanguageError) {
	l := lexer{s: s, v310: p.ID == "promql-prometheus-3.1.0"}
	if err := l.run(); err != nil {
		l.out = append(l.out, token{start: err.Range.StartByte, end: err.Range.EndByte, kind: "lexerr"})
		return l.out, err
	}
	l.out = append(l.out, token{start: len(s), end: len(s), kind: "eof"})
	return l.out, nil
}

type lexer struct {
	s    string
	v310 bool
	out  []token
}

func (l *lexer) bad(a, b int, msg string) *syntax.LanguageError {
	if b > len(l.s) {
		b = len(l.s)
	}
	if a > b {
		a = b
	}
	return &syntax.LanguageError{Category: "syntax", Range: syntax.Range(l.s, a, b), SafeMessage: msg}
}
func (l *lexer) emit(start, end int, kind string) {
	l.out = append(l.out, token{l.s[start:end], l.s[start:end], start, end, kind})
}

var commonKeywords = map[string]bool{"and": true, "or": true, "unless": true, "atan2": true, "sum": true, "avg": true, "count": true, "min": true, "max": true,
	"group": true, "stddev": true, "stdvar": true, "topk": true, "bottomk": true, "count_values": true, "quantile": true, "limitk": true, "limit_ratio": true,
	"offset": true, "by": true, "without": true, "on": true, "ignoring": true, "group_left": true, "group_right": true, "bool": true, "start": true, "end": true}
var extraKeywords3135 = map[string]bool{"smoothed": true, "anchored": true, "fill": true, "fill_left": true, "fill_right": true, "step": true, "range": true, "max_of": true, "min_of": true}

// ident emits an identifier outside braces. The pinned lexer matches keywords
// case-insensitively: a keyword token compares by its lower-case spelling while
// its value keeps the source spelling for use as a metric or label name.
func (l *lexer) ident(start, end int) {
	word := l.s[start:end]
	lower := strings.ToLower(word)
	if commonKeywords[lower] || !l.v310 && extraKeywords3135[lower] {
		l.out = append(l.out, token{lower, word, start, end, "ident"})
		return
	}
	l.emit(start, end, "ident")
}

// quoted scans a quoted or raw string starting at i and returns its end.
func (l *lexer) quoted(i int) (int, *syntax.LanguageError) {
	s, start := l.s, i
	q := s[i]
	i++
	closed := false
	for i < len(s) {
		if s[i] == q {
			i++
			closed = true
			break
		}
		if s[i] == '\\' && q != '`' {
			i++
		}
		if i < len(s) {
			i++
		}
	}
	if !closed {
		return 0, l.bad(start, len(s), "unterminated string")
	}
	raw := s[start:i]
	v := raw[1 : len(raw)-1]
	if q != '`' {
		var err error
		if q == '\'' {
			raw = "\"" + strings.ReplaceAll(strings.ReplaceAll(v, "\\'", "'"), "\"", "\\\"") + "\""
		}
		v, err = strconv.Unquote(raw)
		if err != nil {
			return 0, l.bad(start, i, "invalid string escape")
		}
	}
	l.out = append(l.out, token{s[start:i], v, start, i, "string"})
	return i, nil
}

// durationKeyword reports the duration keyword spelled at i (3.13.5 brackets).
func durationKeyword(s string, i int) (int, bool) {
	j := i
	for j < len(s) && isAlphaByte(s[j]) {
		j++
	}
	switch strings.ToLower(s[i:j]) {
	case "step", "range", "max_of", "min_of":
		return j, true
	}
	return i, false
}

func (l *lexer) run() *syntax.LanguageError {
	s := l.s
	parens, brace, bracket, gotColon, gotDuration, dmode := 0, false, false, false, false, false
	skipSpace := func(i int) int {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
			i++
		}
		return i
	}
	for i := 0; i < len(s); {
		start := i
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			i++
			continue
		}
		if r == '#' && !(bracket && dmode && !l.v310) {
			for i < len(s) && s[i] != '\n' {
				i++
			}
			continue
		}
		switch {
		case brace:
			switch {
			case isAlphaByte(s[i]):
				for i < len(s) && (isAlphaByte(s[i]) || s[i] >= '0' && s[i] <= '9') {
					i++
				}
				l.emit(start, i, "ident")
			case s[i] == ',':
				i++
				l.emit(start, i, "punct")
			case s[i] == '"' || s[i] == '\'' || s[i] == '`':
				end, err := l.quoted(i)
				if err != nil {
					return err
				}
				i = end
			case s[i] == '=':
				i++
				if i < len(s) && s[i] == '~' {
					i++
				}
				l.emit(start, i, "punct")
			case s[i] == '!':
				if i+1 < len(s) && (s[i+1] == '~' || s[i+1] == '=') {
					i += 2
					l.emit(start, i, "punct")
					break
				}
				return l.bad(start, start+1, "unexpected character after '!' inside braces")
			case s[i] == '{':
				return l.bad(start, start+1, "unexpected left brace")
			case s[i] == '}':
				i++
				brace = false
				l.emit(start, i, "punct")
			default:
				return l.bad(start, start+n, "unexpected character inside braces")
			}
		case s[i] == '"' || s[i] == '\'' || s[i] == '`':
			end, err := l.quoted(i)
			if err != nil {
				return err
			}
			i = end
		case bracket && !l.v310 && dmode:
			// lexDurationExpr: only duration arithmetic and the four duration keywords.
			switch {
			case s[i] == ']':
				i++
				bracket, gotColon, dmode = false, false, false
				l.emit(start, i, "punct")
			case s[i] == ':':
				i++
				if !gotDuration {
					return l.bad(i, i, "unexpected colon before duration in duration expression")
				}
				if gotColon {
					return l.bad(i, i, "unexpected repeated colon in duration expression")
				}
				l.emit(start, i, "punct")
				gotColon = true
			case s[i] == '(':
				i++
				parens++
				l.emit(start, i, "punct")
			case s[i] == ')':
				i++
				parens--
				if parens < 0 {
					return l.bad(i, i, "unexpected right parenthesis")
				}
				l.emit(start, i, "punct")
			case strings.IndexByte("+-*/%^,", s[i]) >= 0:
				i++
				l.emit(start, i, "punct")
			case isAlphaByte(s[i]) && strings.IndexByte("sSrRmM", s[i]) >= 0:
				end, ok := durationKeyword(s, i)
				if !ok {
					return l.bad(start, start+1, "unexpected character in duration expression")
				}
				i = end
				l.ident(start, i)
			case s[i] >= '0' && s[i] <= '9' || s[i] == '.' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9':
				gotDuration, dmode = true, false // lexNumberOrDuration continues in lexStatements
				end, err := l.number(i)
				if err != nil {
					return err
				}
				i = end
			default:
				return l.bad(start, start+n, "unexpected character in duration expression")
			}
		case s[i] >= '0' && s[i] <= '9' || s[i] == '.' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9':
			end, err := l.number(i)
			if err != nil {
				return err
			}
			i = end
		case bracket && !l.v310 && isAlphaByte(s[i]):
			// lexStatements within brackets: only a duration keyword may follow.
			end, ok := durationKeyword(s, i)
			if !ok {
				return l.bad(start, start+1, "unexpected character, expected ':'")
			}
			i = end
			l.ident(start, i)
		case isAlphaByte(s[i]) || s[i] == ':' && !bracket:
			i++
			for i < len(s) && (isAlphaByte(s[i]) || s[i] >= '0' && s[i] <= '9' || s[i] == ':') {
				i++
			}
			l.ident(start, i)
		case s[i] == ':' && bracket:
			if gotColon {
				return l.bad(start, start+1, "unexpected colon")
			}
			gotColon = true
			i++
			l.emit(start, i, "punct")
		case s[i] == '(':
			i++
			parens++
			l.emit(start, i, "punct")
		case s[i] == ')':
			i++
			parens--
			if parens < 0 {
				return l.bad(i, i, "unexpected right parenthesis")
			}
			l.emit(start, i, "punct")
		case s[i] == '{':
			i++
			brace = true
			l.emit(start, i, "punct")
		case s[i] == '[':
			if bracket {
				return l.bad(start, start+1, "unexpected left bracket")
			}
			gotColon, gotDuration = false, false
			i++
			l.emit(start, i, "punct")
			i = skipSpace(i)
			bracket, dmode = true, !l.v310
			if l.v310 {
				// 3.1.0 lexes a number or duration straight after "[".
				if i >= len(s) || !(s[i] >= '0' && s[i] <= '9' || s[i] == '.' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9') {
					return l.bad(i, i+1, "bad number or duration syntax")
				}
				end, err := l.number(i)
				if err != nil {
					return err
				}
				i = end
			}
		case s[i] == ']':
			if !bracket {
				return l.bad(start, start+1, "unexpected right bracket")
			}
			i++
			bracket, gotColon, dmode = false, false, false
			l.emit(start, i, "punct")
		case s[i] == '=':
			i++
			if i < len(s) && s[i] == '=' {
				i++
			} else if i < len(s) && s[i] == '~' {
				return l.bad(start, i+1, "unexpected character after '='")
			}
			l.emit(start, i, "punct")
		case s[i] == '!':
			if i+1 < len(s) && s[i+1] == '=' {
				i += 2
				l.emit(start, i, "punct")
				break
			}
			return l.bad(start, start+1, "unexpected character after '!'")
		case s[i] == '<' || s[i] == '>':
			i++
			if i < len(s) && (s[i] == '=' || s[i] == '/') {
				i++
			}
			l.emit(start, i, "punct")
		case strings.IndexByte(",*/%+-^@", s[i]) >= 0:
			i++
			l.emit(start, i, "punct")
		default:
			return l.bad(start, start+n, "unexpected character")
		}
	}
	return nil
}

// number scans a number or duration at i (lexNumberOrDuration).
func (l *lexer) number(i int) (int, *syntax.LanguageError) {
	pos, ok := scanNumber(l.s, i)
	if ok {
		l.emit(i, pos, "number")
		return pos, nil
	}
	end, ok := acceptRemainingDuration(l.s, pos)
	if ok {
		l.emit(i, end, "duration")
		return end, nil
	}
	if pos <= i {
		pos = i + 1
	}
	return 0, l.bad(i, pos, "bad number or duration syntax")
}

type numScanner struct {
	s   string
	pos int
}

func (n *numScanner) peek() int {
	if n.pos >= len(n.s) {
		return -1
	}
	return int(n.s[n.pos])
}
func (n *numScanner) is(set string) bool {
	c := n.peek()
	return c >= 0 && strings.IndexByte(set, byte(c)) >= 0
}
func (n *numScanner) accept(set string) bool {
	if n.is(set) {
		n.pos++
		return true
	}
	return false
}
func (n *numScanner) acceptRun(set string) {
	for n.accept(set) {
	}
}

// scanNumber ports Lexer.scanNumber of the pinned lexer (series descriptions
// excluded): decimal, hexadecimal integers, fractions, exponents and
// underscore separators with their anti-patterns. It reports whether the
// scanned text is a complete number token; pos is where scanning stopped.
func scanNumber(s string, i int) (int, bool) {
	n := &numScanner{s: s, pos: i}
	initial := n.pos
	digits := "0123456789"
	if n.accept("0") && n.accept("xX") {
		n.accept("_") // 0X_1FFFP-16
		digits = "0123456789abcdefABCDEF"
	}
	const (
		dot, exponent, underscore        = ".", "eE", "_"
		dotAnti, exponentAnti, underAnti = "_.", "._eE", "._eE"
	)
	n.accept(dot)
	n.accept(digits)
	dotConsumed, exponentConsumed := false, false
	for n.is(digits + dot + underscore + exponent) {
		if n.is(dot) && dotConsumed {
			n.accept(dot)
			return n.pos, false
		}
		if n.is(exponent) && exponentConsumed {
			n.accept(exponent)
			return n.pos, false
		}
		if n.accept(dot) {
			dotConsumed = true
			if n.accept(dotAnti) {
				return n.pos, false
			}
			if len(digits) > 10 { // fractional hexadecimal literals are not allowed
				return n.pos, false
			}
			continue
		}
		if n.accept(exponent) {
			exponentConsumed = true
			n.accept("+-")
			if n.accept(exponentAnti) || n.peek() == -1 {
				return n.pos, false
			}
			continue
		}
		if n.accept(underscore) {
			if n.accept(underAnti) || n.peek() == -1 {
				return n.pos, false
			}
			continue
		}
		n.acceptRun(digits)
	}
	if n.pos == initial {
		return n.pos, false
	}
	c := n.peek()
	return n.pos, !(c >= 0 && isAlnumByte(byte(c)))
}

// acceptRemainingDuration ports the pinned lexer's duration continuation: a unit,
// optional "s" (ms), then further number+unit pairs, ending at a non-alphanumeric.
func acceptRemainingDuration(s string, i int) (int, bool) {
	n := &numScanner{s: s, pos: i}
	if !n.accept("smhdwy") {
		return n.pos, false
	}
	n.accept("s")
	for n.accept("0123456789") {
		n.acceptRun("0123456789")
		if !n.accept("smhdw") {
			return n.pos, false
		}
		n.accept("s")
	}
	c := n.peek()
	return n.pos, !(c >= 0 && isAlnumByte(byte(c)))
}

func isAlphaByte(c byte) bool { return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isAlnumByte(c byte) bool { return isAlphaByte(c) || c >= '0' && c <= '9' }

// Bare PromQL names are ASCII in both reference profiles; quoted UTF-8 names
// are handled as strings. Host Unicode upgrades must not expand lexical syntax.
func asciiLetter(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }
