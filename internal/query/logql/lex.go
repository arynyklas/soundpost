// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"soundpost/internal/query/profile"
	"soundpost/internal/query/regexcompat"
	"soundpost/internal/query/syntax"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// lexer is a demand-driven scanner: the parser asks for one token at a time, so
// a lexical failure surfaces only if the parser reaches the offending token. The
// pinned reference behaves the same way (its grammar driver pulls tokens), which
// makes the first token the grammar cannot accept win over any later bad text.
//
// Token kinds: "ident", "kw" (a reserved word, text lower-cased), "string",
// "number", "range" (a whole `[duration]`), "eof"; every operator and
// punctuation mark has kind == text.
type lexer struct {
	source string
	pos    int
	p      profile.Profile
}

// alwaysKeywords are reserved wherever they appear; the reference never reads
// them as label names.
var alwaysKeywords = map[string]bool{
	"or": true, "and": true, "unless": true, "by": true, "without": true, "bool": true, "on": true, "ignoring": true,
	"group_left": true, "group_right": true, "offset": true, "json": true, "logfmt": true, "regexp": true,
	"pattern": true, "unpack": true, "decolorize": true, "line_format": true, "label_format": true,
	"unwrap": true, "drop": true, "keep": true, "of": true,
}

// functionWords are reserved only when they read as a call: the next
// non-space text is `(` or a `by`/`without` grouping followed by `(`. Anywhere
// else they are ordinary identifiers (a label may be called `rate` or `ip`).
func isFunctionWord(w string) bool {
	if aggregateNames[w] || rangeNames[w] {
		return true
	}
	switch w {
	case "vector", "label_replace", "variants", "ip", "bytes", "duration", "duration_seconds":
		return true
	}
	return false
}

func (l *lexer) err(code, msg string, from, to int) error {
	return languageErrorCode(code, "syntax", msg, syntax.Range(l.source, from, to))
}

// invalidAt reports a NUL byte or a malformed UTF-8 sequence starting at i.
func (l *lexer) invalidAt(i int) error {
	if i >= len(l.source) {
		return nil
	}
	if l.source[i] == 0 {
		return l.err("syntax.nul", "invalid NUL character", i, i+1)
	}
	if r, w := utf8.DecodeRuneInString(l.source[i:]); r == utf8.RuneError && w == 1 {
		return l.err("syntax.encoding", "invalid UTF-8", i, i+1)
	}
	return nil
}

// next scans one token. The character right after the token is examined as
// well, because the reference scanner has already read it when the token is
// returned.
func (l *lexer) next() (token, error) {
	t, err := l.scan()
	if err != nil {
		return token{}, err
	}
	if err = l.invalidAt(l.pos); err != nil {
		return token{}, err
	}
	return t, nil
}

func (l *lexer) scan() (token, error) {
	source := l.source
	for {
		if err := l.invalidAt(l.pos); err != nil {
			return token{}, err
		}
		if l.pos >= len(source) {
			return token{kind: "eof", span: syntax.Range(source, len(source), len(source))}, nil
		}
		r, w := utf8.DecodeRuneInString(source[l.pos:])
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' || l.pos == 0 && r == '\ufeff' {
			l.pos += w
			continue
		}
		if r == '#' || strings.HasPrefix(source[l.pos:], "//") {
			end := l.pos
			for end < len(source) && source[end] != '\n' {
				if err := l.invalidAt(end); err != nil {
					return token{}, err
				}
				end++
			}
			l.pos = end
			continue
		}
		if strings.HasPrefix(source[l.pos:], "/*") {
			end := strings.Index(source[l.pos+2:], "*/")
			if end < 0 {
				return token{}, l.err("syntax.comment", "unterminated comment", l.pos, len(source))
			}
			for i := l.pos; i < l.pos+end+4; i++ {
				if err := l.invalidAt(i); err != nil {
					return token{}, err
				}
			}
			l.pos += end + 4
			continue
		}
		return l.token(r, w)
	}
}

func (l *lexer) token(r rune, w int) (token, error) {
	source, start := l.source, l.pos
	switch {
	case r == '"' || r == '`':
		return l.stringToken()
	case r == '[':
		return l.rangeToken()
	}
	letter, _ := regexcompat.IsLetter(l.p, r)
	if r == '_' || letter {
		pos := start + w
		for pos < len(source) {
			r, w = utf8.DecodeRuneInString(source[pos:])
			letter, _ = regexcompat.IsLetter(l.p, r)
			digit, _ := regexcompat.IsDigit(l.p, r)
			if r != '_' && !letter && !digit {
				break
			}
			pos += w
		}
		l.pos = pos
		return l.word(start, pos), nil
	}
	if r >= '0' && r <= '9' || r == '.' && start+1 < len(source) && source[start+1] >= '0' && source[start+1] <= '9' {
		return l.numberToken()
	}
	for _, op := range []string{"--strict", "--keep-empty", "|=", "|~", "|>", "!=", "!~", "!>", "=~", "==", ">=", "<="} {
		if strings.HasPrefix(source[start:], op) {
			l.pos = start + len(op)
			return token{kind: op, text: op, value: op, span: syntax.Range(source, start, l.pos)}, nil
		}
	}
	if strings.ContainsRune("{}()],|=<>+-*/%^.", r) {
		l.pos = start + w
		s := string(r)
		return token{kind: s, text: s, value: s, span: syntax.Range(source, start, l.pos)}, nil
	}
	// Any other character is an identifier of its own, as in the reference
	// scanner: it is rejected by the grammar where a name is not expected, and
	// accepted as a name where one is.
	l.pos = start + w
	s := source[start:l.pos]
	return token{kind: "ident", text: s, value: s, span: syntax.Range(source, start, l.pos)}, nil
}

func (l *lexer) stringToken() (token, error) {
	source, start := l.source, l.pos
	quote := source[start]
	pos := start + 1
	closed := false
	for pos < len(source) {
		c := source[pos]
		pos++
		if c == quote {
			closed = true
			break
		}
		if quote == '"' && c == '\\' {
			if pos < len(source) {
				_, n := utf8.DecodeRuneInString(source[pos:])
				pos += n
			}
		}
	}
	if !closed {
		return token{}, l.err("syntax.string", "unterminated string", start, pos)
	}
	l.pos = pos
	raw := source[start:pos]
	if !utf8.ValidString(raw) || strings.ContainsRune(raw, 0) {
		return token{}, l.err("syntax.encoding", "invalid string encoding", start, pos)
	}
	value, err := strconv.Unquote(raw)
	if err != nil {
		return token{}, l.err("syntax.string-escape", "invalid string escape", start, pos)
	}
	return token{kind: "string", text: raw, value: value, span: syntax.Range(source, start, pos)}, nil
}

// rangeToken scans a whole `[duration]` the way the reference does: the text up
// to the first `]` is read when the token is requested and must be exactly a
// duration (no padding, no fractions, no sub-expression such as `5m:1m`), so a
// malformed or unterminated range is a lexical error even where the grammar
// would not accept a range. Every such failure is reported at the column of the
// `[` token (see rangeErrorAt).
func (l *lexer) rangeToken() (token, error) {
	source, start := l.source, l.pos
	end := len(source)
	closed := false
	if closing := strings.IndexByte(source[start+1:], ']'); closing >= 0 {
		end, closed = start+1+closing, true
	}
	for i := start; i < len(source) && i <= end; {
		if err := l.invalidAt(i); err != nil {
			return token{}, err
		}
		_, w := utf8.DecodeRuneInString(source[i:])
		i += w
	}
	if !closed {
		return token{}, l.rangeErrorAt(start, end)
	}
	l.pos = end + 1
	d, err := parseRangeDuration(source[start+1 : end])
	if err != nil {
		return token{}, l.rangeErrorAt(start, end)
	}
	return token{kind: "range", text: source[start : end+1], value: source[start+1 : end], span: syntax.Range(source, start, end+1), dur: d}, nil
}

// rangeErrorAt builds the duration error of the range token starting at
// `start`. The reference raises it after its scanner has advanced past the `[`
// with Next, which clears the line and keeps the column of the `[` token: the
// 1-based character column on its line. That number is the reported start; it
// equals the byte offset of the duration only when nothing multi-byte or
// multi-line precedes the `[`.
func (l *lexer) rangeErrorAt(start, end int) error {
	lineStart := strings.LastIndexByte(l.source[:start], '\n') + 1
	col := utf8.RuneCountInString(l.source[lineStart:start]) + 1
	to := utf8.RuneCountInString(l.source[:end])
	return languageErrorCode("syntax.duration", "syntax", "invalid duration", syntax.SourceRange{StartByte: col, EndByte: max(col, end), StartRune: col, EndRune: max(col, to)})
}

// word classifies an identifier-shaped run: reserved word, function word that
// reads as a call, or plain identifier.
func (l *lexer) word(start, end int) token {
	s := l.source[start:end]
	lower, _ := regexcompat.ToLower(l.p, s)
	span := syntax.Range(l.source, start, end)
	if alwaysKeywords[lower] || isFunctionWord(lower) && l.readsAsCall(end) {
		return token{kind: "kw", text: lower, value: s, span: span}
	}
	return token{kind: "ident", text: s, value: s, span: span}
}

// readsAsCall mirrors the reference's call test: after optional white space the
// text continues with `(`, or with `by`/`without` then optional white space and
// `(`.
func (l *lexer) readsAsCall(from int) bool {
	rest := strings.TrimLeftFunc(l.source[from:], unicode.IsSpace)
	if strings.HasPrefix(rest, "(") {
		return true
	}
	lower := strings.ToLower(rest)
	for _, g := range []string{"by", "without"} {
		if strings.HasPrefix(lower, g) {
			return strings.HasPrefix(strings.TrimLeftFunc(rest[len(g):], unicode.IsSpace), "(")
		}
	}
	return false
}
