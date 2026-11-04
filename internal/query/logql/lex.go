// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"soundpost/internal/query/profile"
	"soundpost/internal/query/regexcompat"
	"soundpost/internal/query/syntax"
	"strconv"
	"strings"
	"unicode/utf8"
)

func lex(source string, p profile.Profile) ([]token, error) {
	if !utf8.ValidString(source) {
		for i := 0; i < len(source); {
			r, w := utf8.DecodeRuneInString(source[i:])
			if r == utf8.RuneError && w == 1 {
				return nil, languageErrorCode("syntax.encoding", "syntax", "invalid UTF-8", syntax.Range(source, i, i+1))
			}
			i += w
		}
	}
	if i := strings.IndexByte(source, 0); i >= 0 {
		return nil, languageErrorCode("syntax.nul", "syntax", "invalid NUL character", syntax.Range(source, i, i+1))
	}
	var out []token
	for pos := 0; pos < len(source); {
		start := pos
		r, w := utf8.DecodeRuneInString(source[pos:])
		if r == utf8.RuneError && w == 1 {
			return nil, languageErrorCode("syntax.encoding", "syntax", "invalid UTF-8", syntax.Range(source, pos, pos+1))
		}
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' || pos == 0 && r == '\ufeff' {
			pos += w
			continue
		}
		if r == '#' || strings.HasPrefix(source[pos:], "//") {
			for pos < len(source) && source[pos] != '\n' {
				pos++
			}
			continue
		}
		if strings.HasPrefix(source[pos:], "/*") {
			end := strings.Index(source[pos+2:], "*/")
			if end < 0 {
				return nil, languageErrorCode("syntax.comment", "syntax", "unterminated comment", syntax.Range(source, pos, len(source)))
			}
			pos += end + 4
			continue
		}
		if r == '"' || r == '`' {
			quote := byte(r)
			pos++
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
				return nil, languageErrorCode("syntax.string", "syntax", "unterminated string", syntax.Range(source, start, pos))
			}
			raw := source[start:pos]
			if !utf8.ValidString(raw) || strings.ContainsRune(raw, 0) {
				return nil, languageErrorCode("syntax.encoding", "syntax", "invalid string encoding", syntax.Range(source, start, pos))
			}
			value, err := strconv.Unquote(raw)
			if err != nil {
				return nil, languageErrorCode("syntax.string-escape", "syntax", "invalid string escape", syntax.Range(source, start, pos))
			}
			out = append(out, token{"string", raw, value, syntax.Range(source, start, pos)})
			continue
		}
		letter, _ := regexcompat.IsLetter(p, r)
		if r == '_' || letter {
			pos += w
			for pos < len(source) {
				r, w = utf8.DecodeRuneInString(source[pos:])
				letter, _ = regexcompat.IsLetter(p, r)
				digit, _ := regexcompat.IsDigit(p, r)
				if r != '_' && !letter && !digit {
					break
				}
				pos += w
			}
			s := source[start:pos]
			out = append(out, token{"ident", canonicalWord(p, s), s, syntax.Range(source, start, pos)})
			continue
		}
		if r >= '0' && r <= '9' || r == '.' && pos+1 < len(source) && source[pos+1] >= '0' && source[pos+1] <= '9' {
			pos += w
			for pos < len(source) {
				c := source[pos]
				if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '_' || c >= 128 {
					_, w = utf8.DecodeRuneInString(source[pos:])
					pos += w
					continue
				}
				if (c == '+' || c == '-') && pos > start && (source[pos-1] == 'e' || source[pos-1] == 'E' || source[pos-1] == 'p' || source[pos-1] == 'P') {
					pos++
					continue
				}
				break
			}
			s := source[start:pos]
			out = append(out, token{"number", s, s, syntax.Range(source, start, pos)})
			continue
		}
		matched := ""
		for _, op := range []string{"--strict", "--keep-empty", "|=", "|~", "|>", "!=", "!~", "!>", "=~", "==", ">=", "<="} {
			if strings.HasPrefix(source[pos:], op) {
				matched = op
				break
			}
		}
		if matched != "" {
			pos += len(matched)
		} else if strings.ContainsRune("{}()[],|=<>+-*/%^", r) {
			matched = string(r)
			pos += w
		} else {
			return nil, languageError("parse", "unexpected character", syntax.Range(source, pos, pos+w))
		}
		out = append(out, token{matched, matched, matched, syntax.Range(source, start, pos)})
	}
	out = append(out, token{kind: "eof", span: syntax.Range(source, len(source), len(source))})
	return out, nil
}
func canonicalWord(p profile.Profile, s string) string {
	lower, _ := regexcompat.ToLower(p, s)
	if aggregateNames[lower] || rangeNames[lower] {
		return lower
	}
	switch lower {
	case "or", "and", "unless", "by", "without", "bool", "on", "ignoring", "group_left", "group_right", "offset", "json", "logfmt", "regexp", "pattern", "unpack", "decolorize", "line_format", "label_format", "unwrap", "drop", "keep", "ip", "bytes", "duration", "duration_seconds", "vector", "label_replace", "variants", "of":
		return lower
	}
	return s
}
