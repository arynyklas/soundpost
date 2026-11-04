// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"soundpost/internal/query/syntax"
	"strconv"
	"strings"
	"unicode/utf8"
)

func lex(s string) ([]token, error) {
	var out []token
	brackets := 0
	bad := func(a, b int, msg string) ([]token, error) {
		return nil, &syntax.LanguageError{Category: "syntax", Range: syntax.Range(s, a, b), SafeMessage: msg}
	}
	for i := 0; i < len(s); {
		start := i
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && n == 1 {
			return bad(i, i+1, "invalid UTF-8")
		}
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			i += n
			continue
		}
		if r == '#' {
			for i < len(s) && s[i] != '\n' {
				i++
			}
			continue
		}
		if r == '"' || r == '\'' || r == '`' {
			q := byte(r)
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
				return bad(start, len(s), "unterminated string")
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
					return bad(start, i, "invalid string escape")
				}
			}
			out = append(out, token{s[start:i], v, start, i, "string"})
			continue
		}
		if asciiLetter(r) || r == '_' || r == ':' && brackets == 0 {
			durationUnit := len(out) > 0 && out[len(out)-1].kind == "number" && out[len(out)-1].end == start
			i += n
			for i < len(s) {
				c, z := utf8.DecodeRuneInString(s[i:])
				if (durationUnit || brackets > 0) && c == ':' {
					break
				}
				if !asciiLetter(c) && !(c >= '0' && c <= '9') && c != '_' && c != ':' {
					break
				}
				i += z
			}
			out = append(out, token{s[start:i], s[start:i], start, i, "ident"})
			continue
		}
		if r >= '0' && r <= '9' || r == '.' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
			i++
			hex := r == '0' && i < len(s) && (s[i] == 'x' || s[i] == 'X')
			if hex {
				i++
			}
			for i < len(s) {
				c := s[i]
				if c >= '0' && c <= '9' || c == '.' || hex && (c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
					i++
					continue
				}
				if !hex && (c == 'e' || c == 'E') {
					i++
					if i < len(s) && (s[i] == '+' || s[i] == '-') {
						i++
					}
					continue
				}
				break
			}
			out = append(out, token{s[start:i], s[start:i], start, i, "number"})
			continue
		}
		if r == '[' {
			brackets++
		}
		if r == ']' {
			brackets--
		}
		i += n
		if i < len(s) {
			pair := s[start : i+1]
			if pair == "==" || pair == "!=" || pair == "=~" || pair == "!~" || pair == ">=" || pair == "<=" || pair == "</" || pair == ">/" {
				i++
			}
		}
		out = append(out, token{s[start:i], s[start:i], start, i, "punct"})
	}
	out = append(out, token{start: len(s), end: len(s), kind: "eof"})
	return out, nil
}

// Bare PromQL names are ASCII in both reference profiles; quoted UTF-8 names
// are handled as strings. Host Unicode upgrades must not expand lexical syntax.
func asciiLetter(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }
