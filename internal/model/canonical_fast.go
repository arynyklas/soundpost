// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
)

// canonicalizeJSON rewrites b, which must be the output of json.Marshal, into the canonical form
// CanonicalJSON has always produced: object members sorted by key, strings without HTML escaping,
// numbers as written. It is what decoding b into an `any` (numbers kept as literals) and encoding it
// again with HTML escaping off gives, without building the generic tree: that round trip was a fifth
// of the CPU of the server at the single-host gate (perf of L2w20Admission6/p1).
func canonicalizeJSON(b []byte) ([]byte, error) {
	out := make([]byte, 0, len(b))
	out, rest, err := canonValue(out, b)
	if err != nil || len(bytes.TrimLeft(rest, " \t\r\n")) != 0 {
		return nil, errors.New("canonical json: malformed input")
	}
	return out, nil
}

var errCanon = errors.New("canonical json: malformed input")

func skipSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\r' || b[0] == '\n') {
		b = b[1:]
	}
	return b
}

func canonValue(dst, b []byte) ([]byte, []byte, error) {
	b = skipSpace(b)
	if len(b) == 0 {
		return nil, nil, errCanon
	}
	switch b[0] {
	case '{':
		return canonObject(dst, b[1:])
	case '[':
		return canonArray(dst, b[1:])
	case '"':
		s, rest, err := canonString(dst, b)
		return s, rest, err
	}
	// a number or true, false, null: copied as written
	i := 0
	for i < len(b) && b[i] != ',' && b[i] != '}' && b[i] != ']' && b[i] != ' ' && b[i] != '\t' && b[i] != '\r' && b[i] != '\n' {
		i++
	}
	if i == 0 {
		return nil, nil, errCanon
	}
	return append(dst, b[:i]...), b[i:], nil
}

func canonArray(dst, b []byte) ([]byte, []byte, error) {
	dst = append(dst, '[')
	b = skipSpace(b)
	if len(b) > 0 && b[0] == ']' {
		return append(dst, ']'), b[1:], nil
	}
	for first := true; ; first = false {
		if !first {
			dst = append(dst, ',')
		}
		var err error
		if dst, b, err = canonValue(dst, b); err != nil {
			return nil, nil, err
		}
		b = skipSpace(b)
		if len(b) == 0 {
			return nil, nil, errCanon
		}
		if b[0] == ']' {
			return append(dst, ']'), b[1:], nil
		}
		if b[0] != ',' {
			return nil, nil, errCanon
		}
		b = b[1:]
	}
}

type canonMember struct {
	key   string
	token []byte // the canonical encoding of the key, quotes included
	value []byte // the canonical encoding of the value
}

func canonObject(dst, b []byte) ([]byte, []byte, error) {
	b = skipSpace(b)
	if len(b) > 0 && b[0] == '}' {
		return append(dst, '{', '}'), b[1:], nil
	}
	var members []canonMember
	for {
		b = skipSpace(b)
		if len(b) == 0 || b[0] != '"' {
			return nil, nil, errCanon
		}
		token, key, rest, err := canonKey(b)
		if err != nil {
			return nil, nil, err
		}
		rest = skipSpace(rest)
		if len(rest) == 0 || rest[0] != ':' {
			return nil, nil, errCanon
		}
		var value []byte
		if value, b, err = canonValue(nil, rest[1:]); err != nil {
			return nil, nil, err
		}
		members = append(members, canonMember{key, token, value})
		b = skipSpace(b)
		if len(b) == 0 {
			return nil, nil, errCanon
		}
		if b[0] == '}' {
			b = b[1:]
			break
		}
		if b[0] != ',' {
			return nil, nil, errCanon
		}
		b = b[1:]
	}
	if !slices.IsSortedFunc(members, func(x, y canonMember) int { return strings.Compare(x.key, y.key) }) {
		slices.SortStableFunc(members, func(x, y canonMember) int { return strings.Compare(x.key, y.key) })
	}
	dst = append(dst, '{')
	for i, m := range members {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, m.token...)
		dst = append(dst, ':')
		dst = append(dst, m.value...)
	}
	return append(dst, '}'), b, nil
}

// stringEnd returns the length of the string token at the start of b (b[0] == '"') and whether it holds
// a backslash.
func stringEnd(b []byte) (n int, escaped bool, ok bool) {
	for i := 1; i < len(b); i++ {
		switch b[i] {
		case '\\':
			escaped = true
			i++
		case '"':
			return i + 1, escaped, true
		}
	}
	return 0, false, false
}

// canonString appends the canonical encoding of the string token at the start of b: a token without an
// escape is already canonical (json.Marshal escapes every character the canonical form escapes); one with
// escapes is decoded and encoded again without HTML escaping.
func canonString(dst, b []byte) ([]byte, []byte, error) {
	n, escaped, ok := stringEnd(b)
	if !ok {
		return nil, nil, errCanon
	}
	if !escaped {
		return append(dst, b[:n]...), b[n:], nil
	}
	enc, _, err := canonEscaped(b[:n])
	if err != nil {
		return nil, nil, err
	}
	return append(dst, enc...), b[n:], nil
}

func canonKey(b []byte) (token []byte, key string, rest []byte, err error) {
	n, escaped, ok := stringEnd(b)
	if !ok {
		return nil, "", nil, errCanon
	}
	if !escaped {
		return b[:n], string(b[1 : n-1]), b[n:], nil
	}
	token, key, err = canonEscaped(b[:n])
	return token, key, b[n:], err
}

func canonEscaped(tok []byte) ([]byte, string, error) {
	var s string
	if err := json.Unmarshal(tok, &s); err != nil {
		return nil, "", errCanon
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, "", err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte{'\n'}), s, nil
}
