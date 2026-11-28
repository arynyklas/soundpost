// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import "strconv"

// ScalarFromCanonical returns the Scalar that Scalar.UnmarshalJSON would build from raw, for the forms
// where that is raw itself, without the JSON decode and encode it costs: null, the booleans, an integer
// in its shortest form that fits an int64, and a string of printable ASCII that the encoder writes
// unescaped (no quote, backslash, '<', '>' or '&') of at most 4096 bytes. Any other text reports false,
// and the caller decodes it with UnmarshalJSON. A page stores a Scalar as its canonical text, so the
// values a page decodes are of these forms but for escaped or non-ASCII strings.
func ScalarFromCanonical(raw string) (Scalar, bool) {
	switch raw {
	case "null", "true", "false":
		return Scalar{raw: raw}, true
	}
	n := len(raw)
	if n == 0 {
		return Scalar{}, false
	}
	if raw[0] == '"' {
		if n < 2 || n > 4098 || raw[n-1] != '"' {
			return Scalar{}, false
		}
		for i := 1; i < n-1; i++ {
			switch c := raw[i]; {
			case c < 0x20 || c > 0x7e, c == '"', c == '\\', c == '<', c == '>', c == '&':
				return Scalar{}, false
			}
		}
		return Scalar{raw: raw}, true
	}
	digits := raw
	if raw[0] == '-' {
		digits = raw[1:]
	}
	if len(digits) == 0 || len(digits) > 19 || digits[0] == '0' && (len(digits) > 1 || raw[0] == '-') {
		return Scalar{}, false
	}
	for i := range len(digits) {
		if digits[i] < '0' || digits[i] > '9' {
			return Scalar{}, false
		}
	}
	if _, err := strconv.ParseInt(raw, 10, 64); err != nil {
		return Scalar{}, false
	}
	return Scalar{raw: raw}, true
}
