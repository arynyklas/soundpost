// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sourcemap

// vlq accepts the signed base64-VLQ magnitude within uint32. Intermediate
// arithmetic is widened, so malformed continuations cannot wrap an accumulator.
func vlq(s string, at *int) (int64, error) {
	var value uint64
	for shift := uint(0); shift <= 30; shift += 5 {
		if *at >= len(s) {
			return 0, ErrInvalid
		}
		c := s[*at]
		*at++
		var digit uint64
		switch {
		case c >= 'A' && c <= 'Z':
			digit = uint64(c - 'A')
		case c >= 'a' && c <= 'z':
			digit = uint64(c-'a') + 26
		case c >= '0' && c <= '9':
			digit = uint64(c-'0') + 52
		case c == '+':
			digit = 62
		case c == '/':
			digit = 63
		default:
			return 0, ErrInvalid
		}
		value |= (digit & 31) << shift
		if value > 0x1ffffffff {
			return 0, ErrInvalid
		}
		if digit&32 == 0 {
			m := int64(value >> 1)
			if value&1 != 0 {
				if m == 0 {
					return 0, ErrInvalid
				}
				m = -m
			}
			return m, nil
		}
	}
	return 0, ErrInvalid
}
func delta(previous int64, change int64) (int64, error) {
	v := previous + change
	if v < 0 || v > 0xffffffff {
		return 0, ErrInvalid
	}
	return v, nil
}
