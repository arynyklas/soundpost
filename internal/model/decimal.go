// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"errors"
	"strconv"
)

// Uint64 and Int64 are exact decimal-string wire integers. Internal arithmetic
// remains primitive; ordinary string fields do not acquire numeric validation.
type Uint64 uint64
type Int64 int64

func (v Uint64) MarshalJSON() ([]byte, error) {
	out := make([]byte, 1, 22)
	out[0] = '"'
	out = strconv.AppendUint(out, uint64(v), 10)
	return append(out, '"'), nil
}
func (v Int64) MarshalJSON() ([]byte, error) {
	out := make([]byte, 1, 22)
	out[0] = '"'
	out = strconv.AppendInt(out, int64(v), 10)
	return append(out, '"'), nil
}
func (v *Uint64) UnmarshalJSON(raw []byte) error {
	magnitude, _, err := decodeDecimal(raw, false)
	if err != nil {
		return err
	}
	*v = Uint64(magnitude)
	return nil
}
func (v *Int64) UnmarshalJSON(raw []byte) error {
	magnitude, negative, err := decodeDecimal(raw, true)
	if err != nil {
		return err
	}
	*v = Int64(decimalSigned(magnitude, negative))
	return nil
}
func decimalSigned(magnitude uint64, negative bool) int64 {
	if negative {
		return -int64(magnitude-1) - 1
	}
	return int64(magnitude)
}
func decimalSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

// Normal quoted digits take a no-allocation path. JSON-escaped strings use the
// uncommon unescape path so existing decoded-string C01 semantics are retained.
// All numeric grammar and overflow validation is shared by the semantic scalars.
func decodeDecimal(raw []byte, signed bool) (uint64, bool, error) {
	for len(raw) > 0 && decimalSpace(raw[0]) {
		raw = raw[1:]
	}
	for len(raw) > 0 && decimalSpace(raw[len(raw)-1]) {
		raw = raw[:len(raw)-1]
	}
	if len(raw) < 3 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return 0, false, errors.New("invalid decimal string")
	}
	digits := raw[1 : len(raw)-1]
	for _, c := range digits {
		if c == '\\' {
			var decoded string
			if json.Unmarshal(raw, &decoded) != nil {
				return 0, false, errors.New("invalid decimal string")
			}
			digits = []byte(decoded)
			break
		}
	}
	negative := false
	if len(digits) > 0 && digits[0] == '-' {
		if !signed {
			return 0, false, errors.New("invalid decimal string")
		}
		negative = true
		digits = digits[1:]
	}
	if len(digits) == 0 || len(digits) > 20 || digits[0] == '0' && (len(digits) != 1 || negative) {
		return 0, false, errors.New("invalid decimal string")
	}
	limit := ^uint64(0)
	if signed {
		limit = uint64(1<<63) - 1
		if negative {
			limit++
		}
	}
	var magnitude uint64
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, false, errors.New("invalid decimal string")
		}
		digit := uint64(c - '0')
		if magnitude > (limit-digit)/10 {
			return 0, false, errors.New("decimal overflow")
		}
		magnitude = magnitude*10 + digit
	}
	return magnitude, negative, nil
}
