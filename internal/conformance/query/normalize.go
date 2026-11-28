// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"
)

// NormalizeFloat converts upstream decimal encodings without equating stale NaN
// to ordinary NaN. Stale bits require an explicit bit-valued transport.
func NormalizeFloat(text string) (string, error) {
	v, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%016x", math.Float64bits(v)), nil
}

// NormalizeSeconds accepts exact decimal JSON timestamps; float64 arithmetic is
// forbidden because it destroys nanosecond ties at contemporary epoch values.
func NormalizeSeconds(value json.Number) (string, error) {
	r, ok := new(big.Rat).SetString(string(value))
	if !ok {
		return "", fmt.Errorf("invalid timestamp")
	}
	r.Mul(r, big.NewRat(1000000000, 1))
	if !r.IsInt() {
		return "", fmt.Errorf("sub-nanosecond timestamp")
	}
	if !r.Num().IsInt64() {
		return "", fmt.Errorf("timestamp outside int64 nanoseconds")
	}
	return r.Num().String(), nil
}
func ValidateFloatBits(bits string) error {
	b, e := hex.DecodeString(bits)
	if e != nil || len(b) != 8 {
		return fmt.Errorf("float bits must contain exactly 16 hex digits")
	}
	return nil
}
