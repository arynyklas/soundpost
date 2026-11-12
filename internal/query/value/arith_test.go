// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package value

import (
	"math"
	"testing"
)

// TestArithmeticNaNBitsAreCanonical: a NaN produced by an invalid operation encodes as the same bits
// on every architecture (the amd64 hardware default), operand NaNs keep their payload, and
// non-NaN results are untouched.
func TestArithmeticNaNBitsAreCanonical(t *testing.T) {
	inf, ninf, zero := math.Inf(1), math.Inf(-1), math.Float64frombits(0) // runtime values: no constant folding
	input := math.Float64frombits(0x7ff8000000000000)
	other := math.Float64frombits(0x7ff8000000000123)
	cases := []struct {
		name string
		got  float64
		want uint64
	}{
		{"inf-inf", Sub(inf, inf), DefaultNaNBits},
		{"inf+-inf", Add(inf, ninf), DefaultNaNBits},
		{"0/0", Div(zero, zero), DefaultNaNBits},
		{"inf/inf", Div(inf, inf), DefaultNaNBits},
		{"inf*0", Mul(inf, zero), DefaultNaNBits},
		{"-inf*0", Mul(ninf, zero), DefaultNaNBits},
		{"input+1 keeps payload", Add(input, 1), 0x7ff8000000000000},
		{"1*payload keeps payload", Mul(1, other), 0x7ff8000000000123},
		{"both NaN: second operand", Add(input, math.Float64frombits(DefaultNaNBits)), DefaultNaNBits},
		{"both NaN: second operand 2", Sub(math.Float64frombits(DefaultNaNBits), other), 0x7ff8000000000123},
		{"finite", Add(1, 2), math.Float64bits(3)},
		{"inf", Add(inf, 1), math.Float64bits(inf)},
		{"div by zero", Div(1, zero), math.Float64bits(inf)},
	}
	for _, c := range cases {
		if bits := math.Float64bits(c.got); bits != c.want {
			t.Errorf("%s = %#x, want %#x", c.name, bits, c.want)
		}
	}
}
