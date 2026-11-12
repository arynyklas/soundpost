// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"
	"soundpost/internal/query/value"
	"testing"
)

// TestInvalidOperationNaNBitsAreCanonical pins that a NaN created by an invalid floating-point
// operation (inf-inf, 0/0, inf*0) carries the amd64 hardware-default bits on every architecture:
// the recorded native observations hold 0xfff8000000000000 for these, and arm64 hardware would
// otherwise produce 0x7ff8000000000000.
func TestInvalidOperationNaNBitsAreCanonical(t *testing.T) {
	inf, zero := math.Inf(1), math.Float64frombits(0)
	want := value.DefaultNaNBits
	check := func(name string, got float64) {
		t.Helper()
		if bits := math.Float64bits(got); bits != want {
			t.Errorf("%s = %#x, want %#x", name, bits, want)
		}
	}
	for _, op := range []struct {
		op   string
		a, b float64
	}{{"-", inf, inf}, {"+", inf, -inf}, {"/", zero, zero}, {"/", inf, inf}, {"*", inf, zero}} {
		got, _, _ := floatOperator(op.op, op.a, op.b)
		check("floatOperator "+op.op, got)
	}
	check("stdvar_over_time([+Inf])", functionRangeVariance([]float64{inf}))
	check("stdvar([+Inf,-Inf])", functionVariance([]float64{inf, -inf}))
	check("quantile(0, [NaN,-Inf,2,+Inf])", functionQuantile(0, []float64{math.Float64frombits(0x7ff8000000000000), -inf, 2, inf}))
	check("quantile(1, [NaN,-Inf,2,+Inf])", functionQuantile(1, []float64{math.Float64frombits(0x7ff8000000000000), -inf, 2, inf}))
}

// TestInputNaNPayloadsSurviveArithmetic pins that an input NaN is passed through with its payload.
func TestInputNaNPayloadsSurviveArithmetic(t *testing.T) {
	for _, bits := range []uint64{0x7ff8000000000000, 0x7ff8000000000001, 0x7ff8000000000123, 0xfff8000000000000} {
		in := math.Float64frombits(bits)
		for _, op := range []string{"+", "-", "*", "/"} {
			if got, _, _ := floatOperator(op, in, 2); math.Float64bits(got) != bits {
				t.Errorf("%#x %s 2 = %#x", bits, op, math.Float64bits(got))
			}
		}
	}
}
