// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package value

import "math"

// DefaultNaNBits is the quiet NaN that x86-64 hardware produces for an invalid operation such as
// inf-inf, 0/0 or inf*0 (the "real indefinite": sign set, quiet bit set, zero payload). That is
// what the pinned native reference implementation produced and what the recorded observations
// hold. arm64 hardware produces 0x7ff8000000000000 for the same operations, so which bits a new
// NaN carries would otherwise depend on the machine running the query.
const DefaultNaNBits uint64 = 0xfff8000000000000

// arithNaN fixes the bits of a NaN that an arithmetic operation produced, so that the result does
// not depend on the architecture:
//
//   - neither operand is NaN: the NaN is new, from an invalid operation, and carries DefaultNaNBits;
//   - both operands are NaN: the second operand's NaN is returned (hardware picks the first or the
//     second one depending on the instruction and the operand order the compiler chose);
//   - exactly one operand is NaN: hardware already returns that operand's payload quieted, on every
//     architecture, so r is returned unchanged.
//
// Non-NaN results are returned unchanged. NaNs that originate in a math library call (math.NaN,
// math.Mod, math.Pow, ...) are not produced by this path and keep the library's bits.
func arithNaN(r, a, b float64) float64 {
	if r == r {
		return r
	}
	if a != a {
		if b != b {
			return b
		}
		return r
	}
	if b != b {
		return r
	}
	return math.Float64frombits(DefaultNaNBits)
}

// Add is a+b with architecture-independent NaN bits (see arithNaN).
func Add(a, b float64) float64 { return arithNaN(a+b, a, b) }

// Sub is a-b with architecture-independent NaN bits (see arithNaN).
func Sub(a, b float64) float64 { return arithNaN(a-b, a, b) }

// Mul is a*b rounded once, with architecture-independent NaN bits (see arithNaN). The explicit
// conversion keeps compilers from fusing the product into a following addition.
func Mul(a, b float64) float64 { return arithNaN(float64(a*b), a, b) }

// Div is a/b with architecture-independent NaN bits (see arithNaN).
func Div(a, b float64) float64 { return arithNaN(a/b, a, b) }
