// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package value

import portablemath "soundpost/third_party/portablemath/go127"

// Ln is the natural logarithm (math.Log) and Log10 the decimal logarithm, with every product rounded
// separately (see Log2).
func Ln(x float64) float64    { return portablemath.Log(x) }
func Log10(x float64) float64 { return portablemath.Log10(x) }

// Log2 is the binary logarithm with every product rounded separately, so the result is the same
// on every architecture and equals the amd64 result of math.Log2. math.Log2 is compiled with
// fused multiply-adds on arm64 and can differ in the last bit.
func Log2(x float64) float64 { return portablemath.Log2(x) }

// Exp2 is 2**x by the portable algorithm amd64 uses, with every product rounded separately.
// math.Exp2 is assembly on arm64, loong64 and riscv64 and can differ by 1-2 ulp.
func Exp2(x float64) float64 { return portablemath.Exp2(x) }
