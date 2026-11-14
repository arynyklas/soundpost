// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package value

import (
	"math"

	portablemath "github.com/arynyklas/soundpost/third_party/portablemath/go127"
)

// Ln is the natural logarithm (math.Log) and Log10 the decimal logarithm, with every product rounded
// separately (see Log2). The pinned reference engines are amd64 builds whose math.Log is assembly
// that does not normalise a subnormal argument; Ln and Log10 reproduce that result for subnormals
// (see subnormalLog) and the portable algorithm everywhere else.
func Ln(x float64) float64 {
	if x > 0 && x < 0x1p-1022 {
		return subnormalLog(x)
	}
	return portablemath.Log(x)
}

// Log10 is math.Log(x) * (1/Ln10), as the standard library computes it.
func Log10(x float64) float64 {
	if x > 0 && x < 0x1p-1022 {
		return float64(subnormalLog(x) * (1 / math.Ln10))
	}
	return portablemath.Log10(x)
}

// subnormalLog is the amd64 assembly math.Log of a positive subnormal x: the exponent field is read
// as 0 (k = -1022, no normalisation) and the mantissa bits as the fraction of [0.5, 1), after which
// the algorithm of the portable Log runs unchanged. So Ln(5e-324) is -709.0895657128241, not the
// mathematical -744.4400719213812. The reduction compares with HSqrt2 as the assembly does
// (f1 <= Sqrt2/2 halves k), every product rounded separately.
func subnormalLog(x float64) float64 {
	const (
		Ln2Hi = 6.93147180369123816490e-01 /* 3fe62e42 fee00000 */
		Ln2Lo = 1.90821492927058770002e-10 /* 3dea39ef 35793c76 */
		L1    = 6.666666666666735130e-01   /* 3FE55555 55555593 */
		L2    = 3.999999999940941908e-01   /* 3FD99999 9997FA04 */
		L3    = 2.857142874366239149e-01   /* 3FD24924 94229359 */
		L4    = 2.222219843214978396e-01   /* 3FCC71C5 1D8E78AF */
		L5    = 1.818357216161805012e-01   /* 3FC74664 96CB03DE */
		L6    = 1.531383769920937332e-01   /* 3FC39A09 D078C69F */
		L7    = 1.479819860511658591e-01   /* 3FC2F112 DF3E5244 */
	)
	f1 := math.Float64frombits(math.Float64bits(x)&0x000FFFFFFFFFFFFF | 0x3FE0000000000000)
	k := -1022.0
	if f1 <= math.Sqrt2/2 {
		f1 *= 2
		k--
	}
	f := f1 - 1
	s := f / (2 + f)
	s2 := float64(s * s)
	s4 := float64(s2 * s2)
	t1 := float64(s2 * (L1 + float64(s4*(L3+float64(s4*(L5+float64(s4*L7)))))))
	t2 := float64(s4 * (L2 + float64(s4*(L4+float64(s4*L6)))))
	R := t1 + t2
	hfsq := float64(float64(0.5*f) * f)
	return float64(k*Ln2Hi) - ((hfsq - (float64(s*(hfsq+R)) + float64(k*Ln2Lo))) - f)
}

// Log2 is the binary logarithm with every product rounded separately, so the result is the same
// on every architecture and equals the amd64 result of math.Log2. math.Log2 is compiled with
// fused multiply-adds on arm64 and can differ in the last bit.
func Log2(x float64) float64 { return portablemath.Log2(x) }

// Exp2 is 2**x by the portable algorithm amd64 uses, with every product rounded separately.
// math.Exp2 is assembly on arm64, loong64 and riscv64 and can differ by 1-2 ulp.
func Exp2(x float64) float64 { return portablemath.Exp2(x) }
