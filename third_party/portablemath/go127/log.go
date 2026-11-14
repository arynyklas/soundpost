// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package portablemath carries the portable (non-assembly) algorithms of Go 1.27.3's math.Log,
// math.Log10, math.Log2 and math.Exp2 with every product rounded separately.
//
// Go's compiler may fuse x*y+z into one rounding on arm64, loong64, ppc64, riscv64 and s390x, and
// math.Exp2 is assembly on arm64, loong64 and riscv64. On amd64 neither happens, so the same inputs
// produce results that differ in the last bit. Every product below that feeds an addition or
// subtraction is wrapped in an explicit float64 conversion, which the Go specification defines as
// preventing fusion, so results are identical on every architecture and equal to the amd64 results
// of the standard library.
package portablemath

import "math"

// Log returns the natural logarithm of x by the algorithm of the standard library's unexported
// math.log (FreeBSD's e_log.c), which amd64 also computes (in assembly), with every product rounded
// separately. The special cases are the same as for math.Log.
func Log(x float64) float64 {
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

	// special cases
	switch {
	case math.IsNaN(x) || math.IsInf(x, 1):
		return x
	case x < 0:
		return math.NaN()
	case x == 0:
		return math.Inf(-1)
	}

	// reduce
	f1, ki := math.Frexp(x)
	if f1 < math.Sqrt2/2 {
		f1 *= 2
		ki--
	}
	f := f1 - 1
	k := float64(ki)

	// compute
	s := f / (2 + f)
	s2 := float64(s * s)
	s4 := float64(s2 * s2)
	t1 := float64(s2 * (L1 + float64(s4*(L3+float64(s4*(L5+float64(s4*L7)))))))
	t2 := float64(s4 * (L2 + float64(s4*(L4+float64(s4*L6)))))
	R := t1 + t2
	hfsq := float64(float64(0.5*f) * f)
	return float64(k*Ln2Hi) - ((hfsq - (float64(s*(hfsq+R)) + float64(k*Ln2Lo))) - f)
}

// Log10 returns the decimal logarithm of x, computed as the standard library's math.Log10 does but
// without fused multiply-adds. The special cases are the same as for Log.
func Log10(x float64) float64 {
	return float64(Log(x) * (1 / math.Ln10))
}

// Log2 returns the binary logarithm of x, computed as the standard library's pure-Go math.Log2
// does but without fused multiply-adds. The special cases are the same as for math.Log.
func Log2(x float64) float64 {
	frac, exp := math.Frexp(x)
	// Make sure exact powers of two give an exact answer.
	// Don't depend on Log(0.5)*(1/Ln2)+exp being exactly exp-1.
	if frac == 0.5 {
		return float64(exp - 1)
	}
	return float64(Log(frac)*(1/math.Ln2)) + float64(exp)
}
