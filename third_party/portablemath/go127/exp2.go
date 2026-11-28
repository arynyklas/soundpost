// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portablemath

import "math"

// Exp2 returns 2**x, the base-2 exponential of x, by the portable algorithm of the standard
// library's unexported math.exp2 (the one amd64 uses) with every product rounded separately. It
// does not use the assembly implementation that math.Exp2 selects on arm64, loong64 and riscv64.
//
// Special cases are the same as for math.Exp.
func Exp2(x float64) float64 {
	const (
		Ln2Hi = 6.93147180369123816490e-01
		Ln2Lo = 1.90821492927058770002e-10

		Overflow  = 1.0239999999999999e+03
		Underflow = -1.0740e+03
	)

	// special cases
	switch {
	case math.IsNaN(x):
		return x
	case x > Overflow: // handles case where x is +∞
		return math.Inf(1)
	case x < Underflow: // handles case where x is -∞
		return 0
	}

	// argument reduction; x = r×lg(e) + k with |r| ≤ ln(2)/2.
	// computed as r = hi - lo for extra precision.
	var k int
	switch {
	case x > 0:
		k = int(x + 0.5)
	case x < 0:
		k = int(x - 0.5)
	}
	t := x - float64(k)
	hi := float64(t * Ln2Hi)
	lo := float64(-t * Ln2Lo)

	// compute
	return expmulti(hi, lo, k)
}

// expmulti returns e**r × 2**k where r = hi - lo and |r| ≤ ln(2)/2.
func expmulti(hi, lo float64, k int) float64 {
	const (
		P1 = 1.66666666666666657415e-01  /* 0x3FC55555; 0x55555555 */
		P2 = -2.77777777770155933842e-03 /* 0xBF66C16C; 0x16BEBD93 */
		P3 = 6.61375632143793436117e-05  /* 0x3F11566A; 0xAF25DE2C */
		P4 = -1.65339022054652515390e-06 /* 0xBEBBBD41; 0xC5D26BF1 */
		P5 = 4.13813679705723846039e-08  /* 0x3E663769; 0x72BEA4D0 */
	)

	r := hi - lo
	t := float64(r * r)
	c := r - float64(t*(P1+float64(t*(P2+float64(t*(P3+float64(t*(P4+float64(t*P5)))))))))
	y := 1 - ((lo - float64(float64(r*c)/(2-c))) - hi)
	// TODO(rsc): make sure Ldexp can handle boundary k
	return math.Ldexp(y, k)
}
