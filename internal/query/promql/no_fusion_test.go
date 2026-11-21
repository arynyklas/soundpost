// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"math"
	"math/big"
	"testing"
)

// The recorded observations come from unfused (amd64) arithmetic. The Go
// compiler may fuse x*y+z into one rounding on arm64, ppc64 and s390x, so the
// products in numeric code are wrapped in float64(...). These tests compare
// against a reference where every operation rounds to 53 bits (math/big), and
// require that the inputs are discriminating: at least one case must differ
// from the fused (math.FMA) result. On amd64 they pass trivially because the
// compiler never fuses there; on arm64 they fail if a conversion is removed.

func bf(x float64) *big.Float {
	return new(big.Float).SetPrec(53).SetMode(big.ToNearestEven).SetFloat64(x)
}

func bop(op byte, a, b *big.Float) *big.Float {
	z := new(big.Float).SetPrec(53).SetMode(big.ToNearestEven)
	switch op {
	case '+':
		return z.Add(a, b)
	case '-':
		return z.Sub(a, b)
	case '*':
		return z.Mul(a, b)
	default:
		return z.Quo(a, b)
	}
}

func bits64(b *big.Float) float64 { f, _ := b.Float64(); return f }

func lcg(state *uint64) float64 {
	*state = *state*6364136223846793005 + 1442695040888963407
	return 1 + float64(*state>>11)/float64(1<<53)*7
}

func TestInterpolationAndVarianceRoundProductsSeparately(t *testing.T) {
	state := uint64(42)
	discriminating := 0
	for i := 0; i < 2000; i++ {
		a, b, q := lcg(&state), lcg(&state), lcg(&state)-1
		if q >= 1 {
			q = 0.5
		}
		// functionQuantile over two values: a*(1-q) + b*q.
		w := bop('-', bf(1), bf(q))
		want := bits64(bop('+', bop('*', bf(a), w), bop('*', bf(b), bf(q))))
		if a > b {
			a, b = b, a
			want = bits64(bop('+', bop('*', bf(a), w), bop('*', bf(b), bf(q))))
		}
		fused := math.FMA(b, q, a*(1-q))
		if fused != want {
			discriminating++
		}
		if got := functionQuantile(q, []float64{a, b}); got != want {
			t.Fatalf("quantile(%v,[%v %v]) = %016x, unfused reference %016x", q, a, b, math.Float64bits(got), math.Float64bits(want))
		}
		// functionVariance over three values: m2 += d*(x-mean).
		c := lcg(&state)
		xs := []float64{a, b, c}
		mean, m2 := bf(0), bf(0)
		for j, x := range xs {
			d := bop('-', bf(x), mean)
			mean = bop('+', mean, bop('/', d, bf(float64(j+1))))
			m2 = bop('+', m2, bop('*', d, bop('-', bf(x), mean)))
		}
		wantVar := bits64(bop('/', m2, bf(3)))
		if got := functionVariance(xs); got != wantVar {
			t.Fatalf("variance(%v) = %016x, unfused reference %016x", xs, math.Float64bits(got), math.Float64bits(wantVar))
		}
	}
	if discriminating == 0 {
		t.Fatal("no input distinguishes fused from unfused interpolation; the table is useless")
	}
}
