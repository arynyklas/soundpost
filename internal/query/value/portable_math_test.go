// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package value

import (
	"math"
	"math/rand"
	"testing"
)

func mathInputs(seed int64) []float64 {
	in := []float64{
		0, math.Copysign(0, -1), 1, -1, 0.5, 2, 3, 10, math.E, math.Pi, math.Sqrt2, math.Sqrt2 / 2,
		math.Inf(1), math.Inf(-1), math.NaN(), math.Float64frombits(DefaultNaNBits),
		math.SmallestNonzeroFloat64, -math.SmallestNonzeroFloat64, 2.2250738585072009e-308, 2.2250738585072014e-308,
		math.MaxFloat64, -math.MaxFloat64, 1023.9999999999999, 1024, 1024.0000000000002, -1074, -1074.0000000000002, -1075, -1022, -1023,
		0.9999999999999999, 1.0000000000000002, 709.78, 745.2, -745.2,
	}
	for e := -1074; e <= 1023; e++ {
		p := math.Ldexp(1, e)
		in = append(in, p, math.Nextafter(p, 0), math.Nextafter(p, math.Inf(1)), float64(e), float64(e)+0.5, float64(e)/7)
	}
	for i := 1; i < 5000; i++ {
		in = append(in, float64(i), float64(i)/1024, 1+float64(i)/1e6, math.Ldexp(1, -i%64)*float64(i))
	}
	r := rand.New(rand.NewSource(seed))
	for i := 0; i < 200000; i++ {
		in = append(in, math.Float64frombits(r.Uint64()))           // any bit pattern, subnormals and NaNs included
		in = append(in, r.Float64()*4-2)                            // histogram schema scale
		in = append(in, (r.Float64()-0.5)*2200)                     // whole Exp2 domain
		in = append(in, math.Exp(r.NormFloat64()*20))               // wide positive range for Log2
		in = append(in, float64(r.Intn(8)-4)*(1+r.Float64()*1e-12)) // near small integers
	}
	return in
}

func sameBits(a, b float64) bool {
	if math.IsNaN(a) && math.IsNaN(b) {
		return true
	}
	return math.Float64bits(a) == math.Float64bits(b)
}

// TestPortableMathAgainstStdlib: where the standard library is itself unfused and pure Go for these
// functions (amd64), the portable ports must agree with it bit for bit. On other architectures
// math.Log2/Exp2 differ in the last bits (fused products, assembly Exp2), which is why the ports
// exist, so the comparison runs only on amd64.
func TestPortableMathAgainstStdlib(t *testing.T) {
	if !stdlibIsUnfusedReference {
		t.Skip("math.Log/Log10/Log2/Exp2 are not the unfused reference on this architecture")
	}
	bad := 0
	for _, x := range mathInputs(1) {
		if got, want := Log2(x), math.Log2(x); !sameBits(got, want) {
			if bad++; bad <= 10 {
				t.Errorf("Log2(%x) = %x, math.Log2 = %x", math.Float64bits(x), math.Float64bits(got), math.Float64bits(want))
			}
		}
		// amd64's assembly math.Log (and so math.Log10) does not normalise a subnormal argument
		// (math.Log(5e-324) is -709.09, the mathematical value is -744.44); Ln and Log10 reproduce
		// that, see TestPortableLogSubnormals.
		if got, want := Ln(x), math.Log(x); !sameBits(got, want) {
			if bad++; bad <= 10 {
				t.Errorf("Ln(%x) = %x, math.Log = %x", math.Float64bits(x), math.Float64bits(got), math.Float64bits(want))
			}
		}
		if got, want := Log10(x), math.Log10(x); !sameBits(got, want) {
			if bad++; bad <= 10 {
				t.Errorf("Log10(%x) = %x, math.Log10 = %x", math.Float64bits(x), math.Float64bits(got), math.Float64bits(want))
			}
		}
		if got, want := Exp2(x), math.Exp2(x); !sameBits(got, want) {
			if bad++; bad <= 10 {
				t.Errorf("Exp2(%x) = %x, math.Exp2 = %x", math.Float64bits(x), math.Float64bits(got), math.Float64bits(want))
			}
		}
	}
}

func TestPortableMathSpecialValues(t *testing.T) {
	for _, c := range []struct{ in, log2, exp2 float64 }{
		{0, math.Inf(-1), 1}, {1, 0, 2}, {2, 1, 4}, {0.5, -1, 1.414213562373095}, {8, 3, 256}, {-1, math.NaN(), 0.5},
		{math.Inf(1), math.Inf(1), math.Inf(1)}, {math.Inf(-1), math.NaN(), 0}, {1024, 10, math.Inf(1)}, {-1075, math.NaN(), 0},
	} {
		if got := Log2(c.in); !sameBits(got, c.log2) {
			t.Errorf("Log2(%v) = %v, want %v", c.in, got, c.log2)
		}
		if got := Exp2(c.in); !sameBits(got, c.exp2) {
			t.Errorf("Exp2(%v) = %v, want %v", c.in, got, c.exp2)
		}
	}
	if !math.IsNaN(Log2(math.NaN())) || !math.IsNaN(Exp2(math.NaN())) || !math.IsNaN(Ln(-1)) || !math.IsInf(Ln(0), -1) || !math.IsInf(Log10(0), -1) {
		t.Fatal("special cases of Ln/Log10/Log2/Exp2 differ from math")
	}
}

// TestPortableLogSubnormals: Ln and Log10 of a subnormal follow the pinned amd64 assembly (exponent
// field read as 0, mantissa bits as the fraction of [0.5,1)), on every architecture; Log2 is
// computed through the exported Frexp and stays the mathematical value. The Ln reference is
// -1022*ln2 + ln(f1) with f1 = 0.5*(1+m/2^52), evaluated at normal arguments.
func TestPortableLogSubnormals(t *testing.T) {
	for _, x := range []float64{math.SmallestNonzeroFloat64, 3 * math.SmallestNonzeroFloat64, 0x1p-1050, 0x1p-1030, 1e-310, 2.2250738585072009e-308} {
		m := math.Float64bits(x)
		f1 := 0.5 * (1 + float64(m)/(1<<52))
		wantLn := -1022*math.Ln2 + math.Log(f1)
		if got := Ln(x); math.Abs(got-wantLn) > 1e-9 {
			t.Errorf("Ln(%v) = %v, want %v", x, got, wantLn)
		}
		if got, want := Log10(x), wantLn/math.Ln10; math.Abs(got-want) > 1e-9 {
			t.Errorf("Log10(%v) = %v, want %v", x, got, want)
		}
		scaled := x * 0x1p500
		if got, want := Log2(x), math.Log2(scaled)-500; math.Abs(got-want) > 1e-9 {
			t.Errorf("Log2(%v) = %v, want %v", x, got, want)
		}
	}
	if got := Ln(math.SmallestNonzeroFloat64); got > -709 || got < -710 {
		t.Errorf("Ln(smallest subnormal) = %v, want about -709.09 (not the mathematical -744.44)", got)
	}
}
