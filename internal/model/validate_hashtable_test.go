// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"fmt"
	"strings"
	"testing"
)

// TestValidateJSONHashTablePathMatchesReference: random byte-level generators reach the
// >16-key table path only in documents that ALREADY have a duplicate in the first 17 keys
// (tiny key alphabet), so a mutant that only breaks the table duplicate check can survive a
// fuzzer (an independent review showed mutant M13 survived one). This test walks the table
// path deterministically against the reference validator:
// objects of DISTINCT keys with a duplicate injected at every position past the
// threshold, including the 17-key switch, the 33-key growth (64 -> 128 slots)
// and re-insertion on growth.
func TestValidateJSONHashTablePathMatchesReference(t *testing.T) {
	const maxKeys = 300
	doc := func(n int, dupAt int, spell string) string {
		var b strings.Builder
		b.WriteByte('{')
		for i := range n {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `"k%d":%d`, i, i)
		}
		if dupAt >= 0 {
			fmt.Fprintf(&b, `,%s:%d`, spell, 999)
		}
		b.WriteByte('}')
		return b.String()
	}
	// spellings that decode to an existing key, an escape spelling, and a
	// fresh key.
	spellings := []struct{ spell, why string }{
		{`"k0"`, "raw duplicate of first key"},
		{`"k17"`, "raw duplicate at the table boundary"},
		{`"k18"`, "raw duplicate just past it"},
		{`"\u006b0"`, "escaped duplicate of first key"},
		{`"k\u00317"`, "escaped duplicate mid-table"},
		{`"zzz"`, "fresh key (control: must stay valid)"},
	}
	compared, accepted, rejected := 0, 0, 0
	for n := range maxKeys + 1 {
		for _, sp := range spellings {
			for _, dup := range []bool{false, true} {
				dupAt := -1
				if dup {
					dupAt = 0
				}
				in := []byte(doc(n, dupAt, sp.spell))
				got := ValidateJSON(in)
				ref := referenceValidateJSON(in)
				compared++
				if (got == nil) != (ref == nil) {
					t.Fatalf("n=%d %s dup=%v: reference=%v new=%v doc=%s", n, sp.why, dup, ref, got, in[max(0, len(in)-160):])
				}
				if got == nil {
					accepted++
				} else {
					rejected++
				}
			}
		}
	}
	// duplicate at EVERY position of a 200-key object once the table is active
	for d := range 200 {
		in := fmt.Sprintf(`{"k0":0`)
		var b strings.Builder
		b.WriteByte('{')
		for i := range 200 {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `"k%d":%d`, i, i)
		}
		fmt.Fprintf(&b, `,"k%d":9}`, d)
		_ = in
		docB := []byte(b.String())
		got, ref := ValidateJSON(docB), referenceValidateJSON(docB)
		compared++
		if (got == nil) != (ref == nil) || got == nil {
			t.Fatalf("dup at k%d in 200-key object: reference=%v new=%v", d, ref, got)
		}
		rejected++
	}
	// growth boundaries: the table doubles at 33, 65, 129, 257 keys; the last
	// key duplicates the FIRST one (worst case for a re-insert bug: every
	// earlier probe of the duplicate hits the same home bucket only after the
	// table moved).
	for _, n := range []int{16, 17, 18, 31, 32, 33, 34, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1000, 4096} {
		dupFirst := append(append([]byte(doc(n, -1, "")[:len(doc(n, -1, ""))-1]), ','), []byte(`"k0":9}`)...)
		if e := ValidateJSON(dupFirst); e == nil {
			t.Fatalf("n=%d: duplicate of first key accepted", n)
		}
		if e := referenceValidateJSON(dupFirst); e == nil {
			t.Fatalf("n=%d: reference accepts duplicate", n)
		}
		if e := ValidateJSON([]byte(doc(n, -1, ""))); e != nil {
			t.Fatalf("n=%d: distinct keys rejected: %v", n, e)
		}
		compared += 2
		rejected++
	}
	t.Logf("%d comparisons: %d accepted, %d rejected by both, 0 divergences", compared, accepted, rejected)
}
