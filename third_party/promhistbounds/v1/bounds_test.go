// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promhistbounds

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"testing"
)

// tableDigest is the SHA-256 of "schema:index:%016x\n" lines over every entry,
// matching the digest recorded in provenance.json for the upstream tables.
const tableDigest = "f21134c635552399c35782d7e915622251d6d91ce0aed7abc59beaa2b92f832c"

func TestTableMatchesPinnedUpstreamDigest(t *testing.T) {
	h := sha256.New()
	entries := 0
	for s := 0; s <= MaxSchema; s++ {
		for i := 0; i < 1<<s; i++ {
			m, ok := Mantissa(s, i)
			if !ok {
				t.Fatalf("schema %d index %d missing", s, i)
			}
			fmt.Fprintf(h, "%d:%d:%016x\n", s, i, math.Float64bits(m))
			entries++
		}
	}
	if entries != 511 {
		t.Fatalf("entries = %d, want 511", entries)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != tableDigest {
		t.Fatalf("table digest %s, want %s", got, tableDigest)
	}
}

func TestTableStructuralInvariants(t *testing.T) {
	for s := 0; s <= MaxSchema; s++ {
		prev := 0.0
		for i := 0; i < 1<<s; i++ {
			m, _ := Mantissa(s, i)
			if m < 0.5 || m >= 1 || m <= prev {
				t.Fatalf("schema %d index %d: %v not strictly ascending in [0.5, 1)", s, i, m)
			}
			prev = m
			if s > 0 && i%2 == 0 {
				parent, _ := Mantissa(s-1, i/2)
				if m != parent {
					t.Fatalf("schema %d index %d != schema %d index %d", s, i, s-1, i/2)
				}
			}
		}
	}
	for _, c := range [][2]int{{-1, 0}, {0, 1}, {9, 0}, {3, 8}, {3, -1}} {
		if _, ok := Mantissa(c[0], c[1]); ok {
			t.Fatalf("Mantissa(%d, %d) reported ok", c[0], c[1])
		}
	}
}
