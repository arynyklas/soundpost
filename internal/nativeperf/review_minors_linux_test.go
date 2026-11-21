//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package nativeperf

import "testing"

// The m2 minors of 04.04: a perf ring mapping must be exactly metadata page + data area (the data area ends where the
// mapping ends), and an acquisition proof must bound a nonzero instant.
func TestRingLayoutRequiresExactTriple(t *testing.T) {
	const page, ring = 4096, 65536
	cases := []struct {
		name         string
		offset, size uint64
		mappingBytes int
		want         bool
	}{
		{"exact layout", page, ring, page + ring, true},
		{"data offset moved", 2 * page, ring, page + ring, false},
		{"data size smaller", page, ring / 2, page + ring, false},
		{"data size larger", page, 2 * ring, page + ring, false},
		{"data area ends before the mapping ends", page, ring, 2*page + ring, false},
		{"data area ends after the mapping ends", page, ring, ring, false},
	}
	for _, c := range cases {
		if got := ringLayoutOK(c.offset, c.size, c.mappingBytes, page, ring); got != c.want {
			t.Errorf("%s: ringLayoutOK = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAcquisitionProofRejectsZeroThrough(t *testing.T) {
	good := AcquisitionProof{Domain: correlationDomain, CPUs: []uint32{0, 1}, Through: 1}
	if !good.valid() {
		t.Fatal("a nonzero proof over a sorted CPU set must be valid")
	}
	zero := good
	zero.Through = 0
	if zero.valid() {
		t.Fatal("a zero Through would trivially pass any progress check")
	}
	zero.Final = true
	if zero.valid() {
		t.Fatal("a zero final proof must be refused too")
	}
	unsorted := good
	unsorted.CPUs = []uint32{1, 0}
	if unsorted.valid() {
		t.Fatal("unsorted CPU set accepted")
	}
}
