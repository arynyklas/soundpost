//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"strings"
	"testing"
)

// The marker of what a sweep handed out, and the fullness of a ring (l4w33 mutation battery A, second pass).

// A record is marked as handed out before it is passed on: what the callback sees is a marker already past the record.
func TestSidebandSweepMarksEachRecordBeforeHandingItOut(t *testing.T) {
	r := sidebandRing("aa11cc22")
	var ends []uint64
	end := uint64(0)
	for _, at := range []uint64{10, 20, 30} {
		spec := defaultMmap2()
		spec.at = at
		rec := mmap2Record(spec)
		end += uint64(len(rec))
		ends = append(ends, end)
		push(r, rec)
	}
	var seen []uint64
	if err := r.sweepSideband(func(KernelRecordView) error { seen = append(seen, r.sideTaken); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 || seen[0] != ends[0] || seen[1] != ends[1] || seen[2] != ends[2] {
		t.Fatalf("the marker seen by the callback %v, want the end of each record %v", seen, ends)
	}
}

// A ring that holds exactly as many bytes as it has room for is full, not overwritten: it is swept whole.
func TestSidebandSweepAcceptsARingThatIsExactlyFull(t *testing.T) {
	r := sidebandRing("aa11cc22")
	spec := defaultMmap2()
	spec.name = strings.Repeat("a", 159) // a record of exactly 256 bytes
	if len(mmap2Record(spec)) != 256 {
		t.Fatalf("test record is %d bytes", len(mmap2Record(spec)))
	}
	for i := range len(r.data) / 256 {
		spec.at = uint64(100 + i)
		push(r, mmap2Record(spec))
	}
	if r.head()-r.tail() != uint64(len(r.data)) {
		t.Fatalf("the ring holds %d of %d bytes", r.head()-r.tail(), len(r.data))
	}
	events := sweepAll(t, r)
	if len(events) != len(r.data)/256 {
		t.Fatalf("%d events from a full ring, want %d", len(events), len(r.data)/256)
	}
}
