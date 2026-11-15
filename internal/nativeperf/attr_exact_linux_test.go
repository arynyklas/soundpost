//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The perf attribute is the whole capture policy: compare it field by field with the approved fixed ABI, so a changed
// selector, sample type, flag, rate or stack bound fails here rather than only on a machine that has perf.
func TestCPUAttrIsExactlyTheApprovedABI(t *testing.T) {
	const flags = 1 | 1<<5 | 1<<6 | 1<<9 | 1<<10 | 1<<13 | 1<<18 | 1<<21 | 1<<24 | 1<<25
	for _, tc := range []struct {
		method SamplingMethod
		typ    uint32
	}{{MethodSoftwareCPUClock, 1}, {MethodHardwareCycles, 0}} {
		for _, frames := range []struct{ asked, stack uint16 }{{1, 1}, {4, 4}, {127, 127}, {128, 127}} {
			a, e := cpuAttr(tc.method, frames.asked)
			want := cpuPerfAttr{Type: tc.typ, Size: 112, Config: 0, Frequency: 99, SampleType: 1 | 2 | 4 | 32 | 128 | 256, Flags: flags, Wakeup: 1, ClockID: 1, SampleMaxStack: frames.stack}
			if e != nil || a != want {
				t.Errorf("%s/%d: %+v (%v), want %+v", tc.method, frames.asked, a, e, want)
			}
		}
		for _, bad := range []uint16{0, 129, 65535} {
			if _, e := cpuAttr(tc.method, bad); !errors.Is(e, ErrInvalid) {
				t.Errorf("%s: maxFrames %d accepted: %v", tc.method, bad, e)
			}
		}
	}
}

func TestSchedulerAttrIsExactlyTheApprovedABI(t *testing.T) {
	cfg := DefaultConfig(1)
	want := func(frames uint16) cpuPerfAttr {
		return cpuPerfAttr{Type: 2, Size: 112, Config: 17, Frequency: 1, SampleType: 2 | 4 | 32 | 128 | 1024, Flags: 1 | 1<<18 | 1<<21 | 1<<24 | 1<<25, Wakeup: 1, ClockID: 1, SampleMaxStack: frames}
	}
	if got := schedulerPerfAttr(NumericLayout{id: 17}, cfg); got != want(127) {
		t.Fatalf("%+v\nwant %+v", got, want(127))
	}
	cfg.MaxFrames = 64
	if got := schedulerPerfAttr(NumericLayout{id: 17}, cfg); got != want(64) {
		t.Fatalf("%+v\nwant %+v", got, want(64))
	}
}

func TestReadFixedMetadataIsBounded(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, n int) string {
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, []byte(strings.Repeat("x", n)), 0o600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	if b, e := readFixedMetadata(write("exact", 100), 100); e != nil || len(b) != 100 {
		t.Fatalf("file of exactly the limit: %d %v", len(b), e)
	}
	if _, e := readFixedMetadata(write("over", 101), 100); !errors.Is(e, ErrInvalid) {
		t.Fatalf("one byte over the limit: %v", e)
	}
	if b, e := readFixedMetadata(write("empty", 0), 100); e != nil || len(b) != 0 {
		t.Fatalf("empty: %d %v", len(b), e)
	}
	if _, e := readFixedMetadata(filepath.Join(dir, "missing"), 100); e == nil {
		t.Fatal("missing file read")
	} else if _, ok := e.(*CapabilityError); !ok {
		t.Fatalf("missing file is not a capability error: %T", e)
	}
}

// ringLayoutOK is a pure function of its arguments: each of the three equalities must hold on its own, even when the
// other two are satisfied by a consistent but wrong triple.
func TestRingLayoutEachEqualityIsIndependent(t *testing.T) {
	const page, ring = 4096, 65536
	for _, c := range []struct {
		name         string
		offset, size uint64
		mappingBytes int
	}{
		{"offset moved, mapping consistent with it", 2 * page, ring, 2*page + ring},
		{"size smaller, offset and mapping consistent with it", page, ring / 2, page + ring/2},
		{"size larger, offset and mapping consistent with it", page, 2 * ring, page + 2*ring},
		{"offset and size swapped consistently", ring, page, ring + page},
	} {
		if ringLayoutOK(c.offset, c.size, c.mappingBytes, page, ring) {
			t.Errorf("%s accepted", c.name)
		}
	}
	if !ringLayoutOK(page, ring, page+ring, page, ring) {
		t.Fatal("exact layout refused")
	}
}
