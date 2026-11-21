//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Second pass of the l4w33 mutation battery on the mmap2 decoder and the sideband sweep: the kernel's own constants
// as literals (a drifting constant must fail here instead of moving the encoder of the tests with it).

// A record is accepted up to exactly 8192 bytes and refused above; a build ID is accepted up to the 20 bytes the kernel
// reserves.
func TestMmap2AcceptsTheLargestRecordAndBuildIDTheKernelWrites(t *testing.T) {
	r := sidebandRing("aa11cc22")
	largest := defaultMmap2()
	largest.name = strings.Repeat("a", 8095)
	if b := mmap2Record(largest); len(b) != 8192 {
		t.Fatalf("test record is %d bytes, want 8192", len(b))
	}
	if e, ok, err := decodeOne(t, r, largest); err != nil || !ok || e.Mapping == nil || e.Mapping.BuildID != "aa11cc22" {
		t.Fatalf("a record of 8192 bytes: %+v %v %v", e.Mapping, ok, err)
	}
	over := defaultMmap2()
	over.name = strings.Repeat("a", 8103)
	if b := mmap2Record(over); len(b) != 8200 {
		t.Fatalf("test record is %d bytes, want 8200", len(b))
	}
	if _, ok, err := decodeOne(t, r, over); ok || !errors.Is(err, ErrRingMalformed) {
		t.Fatalf("a record of 8200 bytes: %v %v", ok, err)
	}

	id := make([]byte, 20)
	for i := range id {
		id[i] = byte(i + 1)
	}
	full := defaultMmap2()
	full.build = id
	if e, ok, err := decodeOne(t, sidebandRing(hex.EncodeToString(id)), full); err != nil || !ok || e.Mapping.BuildID != hex.EncodeToString(id) {
		t.Fatalf("a 20-byte build id: %+v %v %v", e.Mapping, ok, err)
	}
}

// The CPU mode of a record is the low three bits of its misc field and only 2 (user) is a user mapping; the build ID
// flag is bit 14 - bit 13 of the same field means something else (a data mapping) and names no build ID.
func TestMmap2ReadsTheKernelsMiscBits(t *testing.T) {
	r := sidebandRing("aa11cc22")
	guest := defaultMmap2()
	guest.misc = 4 // 4|2: the CPU mode field says 6, which is no CPU mode of a user mapping
	if _, ok, err := decodeOne(t, r, guest); ok || !errors.Is(err, ErrRingMalformed) {
		t.Fatalf("an undefined CPU mode: %v %v", ok, err)
	}

	flagged := mmap2Record(defaultMmap2())
	binary.LittleEndian.PutUint16(flagged[4:], 0x4002)
	if e, ok, err := decodeCPURecord(KernelRecordView{first: flagged}, r); err != nil || !ok || e.Mapping.BuildID != "aa11cc22" {
		t.Fatalf("misc 0x4002 (user, build id): %+v %v %v", e.Mapping, ok, err)
	}

	// a file the kernel could not read a build ID from, flagged with bit 13 only: its bytes 44.. are a device and an
	// inode number, not a build ID, even when they happen to spell an approved one
	nobuild := defaultMmap2()
	nobuild.build, nobuild.maj, nobuild.min, nobuild.ino = nil, 8, 1, 4242
	b := mmap2Record(nobuild)
	binary.LittleEndian.PutUint16(b[4:], 0x2002)
	look := sidebandRing("0100000092100000")
	e, ok, err := decodeCPURecord(KernelRecordView{first: b}, look)
	if err != nil || !ok || e.Mapping.BuildID != "" || e.Mapping.Reason != FrameUnapproved {
		t.Fatalf("misc 0x2002 (user, not a build id): %+v %v %v", e.Mapping, ok, err)
	}
}

// One sweep hands out at most 4096 announcements: exactly 4096 are not an overflow, the 4097th is.
func TestSidebandSweepBoundIs4096(t *testing.T) {
	sweep := func(n int) ([]SanitizedEvent, bool) {
		r := sidebandRing("aa11cc22")
		r.data = make([]byte, 1<<20)
		spec := defaultMmap2()
		spec.name = ""
		for i := range n {
			spec.at = uint64(100 + i)
			push(r, mmap2Record(spec))
		}
		events, full, err := sweepRings([]*Ring{r}, ClockDomain{HostID: "host", BootID: "boot"})
		if err != nil {
			t.Fatal(err)
		}
		return events, full
	}
	if events, full := sweep(4096); full || len(events) != 4096 {
		t.Fatalf("4096 announcements: %d events, full %v", len(events), full)
	}
	if events, full := sweep(4097); !full || len(events) != 4096 {
		t.Fatalf("4097 announcements: %d events, full %v", len(events), full)
	}
}

// A ring whose control page is too short for the kernel's header, or that has no data area, is malformed and is never
// swept as an empty ring.
func TestSidebandSweepRefusesARingWithoutControlPageOrData(t *testing.T) {
	noData := sidebandRing("aa11cc22")
	noData.data = nil
	if _, _, err := sweepRings([]*Ring{noData}, ClockDomain{}); !errors.Is(err, ErrRingMalformed) {
		t.Fatalf("no data area: %v", err)
	}
	short := sidebandRing("aa11cc22")
	short.meta = short.meta[:1039]
	if _, _, err := sweepRings([]*Ring{short}, ClockDomain{}); !errors.Is(err, ErrRingMalformed) {
		t.Fatalf("a control page of 1039 bytes: %v", err)
	}
}
