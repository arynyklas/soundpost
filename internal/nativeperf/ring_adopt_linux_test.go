//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"unsafe"
)

// 04.02-C16 mutation battery re-run (mut0402, P-S02/P-S07): a real kernel always writes the layout the openers expect, so
// the refusal of an unexpected one was unreachable in the openers themselves. Both ring openers now end in
// Ring.adoptMapping; the test hands it mappings whose metadata page claims a layout of the test's own.

func fakePerfMapping(t *testing.T, mappingBytes int, offset, size uint64) []byte {
	t.Helper()
	m, e := syscall.Mmap(-1, 0, mappingBytes, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if e != nil {
		t.Skip("cannot map anonymous memory:", e)
	}
	*(*uint64)(unsafe.Pointer(&m[1040])) = offset
	*(*uint64)(unsafe.Pointer(&m[1048])) = size
	return m
}

func TestAdoptMappingAcceptsOnlyTheExactPerfLayout(t *testing.T) {
	page := uint64(os.Getpagesize())
	ring := 16 * page
	for _, tc := range []struct {
		name         string
		mappingBytes uint64
		offset, size uint64
		want         bool
	}{
		{"the kernel's layout: one metadata page, the ring, nothing after it", page + ring, page, ring, true},
		{"data area starting at the mapping's start", page + ring, 0, ring, false},
		{"data area starting a page late", 2*page + ring, 2 * page, ring, false},
		{"data area one page short", page + ring, page, ring - page, false},
		{"data area one page long", 2*page + ring, page, ring + page, false},
		{"a mapping longer than the data area it ends", 2*page + ring, page, ring, false},
		{"a mapping shorter than the data area claims", page + ring, page, ring + 8, false},
		{"offset and size that only add up to the mapping", page + ring, 2 * page, ring - page, false},
	} {
		mapping := fakePerfMapping(t, int(tc.mappingBytes), tc.offset, tc.size)
		r := &Ring{}
		e := r.adoptMapping(mapping, ring)
		switch {
		case tc.want && e != nil:
			t.Errorf("%s: %v", tc.name, e)
		case tc.want && (uint64(len(r.data)) != ring || uint64(len(r.meta)) != page || uint64(len(r.mapping)) != tc.mappingBytes || r.closed):
			t.Errorf("%s: data %d bytes, meta %d bytes, mapping %d bytes, closed %v", tc.name, len(r.data), len(r.meta), len(r.mapping), r.closed)
		case tc.want && (&r.data[0] != &mapping[page] || &r.meta[0] != &mapping[0]):
			t.Errorf("%s: the data area and the metadata page are not the mapping's own pages", tc.name)
		case !tc.want && !errors.Is(e, ErrRingMalformed):
			t.Errorf("%s: %v, want ErrRingMalformed", tc.name, e)
		case !tc.want && (r.data != nil || r.meta != nil || r.mapping != nil || !r.closed):
			t.Errorf("%s: refused ring still holds its mapping (data %d meta %d mapping %d closed %v)", tc.name, len(r.data), len(r.meta), len(r.mapping), r.closed)
		}
		if tc.want {
			r.Close()
		} else if r.mapping == nil {
			continue
		} else {
			syscall.Munmap(mapping)
		}
	}
}
