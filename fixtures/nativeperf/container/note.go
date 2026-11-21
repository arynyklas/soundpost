//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
)

// The helper reads the workload's GNU build ID through the PT_NOTE program headers. A Go executable linked with
// `-ldflags "-B gobuildid"` has the note section but its PT_NOTE segment stops at the Go build ID note, so no
// segment-based reader finds it. This is the same repair tools/smoke/native_helper_container.go applies to its workload
// (that file is package main of another command, so the three functions are repeated here, not shared).

func noteDescriptor(b []byte) (string, error) {
	if len(b) < 16 {
		return "", errors.New("build ID note too short")
	}
	nameSize, descSize := binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint32(b[4:])
	start := 12 + (uint64(nameSize)+3)&^3
	if descSize == 0 || start+uint64(descSize) > uint64(len(b)) {
		return "", errors.New("invalid build ID note bounds")
	}
	return hex.EncodeToString(b[start : start+uint64(descSize)]), nil
}

// sectionBuildID is the GNU build ID of the .note.gnu.build-id section.
func sectionBuildID(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	s := f.Section(".note.gnu.build-id")
	if s == nil {
		return "", errors.New("no .note.gnu.build-id section")
	}
	b, err := s.Data()
	if err != nil {
		return "", err
	}
	return noteDescriptor(b)
}

// segmentBuildID walks the PT_NOTE segments exactly as the helper does (internal/nativeperf executableBuildID).
func segmentBuildID(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(raw) < 64 || !bytes.Equal(raw[:4], []byte{0x7f, 'E', 'L', 'F'}) || raw[4] != 2 || raw[5] != 1 {
		return "", errors.New("not a little-endian ELF64")
	}
	order := binary.LittleEndian
	phoff, phnum, phsize := order.Uint64(raw[32:]), order.Uint16(raw[56:]), order.Uint16(raw[54:])
	if phsize != 56 {
		return "", errors.New("unexpected program header size")
	}
	for i := uint16(0); i < phnum; i++ {
		ph := raw[phoff+uint64(i)*56:]
		if order.Uint32(ph) != 4 {
			continue
		}
		start, length := order.Uint64(ph[8:]), order.Uint64(ph[32:])
		if start+length > uint64(len(raw)) {
			return "", errors.New("PT_NOTE outside the file")
		}
		b := raw[start : start+length]
		for len(b) >= 12 {
			n, d, typ := order.Uint32(b), order.Uint32(b[4:]), order.Uint32(b[8:])
			b = b[12:]
			nn, dd := (uint64(n)+3)&^3, (uint64(d)+3)&^3
			if nn+dd > uint64(len(b)) {
				return "", errors.New("invalid note")
			}
			if typ == 3 && bytes.Equal(bytes.TrimRight(b[:n], "\x00"), []byte("GNU")) && d > 0 && d <= 64 {
				return hex.EncodeToString(b[nn : nn+uint64(d)]), nil
			}
			b = b[nn+dd:]
		}
	}
	return "", errors.New("no GNU build ID inside any PT_NOTE segment")
}

// exposeBuildID extends the PT_NOTE segment that ends where the .note.gnu.build-id section starts so that it covers
// that note; a segment that already covers it is left alone. It then requires the helper's own walk to find the same ID.
func exposeBuildID(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	section := f.Section(".note.gnu.build-id")
	type note struct {
		index         int
		off, filesize uint64
	}
	var notes []note
	for i, p := range f.Progs {
		if p.Type == elf.PT_NOTE {
			notes = append(notes, note{i, p.Off, p.Filesz})
		}
	}
	f.Close()
	if section == nil {
		return "", errors.New("the workload has no .note.gnu.build-id section (build it with -ldflags \"-B gobuildid\")")
	}
	covered := false
	for _, n := range notes {
		if n.off <= section.Offset && n.off+n.filesize >= section.Offset+section.Size {
			covered = true
		}
	}
	if !covered {
		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return "", err
		}
		var header [64]byte
		if _, err = file.ReadAt(header[:], 0); err != nil {
			file.Close()
			return "", err
		}
		phoff, phsize := binary.LittleEndian.Uint64(header[32:]), binary.LittleEndian.Uint16(header[54:])
		if phsize != 56 {
			file.Close()
			return "", errors.New("unexpected program header size")
		}
		patched := false
		for _, n := range notes {
			if n.off+n.filesize == section.Offset {
				var sizes [16]byte
				binary.LittleEndian.PutUint64(sizes[0:], n.filesize+section.Size)
				binary.LittleEndian.PutUint64(sizes[8:], n.filesize+section.Size)
				// p_filesz at +32, p_memsz at +40 of the ELF64 program header
				if _, err = file.WriteAt(sizes[:], int64(phoff)+int64(n.index)*56+32); err != nil {
					file.Close()
					return "", err
				}
				patched = true
				break
			}
		}
		if err = file.Close(); err != nil {
			return "", err
		}
		if !patched {
			return "", errors.New("no PT_NOTE segment is adjacent to the GNU build ID note")
		}
	}
	want, err := sectionBuildID(path)
	if err != nil {
		return "", err
	}
	got, err := segmentBuildID(path)
	if err != nil || got != want {
		return "", errors.New("the workload's build ID is still hidden from the helper's PT_NOTE walk")
	}
	return want, nil
}
