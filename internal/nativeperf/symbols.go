// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"sort"
)

// Only ordinary ELF64 little-endian amd64/arm64 code and symbol metadata is
// interpreted. No DWARF bytecode, decompression, external debug links, source
// filenames, subprocesses or network fetches are executed/followed.
type imageReader struct {
	*bytes.Reader
	data []byte
}

func newImageReader(b []byte) imageReader { return imageReader{Reader: bytes.NewReader(b), data: b} }

type elfSegment struct{ offset, address, size uint64 }
type elfSymbol struct {
	start, end uint64
	name       string
}
type elfSymbolInfo struct {
	buildID string
	symbols []elfSymbol
}

func (e elfSymbolInfo) lookup(offset uint64) (string, bool) {
	index := sort.Search(len(e.symbols), func(i int) bool { return e.symbols[i].start > offset }) - 1
	if index < 0 {
		return "", false
	}
	// Overlapping ELF symbols can be aliases, but must not invent an extent.
	// Refuse ambiguity rather than borrowing another symbol's later end.
	symbol := e.symbols[index]
	if offset >= symbol.end {
		return "", false
	}
	return symbol.name, true
}

type boundedELF struct {
	ctx       context.Context
	input     io.ReaderAt
	max, read uint64
}

func (r *boundedELF) at(offset, size uint64) ([]byte, error) {
	if e := r.ctx.Err(); e != nil {
		return nil, e
	}
	if size > r.max || offset > r.max-size || r.read > r.max-size {
		return nil, ErrResourceBudget
	}
	r.read += size
	if image, ok := r.input.(imageReader); ok {
		if offset > uint64(len(image.data)) || size > uint64(len(image.data))-offset {
			return nil, ErrInvalid
		}
		return image.data[offset : offset+size], nil
	}
	b := make([]byte, int(size))
	if _, e := r.input.ReadAt(b, int64(offset)); e != nil {
		return nil, ErrInvalid
	}
	return b, nil
}
func safeNativeSymbol(name string) bool {
	if len(name) == 0 || len(name) > 256 {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '$' || c == '@' || c == ':') {
			return false
		}
	}
	return true
}

type elfLayout struct {
	buildID         string
	loads           []elfSegment
	shOffset        uint64
	shSize, shCount uint16
}

func (e elfLayout) codeOffset(offset uint64) bool {
	for _, load := range e.loads {
		if offset >= load.offset && offset-load.offset < load.size {
			return true
		}
	}
	return false
}
func readELFLayout(r *boundedELF) (elfLayout, error) {
	result := elfLayout{}
	header, e := r.at(0, 64)
	if e != nil {
		return result, e
	}
	o := binary.LittleEndian
	if !bytes.Equal(header[:7], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1}) || (o.Uint16(header[16:]) != 2 && o.Uint16(header[16:]) != 3) || (o.Uint16(header[18:]) != 62 && o.Uint16(header[18:]) != 183) || o.Uint32(header[20:]) != 1 || o.Uint16(header[52:]) != 64 {
		return result, ErrInvalid
	}
	phOffset, phSize, phCount := o.Uint64(header[32:]), o.Uint16(header[54:]), o.Uint16(header[56:])
	result.shOffset, result.shSize, result.shCount = o.Uint64(header[40:]), o.Uint16(header[58:]), o.Uint16(header[60:])
	if phSize != 56 || phCount == 0 || phCount > 128 {
		return result, ErrInvalid
	}
	ph, e := r.at(phOffset, uint64(phSize)*uint64(phCount))
	if e != nil {
		return result, e
	}
	result.loads = make([]elfSegment, 0, phCount)
	for i := range int(phCount) {
		p := ph[i*56 : (i+1)*56]
		typ, flags := o.Uint32(p), o.Uint32(p[4:])
		offset, address, size := o.Uint64(p[8:]), o.Uint64(p[16:]), o.Uint64(p[32:])
		if offset > r.max || size > r.max-offset || address > ^uint64(0)-size {
			return result, ErrInvalid
		}
		if typ == 1 && flags&1 != 0 {
			result.loads = append(result.loads, elfSegment{offset, address, size})
		}
		if typ != 4 {
			continue
		}
		if size > 65536 {
			return result, ErrResourceBudget
		}
		notes, e := r.at(offset, size)
		if e != nil {
			return result, e
		}
		for len(notes) > 0 {
			if len(notes) < 12 {
				for _, v := range notes {
					if v != 0 {
						return result, ErrInvalid
					}
				}
				break
			}
			names, desc, kind := o.Uint32(notes), o.Uint32(notes[4:]), o.Uint32(notes[8:])
			notes = notes[12:]
			namesAligned, descAligned := (uint64(names)+3)&^3, (uint64(desc)+3)&^3
			if namesAligned > uint64(len(notes)) || descAligned > uint64(len(notes))-namesAligned {
				return result, ErrInvalid
			}
			if kind == 3 && names == 4 && bytes.Equal(notes[:4], []byte{'G', 'N', 'U', 0}) {
				if desc == 0 || desc > 64 || result.buildID != "" {
					return result, ErrInvalid
				}
				result.buildID = hex.EncodeToString(notes[namesAligned : namesAligned+uint64(desc)])
			}
			notes = notes[namesAligned+descAligned:]
		}
	}
	if result.buildID == "" || len(result.loads) == 0 {
		return result, ErrInvalid
	}
	return result, nil
}
func readELFSymbols(ctx context.Context, input io.ReaderAt, maxBytes uint64, maxSymbols uint32) (elfSymbolInfo, error) {
	result := elfSymbolInfo{}
	if maxBytes == 0 || maxBytes > 32<<20 || maxSymbols == 0 || maxSymbols > 65536 {
		return result, ErrResourceBudget
	}
	r := boundedELF{ctx: ctx, input: input, max: maxBytes}
	layout, e := readELFLayout(&r)
	if e != nil {
		return result, e
	}
	result.buildID = layout.buildID
	loads, shOffset, shSize, shCount := layout.loads, layout.shOffset, layout.shSize, layout.shCount
	if shSize != 64 || shCount == 0 || shCount > 4096 {
		return result, ErrInvalid
	}
	o := binary.LittleEndian
	sections, e := r.at(shOffset, uint64(shSize)*uint64(shCount))
	if e != nil {
		return result, e
	}
	for i := range int(shCount) {
		sh := sections[i*64 : (i+1)*64]
		typ := o.Uint32(sh[4:])
		if typ != 2 && typ != 11 {
			continue
		}
		offset, size, entrySize, link := o.Uint64(sh[24:]), o.Uint64(sh[32:]), o.Uint64(sh[56:]), o.Uint32(sh[40:])
		if entrySize != 24 || size%24 != 0 || link >= uint32(shCount) {
			return result, ErrInvalid
		}
		if size/24 > uint64(maxSymbols) || uint64(len(result.symbols))+size/24 > uint64(maxSymbols) {
			return result, ErrResourceBudget
		}
		strSection := sections[int(link)*64 : (int(link)+1)*64]
		if o.Uint32(strSection[4:]) != 3 {
			return result, ErrInvalid
		}
		strings, e := r.at(o.Uint64(strSection[24:]), o.Uint64(strSection[32:]))
		if e != nil {
			return result, e
		}
		symbols, e := r.at(offset, size)
		if e != nil {
			return result, e
		}
		for j := range int(size / 24) {
			if e := ctx.Err(); e != nil {
				return result, e
			}
			symbol := symbols[j*24 : (j+1)*24]
			nameOffset, info, sectionIndex, value, length := o.Uint32(symbol), symbol[4], o.Uint16(symbol[6:]), o.Uint64(symbol[8:]), o.Uint64(symbol[16:])
			if info&15 != 2 || sectionIndex == 0 || sectionIndex >= shCount || length == 0 || value > ^uint64(0)-length {
				continue
			}
			if uint64(nameOffset) >= uint64(len(strings)) {
				return result, ErrInvalid
			}
			nameBytes := strings[nameOffset:]
			if len(nameBytes) > 257 {
				nameBytes = nameBytes[:257]
			}
			end := bytes.IndexByte(nameBytes, 0)
			if end < 0 {
				continue
			}
			name := string(nameBytes[:end])
			if !safeNativeSymbol(name) {
				continue
			}
			for _, load := range loads {
				if value >= load.address && value-load.address < load.size && length <= load.size-(value-load.address) {
					start := load.offset + (value - load.address)
					result.symbols = append(result.symbols, elfSymbol{start, start + length, name})
					break
				}
			}
		}
	}
	sort.Slice(result.symbols, func(i, j int) bool {
		if result.symbols[i].start != result.symbols[j].start {
			return result.symbols[i].start < result.symbols[j].start
		}
		if result.symbols[i].end != result.symbols[j].end {
			return result.symbols[i].end < result.symbols[j].end
		}
		return result.symbols[i].name < result.symbols[j].name
	})
	return result, nil
}
