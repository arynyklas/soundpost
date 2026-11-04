// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"encoding/binary"
	"math/bits"
	"soundpost/internal/model"
)

// metricLabelBytes is the pinned label byte identity: FE prefix, FF between
// name/value components, with no trailing separator. It is not a record ID.
func metricLabelBytes(labels model.Labels) []byte { return metricAppendLabelBytes(nil, labels) }
func metricAppendLabelBytes(out []byte, labels model.Labels) []byte {
	n := 1
	for _, l := range labels {
		n += len(l.Name) + len(l.Value) + 2
	}
	if cap(out) < n {
		out = make([]byte, 0, n)
	}
	out = append(out[:0], 254)
	for i, l := range labels {
		if i > 0 {
			out = append(out, 255)
		}
		out = append(out, l.Name...)
		out = append(out, 255)
		out = append(out, l.Value...)
	}
	return out
}

// Stream hashing is deliberately different from sketch-label byte encoding:
// sorted name, FF, value, FF components have no leading FE marker.
func metricStreamHashBytes(out []byte, labels model.Labels) []byte {
	n := 0
	for _, l := range labels {
		n += len(l.Name) + len(l.Value) + 2
	}
	if cap(out) < n {
		out = make([]byte, 0, n)
	}
	out = out[:0]
	for _, l := range labels {
		out = append(out, l.Name...)
		out = append(out, 255)
		out = append(out, l.Value...)
		out = append(out, 255)
	}
	return out
}

// metricXXH64 implements the public XXH64 arithmetic specification with seed 0.
// No telemetry engine is imported or invoked.
func metricXXH64(data []byte) uint64 {
	const a uint64 = 11400714785074694791
	const b uint64 = 14029467366897019727
	const c uint64 = 1609587929392839161
	const d uint64 = 9650029242287828579
	const e uint64 = 2870177450012600261
	round := func(acc, word uint64) uint64 { return bits.RotateLeft64(acc+word*b, 31) * a }
	size := len(data)
	h := e
	if size >= 32 {
		state := [4]uint64{a, b, 0, 0}
		state[0] += b
		state[3] -= a
		for len(data) >= 32 {
			for lane := range state {
				state[lane] = round(state[lane], binary.LittleEndian.Uint64(data[lane*8:]))
			}
			data = data[32:]
		}
		h = bits.RotateLeft64(state[0], 1) + bits.RotateLeft64(state[1], 7) + bits.RotateLeft64(state[2], 12) + bits.RotateLeft64(state[3], 18)
		for _, v := range state {
			h = (h^round(0, v))*a + d
		}
	}
	h += uint64(size)
	for len(data) >= 8 {
		h = bits.RotateLeft64(h^round(0, binary.LittleEndian.Uint64(data)), 27)*a + d
		data = data[8:]
	}
	if len(data) >= 4 {
		h = bits.RotateLeft64(h^(uint64(binary.LittleEndian.Uint32(data))*a), 23)*b + c
		data = data[4:]
	}
	for _, v := range data {
		h = bits.RotateLeft64(h^(uint64(v)*e), 11) * a
	}
	h ^= h >> 33
	h *= b
	h ^= h >> 29
	h *= c
	return h ^ (h >> 32)
}
