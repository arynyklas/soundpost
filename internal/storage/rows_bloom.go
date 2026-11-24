// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"encoding/binary"
)

// A bloom filter per run of the row store (rows.go): a point read (does this receipt exist, is this metric
// sample stored, where is this page) asks every run of the store, and a run has no cheap way to say "not
// here" for a random key, so each run carries a filter of its keys, kept in the registry beside its meta
// (rowRunBloomKey) and written with the run. A filter has no false negatives for the keys the run held when it
// was written; a key deleted from the run afterwards stays in it (a false positive, which the run then
// answers "not here" itself).
//
// The filter is blocked: the keys hash to one 64-byte block, the probes of one key all fall in it, so a probe
// costs one cache line however large the filter is.
//
//	byte   bloomVersion
//	byte   probes per key
//	u32    number of 64-byte blocks (>= 1)
//	blocks * 64 bytes
const (
	bloomVersion    = 1
	bloomHeader     = 1 + 1 + 4
	bloomBlockBytes = 64
	bloomBlockBits  = bloomBlockBytes * 8
	bloomBitsPerKey = 12
	bloomProbes     = 6
	bloomMinBlocks  = 1
	bloomMaxBlocks  = 1 << 24 // 1 GiB of filter: far more than any run of the row store reaches
)

// bloomHash returns the two 64-bit hashes of a key the filter derives its block and probes from (FNV-1a
// with a finalizer: stable across processes and releases, as the filter is persisted).
func bloomHash(key []byte) (h1, h2 uint64) {
	h := uint64(14695981039346656037)
	for _, c := range key {
		h ^= uint64(c)
		h *= 1099511628211
	}
	h1 = h
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h1, h
}

// bloomBuilder collects the keys of one run.
type bloomBuilder struct {
	raw []byte
	n   uint32 // blocks
}

// newBloomBuilder sizes a filter for about keys keys.
func newBloomBuilder(keys int64) *bloomBuilder {
	blocks := (keys*bloomBitsPerKey + bloomBlockBits - 1) / bloomBlockBits
	blocks = min(max(blocks, bloomMinBlocks), bloomMaxBlocks)
	raw := make([]byte, bloomHeader+int(blocks)*bloomBlockBytes)
	raw[0], raw[1] = bloomVersion, bloomProbes
	binary.BigEndian.PutUint32(raw[2:], uint32(blocks))
	return &bloomBuilder{raw: raw, n: uint32(blocks)}
}

func bloomProbe(h1, h2 uint64, i int) uint {
	return uint(h2+uint64(i)*(h1|1)) & (bloomBlockBits - 1)
}

func (b *bloomBuilder) add(key []byte) {
	h1, h2 := bloomHash(key)
	block := b.raw[bloomHeader+int((h1>>32)*uint64(b.n)>>32)*bloomBlockBytes:][:bloomBlockBytes]
	for i := range bloomProbes {
		bit := bloomProbe(h1, h2, i)
		block[bit>>3] |= 1 << (bit & 7)
	}
}

// bytes is the encoded filter.
func (b *bloomBuilder) bytes() []byte { return b.raw }

// bloomMayHold reports whether the filter raw may hold the key whose hashes are h1, h2. A filter that does
// not parse holds everything (the run is then asked).
func bloomMayHold(raw []byte, h1, h2 uint64) bool {
	if len(raw) < bloomHeader+bloomBlockBytes || raw[0] != bloomVersion || raw[1] != bloomProbes {
		return true
	}
	n := uint64(binary.BigEndian.Uint32(raw[2:]))
	if n == 0 || uint64(len(raw)-bloomHeader) != n*bloomBlockBytes {
		return true
	}
	block := raw[bloomHeader+int((h1>>32)*n>>32)*bloomBlockBytes:][:bloomBlockBytes]
	for i := range bloomProbes {
		bit := bloomProbe(h1, h2, i)
		if block[bit>>3]&(1<<(bit&7)) == 0 {
			return false
		}
	}
	return true
}
