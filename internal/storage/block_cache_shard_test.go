// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"encoding/binary"
	"testing"
)

// The blocks of an index run lie at offsets that are multiples of the block size (128 KiB) when nothing
// sits between them. A shard hash that shifts or truncates the offset puts every such block in one shard,
// whose bound (a sixteenth of the cache) then holds a sixteenth of the blocks the cache is sized for.
func TestBlockCacheSpreadsBlockAlignedOffsetsOverItsShards(t *testing.T) {
	const blockSize = 128 << 10
	data := make([]byte, blockSize)
	ref := func(file uint32, i int) []byte {
		b := make([]byte, 25)
		b[0] = 1
		binary.BigEndian.PutUint32(b[1:], file)
		binary.BigEndian.PutUint64(b[5:], uint64(i)*blockSize)
		return b
	}
	for _, files := range []int{1, 3} {
		var c blockCache
		const perFile = 4096 // half of what the cache holds: nothing may be evicted when the blocks spread
		for f := 1; f <= files; f++ {
			for i := range perFile / files {
				c.put(ref(uint32(f), i), data, 10, 0)
			}
		}
		perShard := make([]int, blockCacheShards)
		for f := 1; f <= files; f++ {
			for i := range perFile / files {
				r := ref(uint32(f), i)
				for s := range c.shards {
					if c.shard(r) == &c.shards[s] {
						perShard[s]++
					}
				}
				if _, ok := c.get(r); !ok {
					t.Fatalf("%d files: block %d of file %d was evicted from a cache holding half its bound: %v", files, i, f, perShard)
				}
			}
		}
		mean := perFile / blockCacheShards
		for s, n := range perShard {
			if n < mean/2 || n > mean*2 {
				t.Fatalf("%d files: shard %d holds %d of %d aligned blocks, mean %d: %v", files, s, n, perFile, mean, perShard)
			}
		}
	}
}
