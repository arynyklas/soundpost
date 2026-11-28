// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"encoding/binary"
	"testing"
)

// The index-block cache never holds more than indexBlockCacheBytes, however many blocks pass through it: a put
// beyond the bound of a shard evicts the least recently used blocks of that shard, and the newest block stays.
func TestBlockCacheEvictsAtItsBound(t *testing.T) {
	const blockSize = 128 << 10
	data := make([]byte, blockSize) // one buffer stands for every block: the cache never copies or writes it
	ref := func(i int) []byte {
		b := make([]byte, 25)
		b[0] = 1
		binary.BigEndian.PutUint32(b[1:], uint32(i))
		binary.BigEndian.PutUint64(b[5:], uint64(i)*(blockSize+37)) // a record carries a header: offsets are not block aligned
		return b
	}
	var c blockCache
	total := 3 * indexBlockCacheBytes / blockSize // three times what the cache may hold
	for i := range total {
		c.put(ref(i), data, 10, 0)
	}
	held, blocks := 0, 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		if s.used > indexBlockCacheBytes/blockCacheShards {
			t.Fatalf("shard %d holds %d bytes, over its bound %d", i, s.used, indexBlockCacheBytes/blockCacheShards)
		}
		held += s.used
		blocks += s.lru.Len()
		s.mu.Unlock()
	}
	if held > indexBlockCacheBytes || held != blocks*blockSize {
		t.Fatalf("the cache holds %d bytes in %d blocks, bound %d", held, blocks, indexBlockCacheBytes)
	}
	if held < indexBlockCacheBytes/2 {
		t.Fatalf("the cache holds only %d bytes after %d blocks: it evicts far below its bound", held, total)
	}
	if _, ok := c.get(ref(total - 1)); !ok {
		t.Fatal("the newest block was evicted")
	}
	if _, ok := c.get(ref(0)); ok {
		t.Fatal("the oldest block is still cached after three times the bound passed through")
	}
}
