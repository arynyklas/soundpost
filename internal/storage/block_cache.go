// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"container/list"
	"encoding/binary"
	"sync"
	"sync/atomic"

	bolt "go.etcd.io/bbolt"
)

// The index blocks of the final runs live in the payload log, 128 KiB each, and every Seek of a scan fetched the
// block that holds its key from the file: a record read, a zeroed buffer of the block's size and a checksum of all
// of it, for each run of the index, at every chunk of every scan. A 24 h query of one organization makes about
// 1,440 chunk builds, and the ten queries of the Queries gate mix a few thousand a second, all of them into the
// same few thousand blocks: 154 of the 458 CPU seconds of a 60 s profile were the reads of these blocks.
//
// The blocks scans read are kept here, by the reference that names them (the file, the offset, the length and the
// checksum of the record: the bytes a reference names never change until the record is zeroed). A hit costs a map
// lookup and no copy: the cursors only read a block, and the bytes of a cached block are never written.
//
// Consistency. The record of a block is zeroed once nothing names it any more (erasure rewrites the block that
// held an erased pair, a merge replaces the blocks of its inputs, a migration moves them), and a copy of an erased
// block must not outlive the erasure. Every such change owes the zeroing in the write transaction that makes it
// (owePayloadScrub), and that is where the block is forgotten, before the transaction commits and long before
// the zeroing. A reader that began before that commit still names the old reference: its read must not put the
// block back, so a read caches only when the transaction it reads in sees every transaction that owed a zeroing
// (scrubTx, the newest of them, is at or below its own id) and none owed one while the record was being read. The
// check and the insertion are made under the lock of the shard, as forget is, so a forget is either seen by the
// put or undoes it. A write transaction neither reads from the cache nor fills it. Only the cursors of scans
// use it: the verification of the indexes reads the disk, as it is there to do.

// indexBlockCacheBytes bounds the bytes of the blocks cached: 8,192 blocks of 128 KiB. At the gate the indexes
// the interactive queries touch (the time and the posting index of the signals the mix reads) are a few
// thousand blocks, so the working set of the mix is held, and a node of 16 GiB spends one sixteenth of it here.
// The blocks are byte slices without pointers: the collector does not walk them.
const indexBlockCacheBytes = 1 << 30

const blockCacheShards = 16

type blockCache struct {
	shards  [blockCacheShards]blockShard
	scrubTx atomic.Uint64 // the newest write transaction that owed the zeroing of a record
	hits    atomic.Uint64
	misses  atomic.Uint64
}

type blockShard struct {
	mu   sync.Mutex
	used int
	lru  list.List // newest first
	m    map[string]*list.Element
}

type cachedBlock struct {
	ref  string
	data []byte
}

func (c *blockCache) shard(ref []byte) *blockShard {
	// The reference is the marker, the file, the offset, the length and the checksum. The offset of a block
	// is a multiple of 128 KiB when the records between blocks carry no header, so its low 17 bits are
	// zero: a hash that shifts or truncates the offset puts all of them in one shard. The offset and the
	// file go through the finalizer of splitmix64, so every bit of them decides the shard.
	h := binary.BigEndian.Uint64(ref[5:]) + uint64(binary.BigEndian.Uint32(ref[1:]))*0x9e3779b97f4a7c15
	h = (h ^ h>>30) * 0xbf58476d1ce4e5b9
	h = (h ^ h>>27) * 0x94d049bb133111eb
	h ^= h >> 31
	return &c.shards[h%blockCacheShards]
}

func (c *blockCache) get(ref []byte) ([]byte, bool) {
	s := c.shard(ref)
	s.mu.Lock()
	e := s.m[string(ref)]
	if e == nil {
		s.mu.Unlock()
		c.misses.Add(1)
		return nil, false
	}
	s.lru.MoveToFront(e)
	data := e.Value.(*cachedBlock).data
	s.mu.Unlock()
	c.hits.Add(1)
	return data, true
}

// put keeps a block a reader read in snapshot, unless a record was owed a zeroing since the reader began or
// while it read: the block may be that record's.
func (c *blockCache) put(ref, data []byte, snapshot, scrubbed uint64) {
	limit := indexBlockCacheBytes / blockCacheShards
	if len(data) > limit {
		return
	}
	s := c.shard(ref)
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.scrubTx.Load() != scrubbed || snapshot < scrubbed {
		return
	}
	if s.m == nil {
		s.m = map[string]*list.Element{}
	}
	if e := s.m[string(ref)]; e != nil {
		s.lru.MoveToFront(e)
		return
	}
	s.m[string(ref)] = s.lru.PushFront(&cachedBlock{ref: string(ref), data: data})
	s.used += len(data)
	for s.used > limit {
		oldest := s.lru.Back()
		b := oldest.Value.(*cachedBlock)
		s.lru.Remove(oldest)
		delete(s.m, b.ref)
		s.used -= len(b.data)
	}
}

// forget drops the block of a record that write transaction tx owes a zeroing: the copy goes before the
// transaction commits, and a reader that does not see the commit cannot put it back (put).
func (c *blockCache) forget(ref []byte, tx uint64) {
	for {
		cur := c.scrubTx.Load()
		if tx <= cur || c.scrubTx.CompareAndSwap(cur, tx) {
			break
		}
	}
	s := c.shard(ref)
	s.mu.Lock()
	if e := s.m[string(ref)]; e != nil {
		b := e.Value.(*cachedBlock)
		s.lru.Remove(e)
		delete(s.m, b.ref)
		s.used -= len(b.data)
	}
	s.mu.Unlock()
}

// bytes is the size of the blocks held.
func (c *blockCache) bytes() (n int) {
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		n += s.used
		s.mu.Unlock()
	}
	return n
}

// readBlock is read for the block of an index run, served from the cache when a scan has read it before. The
// bytes are shared and must not be written.
func (l *payloadLog) readBlock(ref []byte, tx *bolt.Tx) ([]byte, error) {
	if tx.Writable() || len(ref) != payloadRefLen {
		return l.read(ref)
	}
	if b, ok := l.blocks.get(ref); ok {
		return b, nil
	}
	scrubbed := l.blocks.scrubTx.Load()
	b, err := l.read(ref)
	if err == nil {
		l.blocks.put(ref, b, uint64(tx.ID()), scrubbed)
	}
	return b, err
}

// storedBlockTx is storedTx for a block of an index run read by a scan.
func storedBlockTx(tx *bolt.Tx, v []byte) []byte {
	if !isPayloadRef(v) {
		return v
	}
	l, ok := payloadLogs.Load(tx.DB())
	if !ok {
		return nil
	}
	raw, err := l.(*payloadLog).readBlock(v, tx)
	if err != nil {
		return nil
	}
	return raw
}
