// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package durablefs

import (
	"encoding/binary"
	"hash/fnv"
	"os"
	"sync"
)

// The page layout of a bolt file (go.etcd.io/bbolt, internal/common): a page starts with a 16-byte header (id, flags, element count,
// overflow pages); a branch page is an array of 16-byte elements (offset, key size, child page) and a leaf page an array of 16-byte
// elements (flags, offset, key size, value size) whose values follow; a value flagged as a bucket starts with the bucket header (root page,
// sequence), followed by the bucket's own leaf page when its root is 0 (an inline bucket). The two meta pages are pages 0 and 1.
const (
	boltPageHeader   = 16
	boltElement      = 16
	boltBranchFlag   = 0x01
	boltLeafFlag     = 0x02
	boltBucketFlag   = 0x01
	boltMetaMagic    = 0xED0CDAED
	boltNoFreelist   = ^uint64(0)
	boltMinWarmBytes = 32 << 20
	// boltWholeNodeMax is the largest node WarmBoltTree reads whole to look for the buckets in its values: a larger one is a value
	// that spans pages (a block of a run), and what is read of it is its first page, which bolt's own pass reads too.
	boltWholeNodeMax = 1 << 20
	boltWarmWorkers  = 64
)

// WarmBoltTree reads the live tree of the bolt file at path with many readers at once and returns the pages it holds (each node counts its
// overflow pages), so that the page cache has them when bolt walks the tree itself. A bolt file that does not carry its freelist (the
// commits of apply.db and control.db do not write it, D91; a crash leaves the file so) is opened by a pass over every node of its live
// tree, one page fault after the other: 107,000 nodes of apply.db cost 14 s on the cold disk of the single-host gate, and the 200,000 of
// control.db twice that, against a startup budget of 20 s (L2w20Admission27). The device answers many reads in the time it answers one, so
// the same pages read 64 at a time are in the cache a second or two later and bolt's pass costs what a warm one costs.
//
// It is best effort and changes nothing: it only reads, answers 0 for a file that is small, absent, unreadable, or that carries its freelist
// (bolt reads that one in a few pages), and stops following a page it cannot make sense of; whatever it does not read, bolt reads itself.
func WarmBoltTree(path string) int64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() < boltMinWarmBytes {
		return 0
	}
	root, pageSize, ok := newestBoltRoot(f)
	if !ok {
		return 0
	}
	w := &boltWalk{f: f, pageSize: int64(pageSize), maxPage: uint64(info.Size()) / uint64(pageSize), queue: []uint64{root}}
	w.cond = sync.NewCond(&w.mu)
	var wg sync.WaitGroup
	for range boltWarmWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.run()
		}()
	}
	wg.Wait()
	return w.pages
}

// newestBoltRoot returns the root page of the bucket tree of the newest valid meta page, unless that meta names a freelist.
func newestBoltRoot(f *os.File) (root uint64, pageSize uint32, ok bool) {
	head := make([]byte, 4096)
	if _, err := f.ReadAt(head, 0); err != nil {
		return 0, 0, false
	}
	pageSize = binary.LittleEndian.Uint32(head[boltPageHeader+8:])
	if pageSize < 1024 || pageSize > 1<<20 || pageSize&(pageSize-1) != 0 {
		return 0, 0, false
	}
	var bestTx uint64
	var found, free bool
	for i := range 2 {
		buf := make([]byte, boltPageHeader+80)
		if _, err := f.ReadAt(buf, int64(i)*int64(pageSize)); err != nil {
			continue
		}
		m := buf[boltPageHeader:]
		if binary.LittleEndian.Uint32(m[0:]) != boltMetaMagic || binary.LittleEndian.Uint32(m[8:]) != pageSize {
			continue
		}
		sum := fnv.New64a()
		sum.Write(m[:56])
		if sum.Sum64() != binary.LittleEndian.Uint64(m[56:]) {
			continue
		}
		if tx := binary.LittleEndian.Uint64(m[48:]); !found || tx > bestTx {
			found, bestTx = true, tx
			root = binary.LittleEndian.Uint64(m[16:])
			free = binary.LittleEndian.Uint64(m[32:]) != boltNoFreelist
		}
	}
	return root, pageSize, found && !free && root != 0
}

type boltWalk struct {
	f        *os.File
	pageSize int64
	maxPage  uint64

	mu     sync.Mutex
	cond   *sync.Cond
	queue  []uint64
	active int
	pages  int64
}

func (w *boltWalk) run() {
	for {
		w.mu.Lock()
		for len(w.queue) == 0 && w.active > 0 {
			w.cond.Wait()
		}
		if len(w.queue) == 0 {
			w.mu.Unlock()
			w.cond.Broadcast()
			return
		}
		pgid := w.queue[len(w.queue)-1]
		w.queue = w.queue[:len(w.queue)-1]
		w.active++
		w.mu.Unlock()
		children, pages := w.visit(pgid)
		w.mu.Lock()
		w.queue = append(w.queue, children...)
		w.pages += pages
		w.active--
		w.mu.Unlock()
		w.cond.Broadcast()
	}
}

// visit reads the node that starts at page pgid and returns the pages it points to and the pages it takes.
func (w *boltWalk) visit(pgid uint64) (children []uint64, pages int64) {
	if pgid < 2 || pgid >= w.maxPage {
		return nil, 0
	}
	buf := make([]byte, w.pageSize)
	if _, err := w.f.ReadAt(buf, int64(pgid)*w.pageSize); err != nil {
		return nil, 0
	}
	flags, count, overflow := binary.LittleEndian.Uint16(buf[8:]), int(binary.LittleEndian.Uint16(buf[10:])), uint64(binary.LittleEndian.Uint32(buf[12:]))
	if flags&(boltBranchFlag|boltLeafFlag) == 0 || pgid+overflow >= w.maxPage {
		return nil, 0
	}
	pages = 1 + int64(overflow)
	if node := int64(1+overflow) * w.pageSize; overflow > 0 && node <= boltWholeNodeMax {
		whole := make([]byte, node)
		copy(whole, buf)
		if _, err := w.f.ReadAt(whole[w.pageSize:], int64(pgid+1)*w.pageSize); err != nil {
			return nil, pages
		}
		buf = whole
	}
	return nodeChildren(buf, flags, count, w.maxPage, nil), pages
}

// nodeChildren appends the root pages of the nodes and buckets a branch or leaf page points to. A page that is not complete in b is
// followed as far as it goes.
func nodeChildren(b []byte, flags uint16, count int, maxPage uint64, out []uint64) []uint64 {
	for i := range count {
		at := boltPageHeader + i*boltElement
		if at+boltElement > len(b) {
			break
		}
		el := b[at:]
		switch {
		case flags&boltBranchFlag != 0:
			if child := binary.LittleEndian.Uint64(el[8:]); child >= 2 && child < maxPage {
				out = append(out, child)
			}
		case binary.LittleEndian.Uint32(el[0:])&boltBucketFlag != 0:
			pos, ksize, vsize := int(binary.LittleEndian.Uint32(el[4:])), int(binary.LittleEndian.Uint32(el[8:])), int(binary.LittleEndian.Uint32(el[12:]))
			start := at + pos + ksize
			if start < 0 || vsize < 16 || start+16 > len(b) {
				continue
			}
			if root := binary.LittleEndian.Uint64(b[start:]); root != 0 {
				if root < maxPage {
					out = append(out, root)
				}
				continue
			}
			end := min(start+vsize, len(b)) // an inline bucket: its leaf page follows the header
			inline := b[start+16 : end]
			if len(inline) >= boltPageHeader {
				out = nodeChildren(inline, binary.LittleEndian.Uint16(inline[8:]), int(binary.LittleEndian.Uint16(inline[10:])), maxPage, out)
			}
		}
	}
	return out
}
