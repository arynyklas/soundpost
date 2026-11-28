// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func prefetchTestFile(t *testing.T, size int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "apply.db")
	if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// countPrefetchReads makes the prefetch count the bytes it reads for the length of the test.
func countPrefetchReads(t *testing.T) *atomic.Int64 {
	t.Helper()
	var n atomic.Int64
	old := prefetchRead
	prefetchRead = func(f *os.File, buf []byte) (int, error) {
		got, err := f.Read(buf)
		n.Add(int64(got))
		return got, err
	}
	t.Cleanup(func() { prefetchRead = old })
	return &n
}

func waitPrefetch(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the prefetch did not end")
	}
}

func TestPrefetchOnOpenReadsTheWholeFile(t *testing.T) {
	const size = 2*prefetchChunk + 12345
	read := countPrefetchReads(t)
	var closing atomic.Bool
	waitPrefetch(t, prefetchOnOpen(&closing, prefetchTestFile(t, size)))
	if got := read.Load(); got != size {
		t.Fatalf("the prefetch read %d bytes of a %d byte file", got, int64(size))
	}
}

func TestPrefetchOnOpenStopsWhenTheEngineCloses(t *testing.T) {
	read := countPrefetchReads(t)
	var closing atomic.Bool
	closing.Store(true)
	waitPrefetch(t, prefetchOnOpen(&closing, prefetchTestFile(t, 4*prefetchChunk)))
	if got := read.Load(); got != 0 {
		t.Fatalf("the prefetch read %d bytes after the engine was closing", got)
	}
}

func TestPrefetchOnOpenToleratesMissingAndEmptyFiles(t *testing.T) {
	var closing atomic.Bool
	empty := prefetchTestFile(t, 0)
	waitPrefetch(t, prefetchOnOpen(&closing, filepath.Join(t.TempDir(), "missing.db"), empty, prefetchTestFile(t, 10)))
}
