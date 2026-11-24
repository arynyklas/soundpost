// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"os"
	"sync/atomic"
)

// prefetchChunk is what the prefetch reads at a time: large enough for the device to read sequentially,
// small enough that a stop is noticed within a few milliseconds.
const prefetchChunk = 8 << 20

// prefetchRead is the read of the prefetch (a test counts what it reads).
var prefetchRead = func(f *os.File, buf []byte) (int, error) { return f.Read(buf) }

// prefetchOnOpen reads the files the replay of the journals faults in, sequentially and in the
// background, so that the page cache holds them when the replay needs them. apply.db is memory-mapped: on a
// cold cache the replay of each journal entry (slotMachine.planApply) faults the pages of the stored command
// and of the counters one at a time, while it holds the engine lock, at about a tenth of what the device
// reads sequentially (the 3 GB file of the single-host gate: 26 s of a 28 s restart).
//
// It is best effort: it reads, never writes or locks, ignores every error (a missing or short file is
// fine) and never delays the open. It stops when it has read the whole file or when closing is set (the
// engine's Close); it holds nothing the engine waits for. The returned channel is closed when it ends.
func prefetchOnOpen(closing *atomic.Bool, paths ...string) <-chan struct{} {
	read := prefetchRead // taken here, not by the goroutine: a test that swaps the hook neither races with nor is counted by the prefetch of an earlier engine
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, prefetchChunk)
		for _, path := range paths {
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			for !closing.Load() {
				if _, err = read(f, buf); err != nil { // io.EOF: the whole file is read; anything else: give up on it
					break
				}
			}
			f.Close()
			if closing.Load() {
				return
			}
		}
	}()
	return done
}
