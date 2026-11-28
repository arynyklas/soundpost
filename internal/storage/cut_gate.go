// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"sync"
	"sync/atomic"
)

// DefaultCutConcurrency is how many window derivations and window-file writes of snapshot cuts and settlement passes one engine runs at the
// same moment. The 64 data groups of a node are loaded alike: their cuts reach the bound within seconds of one another and, at the 5k records/s
// gate, each rewrote the open window of its group (up to 50 MB) while the others did the same, so the node's disk, which the raft journals of
// every group fsync on, carried 200 MB/s of cut writes and every ReadIndex waited behind them (latgrow-report). A cut that finds the gate full waits its turn, in
// the order it came; what it waits for is bounded work (a window derivation or one file write), never another cut's wait.
const DefaultCutConcurrency = 4

// cutConcurrency is the gate's limit; 0 is no limit.
var cutConcurrency atomic.Int64

func init() { cutConcurrency.Store(DefaultCutConcurrency) }

// SetCutConcurrency changes the limit of every later entry into the cut gate of this process and returns the previous one (0: none); it exists
// for tests.
func SetCutConcurrency(n int) int { return int(cutConcurrency.Swap(int64(n))) }

// cutGate admits at most cutConcurrency holders at a time, first come first served.
type cutGate struct {
	mu     sync.Mutex
	active int
	peak   int
	queue  []chan struct{}
}

// enter waits for a place and returns the function that gives it back. A holder must not wait for anything but the engine's own short
// locks, and takes the gate before any lock of a slot's window cache (windowCache.mu).
func (g *cutGate) enter() func() {
	g.mu.Lock()
	if limit := int(cutConcurrency.Load()); limit <= 0 || g.active < limit && len(g.queue) == 0 {
		g.active++
		g.peak = max(g.peak, g.active)
		g.mu.Unlock()
		return g.leave
	}
	turn := make(chan struct{})
	g.queue = append(g.queue, turn)
	g.mu.Unlock()
	<-turn // the place is handed over with active already counting it
	return g.leave
}

func (g *cutGate) leave() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.queue) > 0 && (cutConcurrency.Load() <= 0 || g.active <= int(cutConcurrency.Load())) {
		turn := g.queue[0]
		g.queue = g.queue[1:]
		close(turn)
		return
	}
	g.active--
}

// peakHolders is the most holders the gate has had at once since resetPeak.
func (g *cutGate) peakHolders() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.peak
}

func (g *cutGate) resetPeak() {
	g.mu.Lock()
	g.peak = g.active
	g.mu.Unlock()
}
