// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"sort"
	"time"

	"soundpost/internal/model"
)

// Decision D4 (2026-11-13). Two bounds that keep a group that never deletes anything from growing
// without limit:
//
//   - The retry table of a machine that keeps commands by digest (DigestRetryMachine) keeps an
//     entry for DefaultRetryWindow or DefaultRetryMax entries, whichever bounds first. The clock is
//     the time the leader stamped into the command (Entry.At), so every replica, and a replica
//     restored from a snapshot, evicts the same entries at the same applied index.
//   - A group configured with a Cadence cuts a snapshot and compacts the journal onto it every
//     Cadence.Commands applied commands or Cadence.Bytes of journal, independent of any deletion.
//
// A retry inside the window is answered with its original receipt. A retry outside it is no longer
// recognized and is proposed as a fresh command: that is safe only for a machine whose commands
// are guarded by a precondition that a second application fails (the control machine: a command
// carries the revision it expects, so a replayed command is a conflict, never a second effect).
const (
	DefaultRetryWindow = 24 * time.Hour
	DefaultRetryMax    = 100_000
)

// Cadence is when a group cuts and compacts by itself. The zero value never does.
type Cadence struct {
	Commands uint64
	Bytes    int64
}

func (c Cadence) Enabled() bool { return c.Commands > 0 || c.Bytes > 0 }

// Cadence is the cut cadence the group was opened with.
func (g *Group) Cadence() Cadence { return g.cadence }

// trackRetry records an applied command kept by digest and evicts what is out of the window.
func (g *Group) trackRetry(c CommittedEntry) {
	if !g.digestKind(c.Entry.Kind) {
		return
	}
	g.retryOrder = append(g.retryOrder, c.Entry.ID)
	g.evictRetries(c.Entry.At)
}

// evictRetries drops the oldest digest entries beyond retryMax, or older than retryWindow before
// now (nanoseconds, 0 when unknown: only the count bounds then).
func (g *Group) evictRetries(now int64) {
	for len(g.retryOrder) > 0 {
		id := g.retryOrder[0]
		old, ok := g.completed[id]
		if ok && len(g.retryOrder) <= g.retryMax && !(now > 0 && old.Entry.At > 0 && now-old.Entry.At > int64(g.retryWindow)) {
			break
		}
		g.retryOrder = g.retryOrder[1:]
		if !ok {
			continue
		}
		delete(g.completed, id)
		if r := old.Entry.ReservationID; r != nil {
			delete(g.known[*r], old.Index)
			if len(g.known[*r]) == 0 {
				delete(g.known, *r)
			}
		}
	}
	if len(g.retryOrder) == 0 {
		g.retryOrder = nil
	}
}

// rebuildRetryOrder re-derives the eviction order from the retry table (after a snapshot restore).
func (g *Group) rebuildRetryOrder() {
	type item struct {
		id    model.ID
		index uint64
	}
	var items []item
	var newest int64
	for id, c := range g.completed {
		if g.digestKind(c.Entry.Kind) {
			items = append(items, item{id, c.Index})
			newest = max(newest, c.Entry.At)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].index < items[j].index })
	g.retryOrder = make([]model.ID, len(items))
	for i, it := range items {
		g.retryOrder[i] = it.id
	}
	g.evictRetries(newest)
}

// countApplied is called under g.mu for every applied entry; it wakes the cadence loop when a
// bound is reached.
func (g *Group) countApplied(dataBytes int) {
	if !g.cadence.Enabled() {
		return
	}
	g.sinceCommands++
	g.sinceBytes += int64(dataBytes)
	if g.cadence.Commands > 0 && g.sinceCommands >= g.cadence.Commands || g.cadence.Bytes > 0 && g.sinceBytes >= g.cadence.Bytes {
		select {
		case g.cadenceWake <- struct{}{}:
		default:
		}
	}
}

func (g *Group) cadenceLoop() {
	for {
		select {
		case <-g.stop:
			return
		case <-g.cadenceWake:
		}
		if g.cutAndCompact() != nil {
			select { // the machine may be behind its cut for a moment: try again on the next command
			case <-g.stop:
				return
			case <-time.After(time.Second):
			}
		}
	}
}

// cutAndCompact cuts a snapshot at the applied index, drops the superseded ones and compacts the
// journal onto the cut.
func (g *Group) cutAndCompact() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	g.mu.Lock()
	commands, size := g.sinceCommands, g.sinceBytes
	cursor := model.Cursor{Group: g.group, Index: model.Uint64(g.application)}
	g.mu.Unlock()
	if _, err := g.CreateSnapshot(ctx, cursor); err != nil {
		return err
	}
	if _, err := g.snaps.DropSuperseded(); err != nil {
		return err
	}
	if _, err := g.CompactJournal(ctx); err != nil {
		return err
	}
	g.mu.Lock()
	g.sinceCommands -= min(commands, g.sinceCommands)
	g.sinceBytes -= min(size, g.sinceBytes)
	g.mu.Unlock()
	return nil
}
