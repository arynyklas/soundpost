// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"sort"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
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
	// Amortize makes the bounds grow with the size of the snapshot the last cut produced (cutDue): for a
	// machine whose cut writes the whole state, so that the cost of the cut stays proportional to the
	// journal it replaces. A machine that cuts incrementally (the data groups) leaves it off.
	Amortize bool
	// Stagger is the share of its bounds, in StaggerBase ths, after which this group cuts (0: all of them). The 64
	// data groups of a node are loaded alike, so with the same bounds they all reach them at the same instant, and
	// their cuts together held the engine lock they share for seconds at the single-host load, with every
	// acknowledgement queued behind (L2w20Admission19). Each group is given a different share, so the cuts of a node
	// are spread over the time one bound takes instead of falling together.
	Stagger uint16
	// Retain keeps the entries a cut compacts, in memory, for this long, so that a member that was away for less than
	// that is sent them instead of a snapshot of the whole state (tail.go); 0 keeps none. RetainBytes bounds the
	// retained entries of the group (0: defaultRetainBytes); when it is exceeded the oldest go first.
	Retain      time.Duration
	RetainBytes int64
}

// StaggerBase is the denominator of Cadence.Stagger.
const StaggerBase = 1024

func (c Cadence) Enabled() bool { return c.Commands > 0 || c.Bytes > 0 }

// Cadence is the cut cadence the group was opened with.
func (g *Group) Cadence() Cadence { return g.cadence }

// CadenceCuts is how many snapshot cuts the cadence loop has completed (cut, superseded snapshots
// dropped, journal compacted) since the group was opened.
func (g *Group) CadenceCuts() uint64 { return g.cadenceCuts.Load() }

// CadenceLongestCut is how long the longest completed cadence cut took, from the start of the
// snapshot to the end of the compaction. Commands keep being applied while it runs, so it is what
// the journal can grow past the cadence bound by.
func (g *Group) CadenceLongestCut() time.Duration { return time.Duration(g.cadenceLong.Load()) }

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
	g.appliedData += uint64(dataBytes)
	g.markApplied()
	if g.cutDue() {
		select {
		case g.cadenceWake <- struct{}{}:
		default:
		}
	}
}

// cutDue reports whether a bound of the cadence is reached. g.mu is held.
//
// With Cadence.Amortize the bounds grow with the snapshot the last cut produced: a cut costs the size of the state (the
// control group's snapshot streams every admission reservation row, 170 MB at 100,000 unsettled
// batches, and the cadence cut it every 8 MiB of journal, 10 s of load: 24 % of the server's CPU
// in the live profile of L2w20Admission7), a restart replays the journal, which costs ~35 ms per MB.
// A bound of at most half the last snapshot's size in journal keeps the cut cost amortized (at
// most 2 bytes cut per byte journaled) and the replay below half of what a cut writes.
func (g *Group) cutDue() bool {
	scale := uint64(1)
	if g.cadence.Amortize && g.cadence.Bytes > 0 && g.cutBytes > 2*g.cadence.Bytes {
		scale = uint64(g.cutBytes / (2 * g.cadence.Bytes))
	}
	commands, bytes := g.cadence.Commands*scale, g.cadence.Bytes*int64(scale)
	if s := uint64(g.cadence.Stagger); s != 0 && s < StaggerBase {
		commands = max(commands*s/StaggerBase, min(commands, 1))
		bytes = max(bytes*int64(s)/StaggerBase, min(bytes, 1))
	}
	return g.cadence.Commands > 0 && g.sinceCommands >= commands || g.cadence.Bytes > 0 && g.sinceBytes >= bytes
}

// AppliedDataBytes is the entry data bytes the cadence has counted since the group was opened (0
// without a cadence); a cut is due when Cadence.Bytes of them accumulate.
func (g *Group) AppliedDataBytes() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.appliedData
}

func (g *Group) cadenceLoop() {
	for {
		select {
		case <-g.stop:
			return
		case <-g.cadenceWake:
		}
		// A wake that arrived while a cut was running is still queued when it ends; the cut counted
		// what made it, so look again before cutting for nothing.
		g.mu.Lock()
		due := g.cutDue()
		g.mu.Unlock()
		if !due {
			continue
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
	// The cut ends when the group stops, so Close (which waits for this loop) never waits out the minute.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	go func() {
		select {
		case <-g.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	began := time.Now()
	g.mu.Lock()
	commands, size := g.sinceCommands, g.sinceBytes
	cursor := model.Cursor{Group: g.group, Index: model.Uint64(g.application)}
	g.mu.Unlock()
	snap, err := g.CreateSnapshot(ctx, cursor)
	if err != nil {
		return err
	}
	cut := g.snaps.freshBytes(snap.Manifest) // what the cut wrote itself: files it linked from the previous snapshot cost nothing
	if cut == 0 {
		for _, f := range snap.Manifest.Files {
			cut += int64(f.Size)
		}
	}
	// The journal is compacted onto the cut before the snapshot it supersedes is dropped: until it is, the journal
	// head is anchored on the superseded snapshot, whose directory holds the retry parts that head names.
	compactBegan := time.Now()
	verify := g.snaps.Verify
	if g.snaps.wroteLast() {
		verify = g.snaps.VerifyCut // the files the cut linked were hashed when they were written
	}
	if _, err := g.compactJournal(ctx, verify, true); err != nil {
		return err
	}
	since(&g.phases.cutCompactNS, compactBegan)
	dropBegan := time.Now()
	if _, err := g.snaps.DropSuperseded(); err != nil {
		return err
	}
	since(&g.phases.cutDropNS, dropBegan)
	g.mu.Lock()
	g.sinceCommands -= min(commands, g.sinceCommands)
	g.sinceBytes -= min(size, g.sinceBytes)
	g.cutBytes = cut
	g.mu.Unlock()
	g.cadenceCuts.Add(1)
	for took := int64(time.Since(began)); ; {
		old := g.cadenceLong.Load()
		if took <= old || g.cadenceLong.CompareAndSwap(old, took) {
			break
		}
	}
	return nil
}
