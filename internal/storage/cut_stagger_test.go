// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// The 64 data groups of a node are loaded alike, so with one bound they reach it at the same instant and cut together
// (at the 5k records/s gate every cut was silent for 0.3-0.8 s and the cuts fell in one stretch, ~T0+80 s: the
// collapse of admit-report round 4). Each group is given its own share of the bound (slotStagger), which places where
// its FIRST cut falls; after it every group cuts at the whole bound, so that the staggering costs nothing in the steady
// state (the cuts a node makes, and the journal a restart replays, are those of the bound the cadence names).
//
// The engine is opened with the production wiring (DefaultSlotCadence, the share per slot) at a bound of 16 commands; the
// 64 groups are driven with the same stream, one command each per round, and the round of each group's first and second
// cut is read off after the round, once every cut that round called for has ended (cutsSettled). The test used to wait a
// fixed 60 ms instead: eight groups cut in the same round, and a group appended last in the round (slot 63) has its cut
// begin at the very end of it, so a cut that took more than the 60 ms was seen one round late (1 run of 3 on a busy
// disk: "17 commands after its first (rounds 14 and 31)"), and a cut seen late is
// counted as a command too many. So that it cannot come back unnoticed, every cut after the 64 first ones (they all end
// by round 15, the second ones begin at round 23) is held for 400 ms: the old wait failed this on every run, for the
// groups appended last in a round.
func TestDataGroupsCutAtDifferentCommandsAndLaterAtTheWholeBound(t *testing.T) {
	const bound = 16
	old := DefaultSlotCadence
	DefaultSlotCadence = replica.Cadence{Commands: bound}
	t.Cleanup(func() { DefaultSlotCadence = old })
	w := newWindowEnv(t)
	var begun atomic.Int64
	w.e.setFault(func(at string) error {
		if at == "snapshot_cut" && begun.Add(1) > 64 {
			time.Sleep(400 * time.Millisecond)
		}
		return nil
	})
	var names [64]string
	for i, found := 0, 0; found < 64; i++ {
		if i == 1<<16 {
			t.Fatalf("series for %d of the 64 slots among the first %d names", found, i)
		}
		name := fmt.Sprintf("stagger_series_%d", i)
		if slot := ackPagesSlotOf(t, w.desc, name); names[slot] == "" {
			names[slot] = name
			found++
		}
	}
	var producers [64]model.ID
	for slot := range producers {
		producers[slot] = model.NewID()
	}
	var first, second [64]int // the round after which the group had cut once, and twice (0: not yet)
	done := func() bool { return !slices.Contains(second[:], 0) }
	rounds := 0
	for rounds < 4*bound && !done() {
		rounds++
		for slot := range names {
			scope, b := settleBatch(t, w.store, w.service, w.cred, w.desc, producers[slot], model.UnixNano(rounds), names[slot])
			if _, err := w.e.Append(context.Background(), scope, b); err != nil {
				t.Fatalf("round %d, slot %d: %v", rounds, slot, err)
			}
		}
		cutsSettled(t, w.e)
		for slot, g := range w.e.repl.groups {
			cuts := g.CadenceCuts()
			if cuts >= 1 && first[slot] == 0 {
				first[slot] = rounds
			}
			if cuts >= 2 && second[slot] == 0 {
				second[slot] = rounds
			}
		}
	}
	lowest, highest := first[0], first[0]
	distinct := map[int]bool{}
	for slot := range first {
		if first[slot] == 0 || second[slot] == 0 {
			t.Fatalf("after %d rounds the group of slot %d made its first cut after round %d and its second after round %d (0: none), want both", rounds, slot, first[slot], second[slot])
		}
		lowest, highest = min(lowest, first[slot]), max(highest, first[slot])
		distinct[first[slot]] = true
	}
	t.Logf("first cuts of the 64 groups after rounds %d..%d (%d distinct) of a bound of %d commands; second cuts after rounds %v", lowest, highest, len(distinct), bound, second)
	if spread := highest - lowest; spread < bound*4/10 {
		t.Fatalf("the first cuts of the 64 groups fall within %d commands of one another (rounds %d..%d), want them spread over at least 40%% of the bound of %d", spread, lowest, highest, bound)
	}
	if len(distinct) < 6 {
		t.Fatalf("the first cuts of the 64 groups fall at %d different counts, want at least 6", len(distinct))
	}
	if highest > bound+2 { // the bound, and the entries every group applies besides its commands
		t.Fatalf("the last group's first cut came after round %d, past the whole bound of %d commands", highest, bound)
	}
	for slot := range first {
		if gap := second[slot] - first[slot]; gap < bound-2 || gap > bound {
			t.Fatalf("slot %d cut a second time %d commands after its first (rounds %d and %d), want the whole bound of %d: the share is for the first cut only", slot, gap, first[slot], second[slot], bound)
		}
	}
}

// cutsSettled waits until no group of the engine owes the cadence a cut (running, or due and not yet begun), so that what
// CadenceCuts says after it is every cut the commands appended so far called for, however long the cuts take.
func cutsSettled(t *testing.T, e *Engine) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		pending := false
		for _, g := range e.repl.groups {
			if g.CadencePending() {
				pending = true
				break
			}
		}
		if !pending {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("a cut was still owed 2 minutes after the commands that called for it")
		}
		time.Sleep(time.Millisecond)
	}
}
