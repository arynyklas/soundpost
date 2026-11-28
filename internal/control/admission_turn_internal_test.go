// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// The turn holds every entry but the one that has it, until that entry is found current (which ends the turn) or turnSpan
// passes; an entry found stale leaves the turn to the writer's next attempt.
func TestTheTurnHoldsOtherEntriesUntilItsOwnIsCurrent(t *testing.T) {
	var ts turnState
	mine, other := model.NewID(), model.NewID()
	t0 := time.Unix(1000, 0)
	if ts.holds(other, t0) {
		t.Fatal("no turn is held: an entry was held")
	}
	if !ts.grant(mine, t0) {
		t.Fatal("the first turn was not granted")
	}
	if !ts.holds(other, t0.Add(turnSpan-time.Nanosecond)) {
		t.Fatal("another entry was not held within the span")
	}
	if ts.holds(other, t0.Add(turnSpan)) {
		t.Fatal("another entry was held past the span")
	}
	ts = turnState{}
	ts.grant(mine, t0)
	if ts.holds(mine, t0.Add(time.Millisecond)) {
		t.Fatal("the entry that has the turn was held")
	}
	if !ts.holds(other, t0.Add(2*time.Millisecond)) {
		t.Fatal("the turn ended before its entry was found current (a stale entry leaves it to the next attempt)")
	}
	ts.done(other, t0.Add(3*time.Millisecond))
	if !ts.holds(other, t0.Add(4*time.Millisecond)) {
		t.Fatal("an entry that does not have the turn ended it")
	}
	ts.done(mine, t0.Add(5*time.Millisecond))
	if ts.holds(other, t0.Add(6*time.Millisecond)) {
		t.Fatal("the turn outlived the entry that had it")
	}
}

// A writer that lost again within its turn extends it up to turnMaxHold in all, and the next turn is not granted before four
// times as long as the last was held has passed: the other writers keep four fifths of the time.
func TestTheTurnIsExtendedToAMaximumAndRationed(t *testing.T) {
	var ts turnState
	first, second := model.NewID(), model.NewID()
	t0 := time.Unix(1000, 0)
	ts.grant(first, t0)
	at := t0
	for at.Before(t0.Add(turnMaxHold)) {
		at = at.Add(10 * time.Millisecond)
		ts.grant(second, at)
	}
	if !ts.holds(first, t0.Add(turnMaxHold-time.Nanosecond)) {
		t.Fatal("the extended turn does not hold until the maximum")
	}
	if ts.holds(first, t0.Add(turnMaxHold)) {
		t.Fatal("the turn was held past the maximum")
	}
	if ts.grant(first, t0.Add(turnMaxHold+time.Millisecond)) {
		t.Fatal("a turn was granted right after one of the maximum length")
	}
	if !ts.grant(first, t0.Add(5*turnMaxHold)) {
		t.Fatal("no turn was granted after the rest")
	}
}

// A turn that ended early (its entry was current after 10 ms) is followed by a rest of four times that, not of the span: the
// writer that needs another turn for its next command does not wait for the longest.
func TestTheRestAfterATurnIsFourTimesTheTimeItWasHeld(t *testing.T) {
	var ts turnState
	mine := model.NewID()
	t0 := time.Unix(1000, 0)
	ts.grant(mine, t0)
	ts.done(mine, t0.Add(10*time.Millisecond))
	if ts.grant(mine, t0.Add(49*time.Millisecond)) {
		t.Fatal("a turn was granted before the rest of 40 ms")
	}
	if !ts.grant(mine, t0.Add(50*time.Millisecond)) {
		t.Fatal("no turn was granted after the rest of 40 ms")
	}
}

// Under a stream of turn requests (a writer asking every millisecond, each time with a new entry, and a command being held
// every millisecond) the turns hold the other commands for at most a fifth of the time (D107 condition 2): measured with the
// counters the diagnostic build reports, at every moment a rest has run its course (a turn that has just ended is still owed
// its rest), in three shapes: turns that run to the maximum, turns that end early, and a mixture.
func TestTheTurnsHoldAtMostAFifthOfTheTimeUnderAStreamOfRequests(t *testing.T) {
	shapes := map[string]func(k int) time.Duration{
		"to the maximum": func(int) time.Duration { return -1 },
		"early":          func(int) time.Duration { return 10 * time.Millisecond },
		"mixed":          func(k int) time.Duration { return time.Duration(k%7) * 13 * time.Millisecond },
	}
	for name, endAfter := range shapes {
		t.Run(name, func(t *testing.T) {
			var ts turnState
			t0 := time.Unix(1000, 0)
			holder, other := model.NewID(), model.NewID()
			var turnStart time.Time
			var turnNo, held, checked int
			end := t0.Add(60 * time.Second)
			for at := t0; at.Before(end); at = at.Add(time.Millisecond) {
				// The rest of the last turn has run its course (a turn that has just ended is still owed it): the time since the
				// first request is then at least five times the time the turns held. Checked before the tick's request, which
				// starts the next turn.
				if st := ts.stats(at); at.UnixNano() >= ts.until+4*(ts.until-ts.start) {
					checked++
					if el := at.Sub(t0); st.Held*5 > el {
						t.Fatalf("at %v the turns held the others for %v, over a fifth of the time", el, st.Held)
					}
				}
				before := ts.stats(at).Granted
				ts.grant(holder, at)
				if ts.stats(at).Granted != before {
					turnStart, turnNo = at, turnNo+1
				}
				if ts.holds(other, at) {
					held++
				}
				if d := endAfter(turnNo); d >= 0 && !turnStart.IsZero() && at.Sub(turnStart) >= d {
					ts.done(holder, at)
				}
				if st := ts.stats(at); st.MaxHold > turnMaxHold {
					t.Fatalf("at %v a turn was held %v, over the maximum %v", at.Sub(t0), st.MaxHold, turnMaxHold)
				}
			}
			st := ts.stats(end)
			if checked == 0 || st.Granted < 10 || st.Refused == 0 || st.Stale == 0 || uint64(held) != st.Stale {
				t.Fatalf("the stream did not exercise the turns: checked %d, %+v, held %d", checked, st, held)
			}
		})
	}
}

// The buckets of the attempts a writer needed end in "33 to the budget"; the most any writer needed is kept exactly, so a test
// can tell a Begin that needed 40 attempts from one that needed 63, and either from the refusal at 64.
func TestTheMostAttemptsAWriterNeededIsExactBeyondTheLastBucket(t *testing.T) {
	var ts turnState
	if ts.mostAttempts() != 0 {
		t.Fatal("a writer needed attempts before any was counted")
	}
	for _, n := range []int{1, 7, 40, 3, 63, 12} {
		ts.noteAttempts(n)
	}
	if got := ts.mostAttempts(); got != 63 {
		t.Fatalf("most attempts %d, want 63", got)
	}
	counts := ts.attemptCounts()
	if last := counts[len(counts)-1]; last != 2 {
		t.Fatalf("the last bucket (33 and more) counted %d writers, want the 2 that needed 40 and 63: %v", last, counts)
	}
}
