// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// A turn for a writer that keeps losing.
//
// admission_yield.go holds the leader's admission commands for a writer that lost, which needs the leader to tell an admission
// command from the writer's and the writer's next proposal to arrive within the window (a few milliseconds). Neither holds
// when the group proposes whole-state replacements (a mixed group, before every member declared the state patch protocols):
// every command is then a replacement the leader cannot classify, every voter runs its own admission against its own read of
// the state, and a voter that is not the leader needs a read-index round trip, the encoding of the whole state and a forward
// between its read and its proposal, a time in which the revision moves many times. A Begin submitted through such a voter lost
// the application-index race 64 times in a row under saturating intake on every voter, and was refused (stale, not retryable)
// with nothing authority-relevant moved.
//
// A retention writer that lost a proposal therefore asks the leader for a turn before it reads again, naming the entry it is
// about to propose. The leader holds every other control command (a patch or a replacement, from any voter) as stale until that
// entry is found current or the turn's span passes; a writer that is told stale reads and proposes again, as it does when it loses to any
// other writer, and the entry that holds the turn meets a revision that does not move. A turn lasts turnSpan and a writer that
// lost again within it extends it, never beyond turnMaxHold in all; a new turn is granted after four times as long again, so
// the other writers keep at least four fifths of the time whatever one writer does. A leader that serves no such call (a
// release that does not know it) or a call that fails costs the writer nothing but the turn: it proposes as it did.
const (
	turnCall    = "turn.v1"
	turnSpan    = 50 * time.Millisecond
	turnMaxHold = 200 * time.Millisecond
	// turnCallBudget bounds the wait for the leader's answer: a turn is a help, never a reason to wait.
	turnCallBudget = 250 * time.Millisecond
)

// turnState is the leader's turn: the entry that holds it and when it ends (UnixNano). The next turn is due four times as long
// after the end as the turn was held (grant); the rest is computed from start and until, not kept. The counters are the
// leader's account of what turns cost the other writers (turnStats).
type turnState struct {
	mu           sync.Mutex
	entry        model.ID
	start, until int64
	granted      uint64 // turns begun (an extension is not another turn)
	refused      uint64 // requests refused because the turn was not due yet (the rest)
	stale        uint64 // commands answered stale because a turn held them
	heldNS       int64  // time the turns that ended were held, the current one excluded
	maxHoldNS    int64  // longest a turn that ended was held
	tries        [len(attemptBounds) + 1]uint64
	most         int // the most attempts one such writer needed
}

// attemptBounds are the upper bounds of the buckets of the attempts a writer that retries lost proposals needed (noteAttempts):
// one attempt each up to eight, then up to 12, 16, 32, and 33 to maxLostProposals in the last.
var attemptBounds = [...]int{1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 32}

// noteAttempts counts a writer that retries lost proposals and needed n attempts in all (the last one is its answer, a
// refusal when n reached the budget).
func (t *turnState) noteAttempts(n int) {
	i := 0
	for i < len(attemptBounds) && n > attemptBounds[i] {
		i++
	}
	t.mu.Lock()
	t.tries[i]++
	t.most = max(t.most, n)
	t.mu.Unlock()
}

// attemptCounts reads the buckets of attemptBounds (the last one counts the rest).
func (t *turnState) attemptCounts() []uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]uint64(nil), t.tries[:]...)
}

// mostAttempts is the most attempts any writer that retries lost proposals needed, exactly (the buckets only say "33 or more").
func (t *turnState) mostAttempts() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.most
}

// turnStats is a reading of the counters of a turnState.
type turnStats struct {
	Granted, Refused, Stale uint64
	Held, MaxHold           time.Duration // all turns, the one running counted up to now
}

// stats reads the counters at now. The held time is that of the turns that ended plus the running one up to now.
func (t *turnState) stats(now time.Time) turnStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	cur := int64(0)
	if t.start != 0 {
		cur = max(0, min(now.UnixNano(), t.until)-t.start)
	}
	return turnStats{
		Granted: t.granted, Refused: t.refused, Stale: t.stale,
		Held: time.Duration(t.heldNS + cur), MaxHold: time.Duration(max(t.maxHoldNS, cur)),
	}
}

// grant gives entry the turn when none is held, or moves the turn held to entry (a writer that lost again, extending the turn up
// to turnMaxHold from its start); false when the turn is not due yet: it is due four times as long after the last one ended as
// that one was held.
func (t *turnState) grant(entry model.ID, now time.Time) bool {
	n := now.UnixNano()
	t.mu.Lock()
	defer t.mu.Unlock()
	if n < t.until {
		t.until = max(t.until, min(n+int64(turnSpan), t.start+int64(turnMaxHold)))
		t.entry = entry
		return true
	}
	if n < t.until+4*(t.until-t.start) {
		t.refused++
		return false
	}
	held := t.until - t.start // the turn that ended is counted when the next begins
	t.heldNS += held
	t.maxHoldNS = max(t.maxHoldNS, held)
	t.granted++
	t.start, t.until, t.entry = n, n+int64(turnSpan), entry
	return true
}

// holds says whether the command with this entry id is held for the writer that has the turn.
func (t *turnState) holds(entry model.ID, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	held := now.UnixNano() < t.until && entry != t.entry
	if held {
		t.stale++
	}
	return held
}

// done ends the turn when entry, which has it, was found current by the leader: it is committed, and the writer is no longer
// waiting for the other commands to stop. An entry that was found stale leaves the turn to the writer's next attempt.
func (t *turnState) done(entry model.ID, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n := now.UnixNano(); n < t.until && entry == t.entry {
		t.until = n
	}
}

type turnRequest struct {
	Entry model.ID `json:"entry"`
}

type turnAnswer struct {
	Granted bool `json:"granted"`
}

// serveTurn is the leader's handler of turnCall.
func (s *Store) serveTurn(_ context.Context, _ uint64, body []byte) ([]byte, error) {
	var q turnRequest
	if model.StrictJSON(body, &q) != nil || q.Entry == (model.ID{}) {
		return nil, model.Fail(model.Invalid)
	}
	return json.Marshal(turnAnswer{Granted: s.turn.grant(q.Entry, time.Now())})
}

// askTurn asks the leader for a turn for the entry this voter is about to propose; the leader takes it for itself. It returns
// nothing: the turn is a help, and a voter that knows no leader, or whose leader serves no such call (replica.ErrNoCall,
// remembered for remoteBackoff) proposes as it would have.
func (s *Store) askTurn(ctx context.Context, entry model.ID) {
	if s.repl == nil {
		return
	}
	leader, self := s.repl.group.Leader()
	if self {
		s.turn.grant(entry, time.Now())
		return
	}
	if leader == 0 || time.Now().UnixNano() < s.turnDownUntil.Load() {
		return
	}
	body, err := json.Marshal(turnRequest{Entry: entry})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, turnCallBudget)
	defer cancel()
	if _, err = s.repl.group.CallLeader(ctx, turnCall, body); errors.Is(err, replica.ErrNoCall) {
		s.turnDownUntil.Store(time.Now().Add(remoteBackoff).UnixNano())
	}
}
