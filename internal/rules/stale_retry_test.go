// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"context"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/staleretry"
)

// raceOnce moves the control revision between the committer's revision read and its command, once, as a concurrent worker's
// commit does.
type raceOnce struct {
	Control
	race func()
	done bool
}

func (r *raceOnce) Transact(ctx context.Context, scope auth.Scope, cmd control.Command) (control.Result, error) {
	if !r.done {
		r.done = true
		r.race()
	}
	return r.Control.Transact(ctx, scope, cmd)
}

// TestACommitThatLostTheRevisionRaceIsCountedAsOneStaleRetry: the workers' report of stale retries is what they name when
// concurrent passes lose to each other. One lost race is one retry of the rule writer, and a commit that raced nothing counts none.
func TestACommitThatLostTheRevisionRaceIsCountedAsOneStaleRetry(t *testing.T) {
	c := newCtl(t)
	rule := c.alert(0, 0)
	var calls []int64
	e := c.evaluator(presentWhile(c.project, &calls, func(int64) bool { return true }), newClock(65))
	lease := c.lease()
	ev, err := e.Evaluate(c.ctx, c.reader(), rule, 60*sec, lease)
	if err != nil {
		t.Fatal(err)
	}
	before := staleretry.Snapshot()
	if _, err = c.committer().Commit(c.ctx, c.admin(), ev, lease); err != nil {
		t.Fatal(err)
	}
	if got := staleretry.Snapshot().Since(before); got.Total() != 0 {
		t.Fatalf("a commit that raced nothing counted retries: %+v", got)
	}

	second := c.alert(0, 0)
	next, err := e.Evaluate(c.ctx, c.reader(), second, 60*sec, lease)
	if err != nil {
		t.Fatal(err)
	}
	racing := &raceOnce{Control: c.store, race: func() {
		other := c.alert(0, 0)
		if _, err := c.committer().RecordMissed(c.ctx, c.admin(), other, MissedInterval{From: 0, To: 60 * sec, Count: 1}, 100*sec, lease); err != nil {
			t.Error(err)
		}
	}}
	before = staleretry.Snapshot()
	if res, err := NewCommitter(racing, c.store.ReplicaGroup()).Commit(c.ctx, c.admin(), next, lease); err != nil || res.Phase != "applied" {
		t.Fatalf("a lost revision race: %+v: %v", res, err)
	}
	if got := staleretry.Snapshot().Since(before); got.Rules != 1 || got.Total() != 1 {
		t.Fatalf("one lost race counted %+v, want one retry of the rule writer", got)
	}
}
