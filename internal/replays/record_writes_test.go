// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replays

import (
	"soundpost/internal/model"
	"testing"
	"time"
)

// The retention group deadline is coalesced to a minute so that a replay costs a
// bounded number of control writes. Every control write is a replicated entry
// that rewrites the whole control state and spends a control revision (the
// compare-and-set token of every admin command), so a Record that changes nothing
// must not write at all: once admission records every chunk, a no-op write per
// chunk would fail concurrent admin commands with conflicts.
func TestReplayRecordWritesNothingWhenNothingChanges(t *testing.T) {
	f := newFx(t)
	r := newRecorder(f.wall())
	cp, d := r.cp(), r.delta()
	g := f.grant(f.main)
	until := f.wall() + model.UnixNano(24*time.Hour)
	if err := f.svc.Record(f.ctx, g, f.main.project, cp, until); err != nil {
		t.Fatal(err)
	}
	settled := f.revision()
	for name, step := range map[string]func() error{
		"the same checkpoint again":           func() error { return f.svc.Record(f.ctx, g, f.main.project, cp, until) },
		"a delta inside the coalescing slack": func() error { return f.svc.Record(f.ctx, g, f.main.project, d, until+model.UnixNano(30*time.Second)) },
		"a delta with an older deadline":      func() error { return f.svc.Record(f.ctx, g, f.main.project, d, until-model.UnixNano(time.Hour)) },
	} {
		if err := step(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := f.revision(); got != settled {
			t.Fatalf("%s wrote the control state (revision %d -> %d)", name, settled, got)
		}
	}

	// A change still writes exactly once: a deadline more than the slack ahead,
	// then a new checkpoint.
	if err := f.svc.Record(f.ctx, g, f.main.project, d, until+model.UnixNano(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := f.revision(); got != settled+1 {
		t.Fatalf("a deadline move was not written once: revision %d -> %d", settled, got)
	}
	cp2 := r.cp()
	if err := f.svc.Record(f.ctx, g, f.main.project, cp2, until+model.UnixNano(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := f.revision(); got != settled+2 {
		t.Fatalf("a new checkpoint was not written once: revision %d -> %d", settled, got)
	}
}
