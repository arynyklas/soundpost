// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replays

import (
	"github.com/arynyklas/soundpost/internal/model"
	"testing"
	"time"
)

// CheckIndex is the read half of RecordScope: it refuses from the index alone
// what RecordScope would refuse, so admission can refuse a conflicting
// checkpoint before it is stored, and it never writes.
func TestReplayCheckIndexRefusesWhatRecordRefusesAndWritesNothing(t *testing.T) {
	f := newFx(t)
	r := newRecorder(f.wall())
	cp, d := r.cp(), r.delta()
	g := f.grant(f.main)
	scope, err := g.Scope()
	if err != nil {
		t.Fatal(err)
	}
	project := f.main.project
	until := f.wall() + model.UnixNano(24*time.Hour)

	forged := cp
	forged.Events = []model.MaskedEvent{{At: 1, Kind: "pointer", Node: 1, X: 9, Y: 9}}
	alien := cp
	alien.Session = model.NewID()
	alienDelta := d
	alienDelta.Session = alien.Session
	stranger := newRecorder(f.wall()).cp()

	// Before anything is recorded every chunk is admissible.
	for name, c := range map[string]model.ReplayChunk{"checkpoint": cp, "forged checkpoint": forged, "foreign session": alien, "unrelated replay": stranger} {
		if err := f.svc.CheckIndex(f.ctx, scope, project, c); err != nil {
			t.Fatalf("%s refused by an empty index: %v", name, err)
		}
	}
	if err = f.svc.RecordScope(f.ctx, scope, project, cp, until); err != nil {
		t.Fatal(err)
	}
	settled := f.revision()

	for name, c := range map[string]model.ReplayChunk{"the recorded checkpoint": cp, "a delta of the recorded session": d, "an unrelated replay": stranger} {
		if err := f.svc.CheckIndex(f.ctx, scope, project, c); err != nil {
			t.Fatalf("%s refused: %v", name, err)
		}
	}
	for name, c := range map[string]model.ReplayChunk{"a different chunk at the recorded checkpoint": forged, "a foreign session's checkpoint": alien, "a foreign session's delta": alienDelta} {
		if got := code(f.svc.CheckIndex(f.ctx, scope, project, c)); got != model.Conflict {
			t.Fatalf("%s: %q, want conflict", name, got)
		}
		if got := code(f.svc.RecordScope(f.ctx, scope, project, c, until)); got != model.Conflict {
			t.Fatalf("%s: record %q, want conflict (the check must agree with the write)", name, got)
		}
	}
	if got := f.revision(); got != settled {
		t.Fatalf("a check or a refused record wrote the control state (revision %d -> %d)", settled, got)
	}
	if got := code(f.svc.CheckIndex(f.ctx, scope, model.NewID(), cp)); got != model.Forbidden {
		t.Fatalf("a project outside the scope was checked: %q", got)
	}
	bad := cp
	bad.Recorder = "soundpost1"
	if got := code(f.svc.CheckIndex(f.ctx, scope, project, bad)); got != model.Unsupported {
		t.Fatalf("a chunk outside the closed format was checked: %q", got)
	}
}

// A scope whose authority cannot be confirmed learns nothing from the index.
func TestReplayCheckIndexAnswersNothingToAnUnconfirmedScope(t *testing.T) {
	f := newFx(t)
	r := newRecorder(f.wall())
	cp := r.cp()
	scope, err := f.grant(f.main).Scope()
	if err != nil {
		t.Fatal(err)
	}
	if err = f.svc.RecordScope(f.ctx, scope, f.main.project, cp, f.wall()+model.UnixNano(time.Hour)); err != nil {
		t.Fatal(err)
	}
	forged := cp
	forged.Events = []model.MaskedEvent{{At: 1, Kind: "pointer", Node: 1, X: 9, Y: 9}}
	down := &flaky{ScopeAuthorizer: f.auth}
	f.svc.authorizer = down
	down.down.Store(true)
	if got := code(f.svc.CheckIndex(f.ctx, scope, f.main.project, forged)); got != model.Unavailable {
		t.Fatalf("an unconfirmed scope was told %q about the index", got)
	}
}

// The index holds at most MaxCheckpoints; the check refuses the next one the way
// the write would, so a full index refuses a checkpoint before it is stored.
func TestReplayCheckIndexRefusesACheckpointBeyondTheBound(t *testing.T) {
	org, project := model.NewID(), model.NewID()
	st := model.ControlState{Orgs: map[string]model.ControlOrg{org.String(): {}}}
	r := newRecorder(1_800_000_000_000_000_000)
	now := time.Unix(0, 1_800_000_000_000_000_000)
	until := model.UnixNano(now.Add(time.Hour).UnixNano())
	for i := range MaxCheckpoints {
		c := r.cp()
		hash, err := ChunkHash(c)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = applyIndex(&st, org, project, c, hash, until, now); err != nil {
			t.Fatalf("checkpoint %d: %v", i+1, err)
		}
	}
	c := r.cp()
	hash, err := ChunkHash(c)
	if err != nil {
		t.Fatal(err)
	}
	wrote, err := applyIndex(&st, org, project, c, hash, until, now)
	if code(err) != model.TooLarge || wrote {
		t.Fatalf("checkpoint %d: wrote=%v err=%v, want too_large and no write", MaxCheckpoints+1, wrote, err)
	}
}
