// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
	"github.com/arynyklas/soundpost/internal/storage"
)

// refsRig is the replay rig plus the composite References source and the real
// storage erase pass driven at a clock the test chooses: appcore.Open's own
// retention service runs on the wall clock, a replay is retained for days, and a
// second retention.Service over the same Store cannot be built (retention.New
// registers on the Store once). pass is the pass the retention worker makes:
// a dry plan over every candidate (nothing is erased; an error ends the pass), then
// the erase with the same guard (retention/worker.go, extra and EraseExpired).
type refsRig struct {
	*indexRig
	refs retention.References
}

func newRefsRig(t *testing.T) *refsRig {
	t.Helper()
	r := &refsRig{indexRig: newIndexRig(t)}
	replay, err := appcore.NewReplayService(r.app.Storage, r.app.Auth, r.app.Control)
	if err != nil {
		t.Fatal(err)
	}
	if r.refs, err = appcore.NewRetentionReferences(r.app.ArtifactLifecycle, replay); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *refsRig) pass(now model.UnixNano) error {
	guard := func(ctx context.Context, c storage.EraseCandidate) (bool, error) {
		ref, err := r.refs.LatestReference(ctx, c)
		if err != nil {
			return false, err
		}
		return ref <= now, nil
	}
	if _, err := r.app.Storage.EraseExpired(r.ctx, now, func(ctx context.Context, c storage.EraseCandidate) (bool, error) {
		_, err := guard(ctx, c)
		return false, err
	}); err != nil {
		return err
	}
	_, err := r.app.Storage.EraseExpired(r.ctx, now, guard)
	return err
}

func replayDeadlineOf(rc model.Receipt) model.UnixNano {
	for _, d := range rc.SignalDeadlines {
		if d.Kind == model.Replay {
			return d.RetainUntil
		}
	}
	return 0
}

// replayChain admits a checkpoint and a delta and moves the retention group of the
// replay ten minutes past the checkpoint's own deadline, as a chunk admitted later
// would. It returns the checkpoint's own deadline and the replay.
func (r *refsRig) replayChain() (model.UnixNano, model.ID) {
	r.t.Helper()
	rec := newReplayRecorder()
	cp, d := rec.cp(), rec.delta()
	first, err := r.admit(r.replayBatch(cp))
	if err != nil {
		r.t.Fatal(err)
	}
	later := r.replayBatch(d)
	if _, err = r.admit(later); err != nil {
		r.t.Fatal(err)
	}
	cred, err := r.app.Auth.AuthenticateSource(r.ctx, r.issued, "", false)
	if err != nil {
		r.t.Fatal(err)
	}
	grant, err := r.app.Ingest.ResolveSource(r.ctx, cred, later)
	if err != nil {
		r.t.Fatal(err)
	}
	scope, err := grant.Scope()
	if err != nil {
		r.t.Fatal(err)
	}
	replay, err := appcore.NewReplayService(r.app.Storage, r.app.Auth, r.app.Control)
	if err != nil {
		r.t.Fatal(err)
	}
	own := replayDeadlineOf(first)
	if err = replay.RecordScope(r.ctx, scope, r.project, d, own+model.UnixNano(10*time.Minute)); err != nil {
		r.t.Fatal(err)
	}
	if r.storedRows(rec.replay) != 2 {
		r.t.Fatal("fixture invalid: both chunks must be stored")
	}
	return own, rec.replay
}

// A replay checkpoint outlives its own deadline while a retained chunk of the
// replay depends on it, through the real erase pass over the real stores; the
// whole group goes together once the group deadline passes. With only the
// artifact lifecycle consulted (the state before the composite) both rows are
// erased at the first pass: see 10.12-mutants.txt, mutant M2.
func TestRetentionKeepsAReplayCheckpointPastItsOwnDeadline(t *testing.T) {
	r := newRefsRig(t)
	own, replay := r.replayChain()
	if err := r.pass(own + model.UnixNano(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if rows := r.storedRows(replay); rows != 2 {
		t.Fatalf("%d rows remain past the checkpoint's own deadline while the group is retained, want 2", rows)
	}
	if err := r.pass(own + model.UnixNano(11*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if rows := r.storedRows(replay); rows != 0 {
		t.Fatalf("%d rows remain after the group deadline", rows)
	}
}

// An error of a reference source ends the pass: the dry plan runs over every
// candidate before any byte is erased, so one chunk whose references cannot be
// read erases nothing, of any kind (the composite answers per candidate; the
// pass-wide veto is the worker's plan). After the state is readable again the next
// pass erases.
func TestAReplayReferenceErrorFailsTheWholeExpiryPassClosed(t *testing.T) {
	r := newRefsRig(t)
	own, replay := r.replayChain()
	key := "replay_pins:" + r.project.String()
	var saved json.RawMessage
	set := func(raw json.RawMessage, remember bool) {
		if err := r.app.Control.Update(r.ctx, func(st *model.ControlState) error {
			o := st.Orgs[r.org.String()]
			if remember {
				saved = o.Settings[key]
			}
			o.Settings[key] = raw
			st.Orgs[r.org.String()] = o
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	set(json.RawMessage(`"unreadable"`), true)
	if err := r.pass(own + model.UnixNano(11*time.Minute)); err == nil {
		t.Fatal("a pass with unreadable replay reference state succeeded")
	}
	if rows := r.storedRows(replay); rows != 2 {
		t.Fatalf("%d rows remain after a failed pass, want 2: nothing may be erased", rows)
	}
	set(saved, false)
	if err := r.pass(own + model.UnixNano(11*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if rows := r.storedRows(replay); rows != 0 {
		t.Fatalf("%d rows remain after the state is readable again", rows)
	}
}

type probeRefs struct{}

func (probeRefs) LatestReference(context.Context, storage.EraseCandidate) (model.UnixNano, error) {
	return 0, nil
}

// The wiring: a node opened the way a served process is opened has exactly one
// References binding on its retention service (the composite; building the
// artifact lifecycle no longer takes the slot). Retention refuses a second one.
func TestOpenBindsTheRetentionReferencesOnce(t *testing.T) {
	r := newIndexRig(t)
	if got := r.app.Retention.UseReferences(probeRefs{}); codeOf(got) != model.Conflict {
		t.Fatalf("retention has no References source bound (or accepted a second one): %v", got)
	}
	if got := r.app.Retention.UseReferences(nil); codeOf(got) != model.Invalid {
		t.Fatalf("a nil source: %v", got)
	}
	replay, err := appcore.NewReplayService(r.app.Storage, r.app.Auth, r.app.Control)
	if err != nil {
		t.Fatal(err)
	}
	if got := appcore.BindRetentionReferences(r.app.Retention, r.app.ArtifactLifecycle, replay); codeOf(got) != model.Conflict {
		t.Fatalf("a second composite binding: %v", got)
	}
	for name, err := range map[string]error{
		"no retention": appcore.BindRetentionReferences(nil, r.app.ArtifactLifecycle, replay),
		"no lifecycle": appcore.BindRetentionReferences(r.app.Retention, nil, replay),
		"no replay":    appcore.BindRetentionReferences(r.app.Retention, r.app.ArtifactLifecycle, nil),
	} {
		if codeOf(err) != model.Invalid {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
