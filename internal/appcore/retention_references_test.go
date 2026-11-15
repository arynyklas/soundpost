// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
	"github.com/arynyklas/soundpost/internal/storage"
)

// refsRig is the replay rig plus the composite References source. The node's real
// retention service (app.Retention) runs on a clock the test moves
// (retention.Service.UseClock): runAt is one real RunOnce. pass is the simulated pass,
// kept beside it, that drives the same engine erase at any instant without the
// worker's hourly expiry schedule: a dry plan over every candidate (nothing is
// erased; an error ends the pass), then the erase with the same guard
// (retention/worker.go, extra and EraseExpired).
type refsRig struct {
	*indexRig
	refs   retention.References
	clock  *retentionClock
	writer *auth.Scope // the artifact writer of uploadBlob, once there is one
}

// retentionClock is the time source of the node's real retention service, moved by
// the test (retention.Service.UseClock): appcore.Open reads the wall clock, and a
// replay is retained for days.
type retentionClock struct{ v atomic.Int64 }

func (c *retentionClock) now() time.Time { return time.Unix(0, c.v.Load()) }

func newRefsRig(t *testing.T) *refsRig {
	t.Helper()
	r := &refsRig{indexRig: newIndexRig(t), clock: &retentionClock{}}
	r.clock.v.Store(time.Now().UnixNano())
	if err := r.app.Retention.UseClock(r.clock.now); err != nil {
		t.Fatal(err)
	}
	replay, err := appcore.NewReplayService(r.app.Storage, r.app.Auth, r.app.Control)
	if err != nil {
		t.Fatal(err)
	}
	if r.refs, err = appcore.NewRetentionReferences(r.app.ArtifactLifecycle, replay); err != nil {
		t.Fatal(err)
	}
	return r
}

// runAt is one real Retention.RunOnce of the node, the retention clock set to now.
func (r *refsRig) runAt(now model.UnixNano) error {
	r.clock.v.Store(int64(now))
	return r.app.Retention.RunOnce(r.ctx)
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

// replayChain is replayChainFor with the group ten minutes past the checkpoint's own
// deadline: the span of the simulated pass, which is driven at any instant.
func (r *refsRig) replayChain() (model.UnixNano, model.ID) {
	r.t.Helper()
	return r.replayChainFor(10 * time.Minute)
}

// replayChainFor admits a checkpoint and a delta and moves the retention group of the
// replay the given span past the checkpoint's own deadline, as a chunk admitted later
// would. It returns the checkpoint's own deadline and the replay. The real retention
// worker runs its expiry once an hour (retention.WorkerConfig.ExpiryInterval), so a
// test that runs it twice makes the span longer than that.
func (r *refsRig) replayChainFor(span time.Duration) (model.UnixNano, model.ID) {
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
	if err = replay.RecordScope(r.ctx, scope, r.project, d, own+model.UnixNano(span)); err != nil {
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

// failingReplaySource is the composite with its replay source broken on demand: a
// candidate that is a replay chunk gets an error while armed, every other
// candidate (an artifact blob) gets the real composite's answer.
type failingReplaySource struct {
	retention.References
	armed  atomic.Bool
	failed atomic.Int64
}

func (f *failingReplaySource) LatestReference(ctx context.Context, c storage.EraseCandidate) (model.UnixNano, error) {
	if f.armed.Load() && c.Kind == model.Replay {
		f.failed.Add(1)
		return 0, model.Fail(model.Unavailable)
	}
	return f.References.LatestReference(ctx, c)
}

// writerScope is a scope of a user who holds artifacts.write on the rig's project.
func (r *refsRig) writerScope() auth.Scope {
	r.t.Helper()
	if r.writer != nil {
		return *r.writer
	}
	writer := model.NewID()
	r.command("create_user", auth.AdminPayload{ID: writer, Email: "blob-writer@example.test", Password: "blob writer password 2026"})
	r.command("membership", auth.AdminPayload{UserID: writer, Enabled: true})
	r.command("grant", auth.AdminPayload{UserID: writer, ProjectID: r.project, Enabled: true, Permissions: []string{string(auth.ArtifactWrite)}})
	login, err := r.app.Auth.Login(r.ctx, "blob-writer@example.test", "blob writer password 2026", "")
	if err != nil {
		r.t.Fatal(err)
	}
	cred, err := r.app.Auth.Authenticate(r.ctx, login.Token)
	if err != nil {
		r.t.Fatal(err)
	}
	scope, err := r.app.Auth.Authorize(r.ctx, cred, r.org, []model.ID{r.project}, auth.ArtifactWrite)
	if err != nil {
		r.t.Fatal(err)
	}
	r.writer = &scope
	return scope
}

// uploadBlob puts one real artifact (a blob root that expires an hour from now)
// into the replay rig's node, through a user who holds artifacts.write.
func (r *refsRig) uploadBlob(debug string) artifacts.Artifact {
	r.t.Helper()
	scope := r.writerScope()
	raw := []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA"}`)
	m := artifacts.Manifest{Version: 1, Org: r.org, Project: r.project, Source: r.source, Build: r.resource.Build, DebugID: debug,
		GeneratedSHA256: model.HashCanonical([]byte("generated")), MapSHA256: model.HashCanonical(raw), Path: "dist/" + debug + ".js",
		Size: model.Uint64(len(raw)), RetainUntil: model.UnixNano(time.Now().Add(time.Hour).UnixNano())}
	a, err := r.app.Artifacts.Put(r.ctx, scope, m, bytes.NewReader(raw))
	if err != nil {
		r.t.Fatal(err)
	}
	return a
}

// One expiry pass over a blob root and a replay chunk that are both due, with the
// replay reference source failing: the pass fails closed for BOTH kinds, so the
// blob that no failing source guards is not erased either (the dry plan runs over
// every candidate before any byte goes). After the source answers again, one pass
// erases the blob and the replay chunks together.
func TestMixedBlobAndReplayPassFailsClosedWhenOneSourceFails(t *testing.T) {
	r := newRefsRig(t)
	failing := &failingReplaySource{References: r.refs}
	r.refs = failing
	own, replay := r.replayChain()
	blob := r.uploadBlob("mixed-pass")
	if err := r.app.Storage.VerifyBlob(r.ctx, blob.Map); err != nil {
		t.Fatalf("fixture: the blob must be stored: %v", err)
	}
	now := own + model.UnixNano(11*time.Minute)
	if int64(blob.Map.Manifest.RetainUntil) >= int64(now) {
		t.Fatal("fixture: the blob must be due at the pass clock")
	}

	failing.armed.Store(true)
	if err := r.pass(now); err == nil {
		t.Fatal("a pass whose replay source failed succeeded")
	}
	if failing.failed.Load() == 0 {
		t.Fatal("fixture: the replay source was never consulted")
	}
	if err := r.app.Storage.VerifyBlob(r.ctx, blob.Map); err != nil {
		t.Fatalf("the failed pass erased the blob that no failing source guards: %v", err)
	}
	if rows := r.storedRows(replay); rows != 2 {
		t.Fatalf("%d replay rows remain after the failed pass, want 2", rows)
	}

	failing.armed.Store(false)
	if err := r.pass(now); err != nil {
		t.Fatal(err)
	}
	if err := r.app.Storage.VerifyBlob(r.ctx, blob.Map); err == nil {
		t.Fatal("the blob survived the pass that all sources answered")
	}
	if rows := r.storedRows(replay); rows != 0 {
		t.Fatalf("%d replay rows remain after the healthy pass", rows)
	}
}

// breakReplayState makes the replay reference state of the rig's project unreadable
// and returns the function that puts the readable state back.
func (r *refsRig) breakReplayState() (restore func()) {
	r.t.Helper()
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
			r.t.Fatal(err)
		}
	}
	set(json.RawMessage(`"unreadable"`), true)
	return func() { set(saved, false) }
}

// The node's own retention service (the one appcore.Open builds and a served process
// runs), driven by RunOnce on a clock moved past the retention of a replay: a replay
// checkpoint stays while the group of a retained chunk needs it, and the whole group
// is erased by the first pass after the group deadline. 10.12-W1, 09.05-W2.
func TestRealRetentionPassExpiresAReplayGroupAtTheInjectedClock(t *testing.T) {
	r := newRefsRig(t)
	own, replay := r.replayChainFor(3 * time.Hour)
	before := r.app.Retention.Status().ExpiryErased

	if err := r.runAt(own + model.UnixNano(90*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if rows := r.storedRows(replay); rows != 2 {
		t.Fatalf("%d rows remain after a real pass past the checkpoint's own deadline while the group is retained, want 2", rows)
	}
	if got := r.app.Retention.Status().ExpiryErased - before; got != 0 {
		t.Fatalf("the pass inside the group's retention erased %d rows", got)
	}

	if err := r.runAt(own + model.UnixNano(4*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if rows := r.storedRows(replay); rows != 0 {
		t.Fatalf("%d rows remain after a real pass past the group deadline", rows)
	}
	if got := r.app.Retention.Status().ExpiryErased - before; got != 2 {
		t.Fatalf("the real pass past the group deadline erased %d rows, want 2 (checkpoint and delta)", got)
	}
}

// A blob root and a replay chunk are both due in one real RunOnce, and the replay's
// reference state cannot be read: the pass fails, and the blob that the broken source
// does not guard is not erased either. The next real pass, the state readable again,
// erases the blob and the replay chunks together. 10.12-W2, 09.05-W2, 09.04-W4.
func TestRealRetentionPassFailsClosedForBlobAndReplayWhenTheReplaySourceFails(t *testing.T) {
	r := newRefsRig(t)
	own, replay := r.replayChainFor(3 * time.Hour)
	blob := r.uploadBlob("real-mixed-pass")
	if err := r.app.Storage.VerifyBlob(r.ctx, blob.Map); err != nil {
		t.Fatalf("fixture: the blob must be stored: %v", err)
	}
	now := own + model.UnixNano(4*time.Hour)
	if int64(blob.Map.Manifest.RetainUntil) >= int64(now) {
		t.Fatal("fixture: the blob must be due at the pass clock")
	}
	before := r.app.Retention.Status().ExpiryErased

	restore := r.breakReplayState()
	if err := r.runAt(now); err == nil {
		t.Fatal("a real pass with unreadable replay reference state succeeded")
	}
	if err := r.app.Storage.VerifyBlob(r.ctx, blob.Map); err != nil {
		t.Fatalf("the failed real pass erased the blob that the broken source does not guard: %v", err)
	}
	if rows := r.storedRows(replay); rows != 2 {
		t.Fatalf("%d replay rows remain after the failed real pass, want 2", rows)
	}
	if got := r.app.Retention.Status().ExpiryErased - before; got != 0 {
		t.Fatalf("the failed real pass counted %d erased", got)
	}

	restore()
	if err := r.runAt(now); err != nil {
		t.Fatal(err)
	}
	if err := r.app.Storage.VerifyBlob(r.ctx, blob.Map); err == nil {
		t.Fatal("the blob survived the real pass that every source answered")
	}
	if rows := r.storedRows(replay); rows != 0 {
		t.Fatalf("%d replay rows remain after the healthy real pass", rows)
	}
	if got := r.app.Retention.Status().ExpiryErased - before; got != 3 {
		t.Fatalf("the healthy real pass erased %d, want 3 (blob, checkpoint, delta)", got)
	}
}

// A map that an error references past its own upload retention stays through a real
// pass at the clock that has the upload due, and is erased by the first real pass after
// the reference ends, with no waiting on the wall clock. 09.04-W4.
func TestRealRetentionPassKeepsAReferencedMapUntilTheReferenceEnds(t *testing.T) {
	r := newRefsRig(t)
	blob := r.uploadBlob("real-referenced")
	due := blob.Map.Manifest.RetainUntil
	refUntil := due + model.UnixNano(5*time.Hour)
	origin := artifacts.OriginCursor{Kind: artifacts.ReferenceError, Cursor: model.Cursor{Group: model.NewID(), Index: 1}}
	if err := r.app.ArtifactLifecycle.Reference(r.ctx, r.writerScope(), blob.ID, origin, refUntil); err != nil {
		t.Fatal(err)
	}

	if err := r.runAt(due + model.UnixNano(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := r.app.Storage.VerifyBlob(r.ctx, blob.Map); err != nil {
		t.Fatalf("a real pass past the upload retention erased a map an error still references: %v", err)
	}
	if err := r.runAt(refUntil + model.UnixNano(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := r.app.Storage.VerifyBlob(r.ctx, blob.Map); err == nil {
		t.Fatal("the map survived the real pass after its reference ended")
	}
}
