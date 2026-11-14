// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
	"github.com/arynyklas/soundpost/internal/storage"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const fixturePassword = "artifact fixture password 2026"

func codeOf(err error) model.Code {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fault.Code
	}
	return ""
}

type fakePins struct {
	mu     sync.Mutex
	pinned bool
	err    error
}

func (p *fakePins) Pinned(context.Context, model.ID, model.ID, model.ID) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pinned, p.err
}
func (p *fakePins) set(pinned bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pinned, p.err = pinned, err
}

// bumpGenerations is the real retention generation plus a controllable extra
// advance, so a test can move only the generation fence.
type bumpGenerations struct {
	base  auth.DeleteGenerations
	extra atomic.Uint64
}

func (g *bumpGenerations) DeleteGeneration(ctx context.Context, org model.ID, projects []model.ID) (uint64, error) {
	base, err := g.base.DeleteGeneration(ctx, org, projects)
	return base + g.extra.Load(), err
}

type lifeFx struct {
	*artifactFixture
	life   *artifacts.Lifecycle
	pins   *fakePins
	gens   *bumpGenerations
	offset atomic.Int64
	seq    atomic.Uint64
}

func newLifeFx(t *testing.T, cacheBytes int) *lifeFx {
	t.Helper()
	f := &lifeFx{artifactFixture: newArtifactFixture(t), pins: &fakePins{}}
	f.attach(t, cacheBytes)
	return f
}

// attach (re)builds the lifecycle over the fixture's current app.
func (f *lifeFx) attach(t *testing.T, cacheBytes int) {
	t.Helper()
	f.gens = &bumpGenerations{base: f.app.Retention}
	var err error
	f.life, err = artifacts.NewLifecycle(f.app.Artifacts, artifacts.LifecycleConfig{
		State: f.app.Control, Deletes: f.gens, Pins: f.pins, CacheBytes: cacheBytes,
		Now: func() time.Time { return time.Now().Add(time.Duration(f.offset.Load())) },
	})
	if err != nil {
		t.Fatal(err)
	}
}
func (f *lifeFx) at(d time.Duration) { f.offset.Store(int64(d)) }
func (f *lifeFx) hours(h float64) model.UnixNano {
	return model.UnixNano(time.Now().Add(time.Duration(h * float64(time.Hour))).UnixNano())
}
func (f *lifeFx) origin(kind artifacts.ReferenceKind) artifacts.OriginCursor {
	return artifacts.OriginCursor{Kind: kind, Cursor: model.Cursor{Group: model.NewID(), Index: model.Uint64(f.seq.Add(1))}}
}
func (f *lifeFx) put(t *testing.T, debug string, private bool) artifacts.Artifact {
	t.Helper()
	raw := []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA","sourcesContent":["PRIVATE SOURCE ` + debug + `"]}`)
	m := f.manifest(raw)
	m.DebugID, m.Path, m.SourceContent = debug, "dist/"+debug+".js", private
	a, err := f.app.Artifacts.Put(context.Background(), f.scope(t, auth.ArtifactWrite), m, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func (f *lifeFx) candidate(a artifacts.Artifact) storage.EraseCandidate {
	m := a.Map.Manifest
	return storage.EraseCandidate{Org: m.Org, Project: m.Project, Blob: &m, Cursor: a.Map.Cursor}
}
func (f *lifeFx) latest(t *testing.T, a artifacts.Artifact) model.UnixNano {
	t.Helper()
	got, err := f.life.LatestReference(context.Background(), f.candidate(a))
	if err != nil {
		t.Fatalf("LatestReference: %v", err)
	}
	return got
}
func (f *lifeFx) ref(t *testing.T, a artifacts.Artifact, o artifacts.OriginCursor, until model.UnixNano) {
	t.Helper()
	if err := f.life.Reference(context.Background(), f.scope(t, auth.ArtifactWrite), a.ID, o, until); err != nil {
		t.Fatalf("Reference %s: %v", o.Kind, err)
	}
}
func (f *lifeFx) setReaders(t *testing.T, readers ...model.ID) {
	t.Helper()
	if err := f.app.Control.Update(context.Background(), func(st *model.ControlState) error {
		o := st.Orgs[f.org.String()]
		cfg, err := json.Marshal(auth.SourcePolicyConfig{ProjectID: f.project, Enabled: true, Readers: readers})
		if err != nil {
			return err
		}
		o.Settings["source_policy:"+f.source.String()] = cfg
		st.Orgs[f.org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func readAllClose(t *testing.T, r io.ReadCloser) []byte {
	t.Helper()
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The map stays until the LAST referencing occurrence/profile expires: an
// expired reference never shortens a live sibling, an unreference of the longest
// one falls back to the next, and only when nothing is retained is the map
// fenced for erasure.
func TestLastRetainedOccurrencePinsMap(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	a := f.put(t, "pinned", false)
	errA, errB, prof := f.origin(artifacts.ReferenceError), f.origin(artifacts.ReferenceError), f.origin(artifacts.ReferenceProfile)
	f.ref(t, a, errA, f.hours(3))
	f.ref(t, a, errB, f.hours(5))
	f.ref(t, a, prof, f.hours(4))
	untilB := f.hours(5)

	f.at(2 * time.Hour) // the upload's own retention (1h) is over; references remain
	if got := f.latest(t, a); got < untilB-model.UnixNano(time.Minute) || got > untilB+model.UnixNano(time.Minute) {
		t.Fatalf("latest retained reference %d, want about +5h %d", got, untilB)
	}
	if eff, err := f.life.EffectiveRetention(ctx, f.scope(t, auth.ArtifactRead), a.ID); err != nil || eff < untilB-model.UnixNano(time.Minute) {
		t.Fatalf("effective retention %d %v", eff, err)
	}
	if err := f.life.Unreference(ctx, f.scope(t, auth.ArtifactWrite), a.ID, errB, 0); err != nil {
		t.Fatal(err)
	}
	f.at(3*time.Hour + 30*time.Minute) // errA (3h) expired, the profile (4h) is its live sibling
	if got := f.latest(t, a); got <= model.UnixNano(time.Now().Add(f.durationAhead()).UnixNano()) {
		t.Fatalf("expired sibling released a map the live profile still needs: %d", got)
	}
	if _, err := f.app.Artifacts.Get(ctx, f.scope(t, auth.ArtifactRead), a.ID); err != nil {
		t.Fatalf("map unreadable while retained: %v", err)
	}
	f.at(4*time.Hour + 30*time.Minute) // everything expired
	if got := f.latest(t, a); got > model.UnixNano(time.Now().Add(f.durationAhead()).UnixNano()) {
		t.Fatalf("nothing retained but the map is still pinned: %d", got)
	}
	if err := f.life.Reference(ctx, f.scope(t, auth.ArtifactWrite), a.ID, f.origin(artifacts.ReferenceError), f.hours(9)); codeOf(err) != model.Conflict {
		t.Fatalf("a map fenced for erasure was re-referenced: %v", err)
	}
	if _, err := f.app.Artifacts.Get(ctx, f.scope(t, auth.ArtifactRead), a.ID); codeOf(err) != model.NotFound {
		t.Fatalf("fenced map still readable through the common Get path: %v", err)
	}

	// With no reference at all the upload's own expiry governs.
	b := f.put(t, "unreferenced", false)
	f.at(30 * time.Minute)
	if got := f.latest(t, b); got < b.Manifest.RetainUntil {
		t.Fatalf("unexpired upload reported unretained: %d < %d", got, b.Manifest.RetainUntil)
	}
	f.at(2 * time.Hour)
	if got := f.latest(t, b); got > model.UnixNano(time.Now().Add(f.durationAhead()).UnixNano()) {
		t.Fatalf("unreferenced expired map pinned: %d", got)
	}

	// Default: an unspecified retention is 90 days from the reference.
	c := f.put(t, "default90", false)
	f.at(0)
	f.ref(t, c, f.origin(artifacts.ReferenceBuild), 0)
	eff, err := f.life.EffectiveRetention(ctx, f.scope(t, auth.ArtifactRead), c.ID)
	want := model.UnixNano(time.Now().Add(90 * 24 * time.Hour).UnixNano())
	if err != nil || eff < want-model.UnixNano(time.Minute) || eff > want+model.UnixNano(time.Minute) {
		t.Fatalf("default retention %d, want about %d: %v", eff, want, err)
	}
	// Record candidates (errors, profiles) are never held by a map's ledger.
	rec := model.Record{ID: model.NewID(), Kind: model.ErrorKind}
	if got, err := f.life.LatestReference(ctx, storage.EraseCandidate{Org: f.org, Project: f.project, Kind: model.ErrorKind, Record: &rec}); err != nil || got != 0 {
		t.Fatalf("record candidate: %d %v", got, err)
	}
}
func (f *lifeFx) durationAhead() time.Duration { return time.Duration(f.offset.Load()) }

func (f *lifeFx) secondSession(t *testing.T) auth.Scope {
	t.Helper()
	ctx := context.Background()
	s, err := f.app.Auth.Login(ctx, "artifact@example.test", fixturePassword, "")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := f.app.Auth.Authenticate(ctx, s.Token)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := f.app.Auth.Authorize(ctx, actor, f.org, []model.ID{f.project}, auth.ArtifactRead)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

// Private source bytes are warm only for the exact visibility that read them; a
// distinct grant set (here another session, then a revoked reader grant) never
// reuses them, and a revoked grant stops a stream before its next byte even
// though the fragment is already held in memory.
func TestPrivateArtifactCacheAndReadRevocation(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	a := f.put(t, "private", true)
	reader := f.scope(t, auth.ArtifactRead).PrincipalID()

	first := readAllClose(t, mustOpen(t, f, f.scope(t, auth.ArtifactRead), a.ID, true))
	if !bytes.Contains(first, []byte("PRIVATE SOURCE private")) {
		t.Fatalf("named reader did not get sources: %s", first)
	}
	if s := f.life.CacheStats(); s.Hits != 0 || s.Misses != 1 {
		t.Fatalf("cold read stats %+v", s)
	}
	if again := readAllClose(t, mustOpen(t, f, f.scope(t, auth.ArtifactRead), a.ID, true)); !bytes.Equal(again, first) {
		t.Fatal("warm read differs")
	}
	if s := f.life.CacheStats(); s.Hits != 1 || s.Misses != 1 {
		t.Fatalf("same visibility did not reuse bytes: %+v", s)
	}
	other := f.secondSession(t)
	if !bytes.Equal(readAllClose(t, mustOpen(t, f, other, a.ID, true)), first) {
		t.Fatal("second authorized session read wrong bytes")
	}
	if s := f.life.CacheStats(); s.Hits != 1 || s.Misses != 2 {
		t.Fatalf("a different visibility reused warm private bytes: %+v", s)
	}

	f.setReaders(t) // the named source-reader grant is revoked
	if _, err := f.app.Artifacts.ReadSourcesAuthorized(ctx, f.scope(t, auth.ArtifactRead), a.ID, artifacts.Window{}); codeOf(err) != model.NotFound {
		t.Fatalf("revoked grant still opened warm sources: %v", err)
	}
	if s := f.life.CacheStats(); s.Hits != 1 || s.Misses != 2 {
		t.Fatalf("cache consulted for a denied caller: %+v", s)
	}

	f.setReaders(t, reader)
	r := mustOpen(t, f, f.scope(t, auth.ArtifactRead), a.ID, true)
	buf := make([]byte, 4)
	if n, err := r.Read(buf); err != nil || n != 4 {
		t.Fatalf("first chunk: %d %v", n, err)
	}
	f.setReaders(t) // revoked mid-stream
	probe := bytes.Repeat([]byte{0x7f}, 8)
	if n, err := r.Read(probe); n != 0 || codeOf(err) != model.NotFound || !bytes.Equal(probe, bytes.Repeat([]byte{0x7f}, 8)) {
		t.Fatalf("a byte was released after the grant was revoked: n=%d err=%v", n, err)
	}
	r.Close()
}
func mustOpen(t *testing.T, f *lifeFx, scope auth.Scope, id artifacts.ArtifactID, private bool) artifacts.ArtifactReader {
	t.Helper()
	var r artifacts.ArtifactReader
	var err error
	if private {
		r, err = f.app.Artifacts.ReadSourcesAuthorized(context.Background(), scope, id, artifacts.Window{})
	} else {
		r, err = f.app.Artifacts.ReadAuthorized(context.Background(), scope, id, artifacts.Window{})
	}
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *lifeFx) adminScope(t *testing.T) auth.Scope {
	t.Helper()
	actor, err := f.app.Auth.Authenticate(context.Background(), f.token)
	if err != nil {
		t.Fatal(err)
	}
	s, err := f.app.Auth.Authorize(context.Background(), actor, f.org, nil, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A restore that brings back an older control snapshot (and with it the
// artifact and its live references) cannot revive an artifact whose deletion
// tombstone the current authority re-applies.
func TestRestoreCannotReviveDeletedArtifact(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	a := f.put(t, "doomed", true)
	f.ref(t, a, f.origin(artifacts.ReferenceError), f.hours(5))
	var rev model.Revision
	if err := f.app.Control.View(ctx, func(st model.ControlState) error { rev = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	receipt, err := f.app.Retention.Delete(ctx, f.adminScope(t), retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: rev, Mode: model.DeleteEntity, OrgID: f.org, ProjectIDs: []model.ID{f.project}, EntityIDs: []model.ID{a.ID}, Reason: "artifact policy restore fixture"})
	if err != nil {
		t.Fatal(err)
	}
	for range 8 {
		if err = f.app.Retention.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
		if r, perr := f.app.Retention.PollDelete(ctx, f.adminScope(t), receipt.OperationID); perr != nil {
			t.Fatal(perr)
		} else if r.Phase == model.DeletePhaseComplete {
			break
		}
	}
	var tombstones []model.DeletePredicate
	if err = f.app.Control.View(ctx, func(st model.ControlState) error {
		for _, op := range st.Deletions {
			tombstones = append(tombstones, op.Predicate)
		}
		return nil
	}); err != nil || len(tombstones) != 1 {
		t.Fatalf("deletion record: %d %v", len(tombstones), err)
	}
	assertGone := func(label string) {
		t.Helper()
		read, write := f.scope(t, auth.ArtifactRead), f.scope(t, auth.ArtifactWrite)
		if _, err := f.app.Artifacts.Get(ctx, read, a.ID); codeOf(err) != model.NotFound {
			t.Fatalf("%s: Get %v", label, err)
		}
		if _, err := f.app.Artifacts.ReadAuthorized(ctx, read, a.ID, artifacts.Window{}); codeOf(err) != model.NotFound {
			t.Fatalf("%s: ReadAuthorized %v", label, err)
		}
		if err := f.life.Reference(ctx, write, a.ID, f.origin(artifacts.ReferenceProfile), f.hours(9)); codeOf(err) != model.NotFound {
			t.Fatalf("%s: a deleted artifact accepted a new reference: %v", label, err)
		}
		if _, err := f.life.GC(ctx, write, a.ID); codeOf(err) != model.NotFound {
			t.Fatalf("%s: GC %v", label, err)
		}
		if got := f.latest(t, a); got != 0 {
			t.Fatalf("%s: deletion does not take precedence over the live reference: %d", label, got)
		}
	}
	assertGone("after deletion")

	// Restore of an older snapshot: the tombstone is missing from control state.
	if err = f.app.Control.Update(ctx, func(st *model.ControlState) error { st.Deletions = map[string]model.DeletionOperation{}; return nil }); err != nil {
		t.Fatal(err)
	}
	// The current-ledger authority re-applies the deletion.
	if err = f.app.Control.ImportDeletions(ctx, tombstones, model.UnixNano(time.Now().UnixNano())); err != nil {
		t.Fatal(err)
	}
	assertGone("after restore and ledger re-application")
}

// Reference lifecycle rules: defaults, validation, tombstones, fences.
func TestReferenceValidationAndTombstones(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	a := f.put(t, "rules", false)
	w := f.scope(t, auth.ArtifactWrite)
	bad := []struct {
		name string
		o    artifacts.OriginCursor
		at   model.UnixNano
	}{
		{"unknown kind", artifacts.OriginCursor{Kind: "url", Cursor: model.Cursor{Group: model.NewID(), Index: 1}}, f.hours(2)},
		{"user string kind", artifacts.OriginCursor{Kind: "https://evil.example/app.js.map", Cursor: model.Cursor{Group: model.NewID(), Index: 1}}, f.hours(2)},
		{"zero group", artifacts.OriginCursor{Kind: artifacts.ReferenceError, Cursor: model.Cursor{Index: 1}}, f.hours(2)},
		{"zero index", artifacts.OriginCursor{Kind: artifacts.ReferenceError, Cursor: model.Cursor{Group: model.NewID()}}, f.hours(2)},
		{"already expired", f.origin(artifacts.ReferenceError), model.UnixNano(time.Now().Add(-time.Minute).UnixNano())},
		{"absurd horizon", f.origin(artifacts.ReferenceError), f.hours(24 * 365 * 100)},
	}
	for _, tc := range bad {
		if err := f.life.Reference(ctx, w, a.ID, tc.o, tc.at); codeOf(err) != model.Invalid {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	if err := f.life.Reference(ctx, f.scope(t, auth.ArtifactRead), a.ID, f.origin(artifacts.ReferenceError), f.hours(2)); codeOf(err) != model.NotFound {
		t.Fatalf("a read scope wrote a reference: %v", err)
	}
	o := f.origin(artifacts.ReferenceError)
	f.ref(t, a, o, f.hours(3))
	f.ref(t, a, o, f.hours(2)) // idempotent, never shortens
	if eff, _ := f.life.EffectiveRetention(ctx, f.scope(t, auth.ArtifactRead), a.ID); eff < f.hours(3)-model.UnixNano(time.Minute) {
		t.Fatalf("a repeated shorter reference shortened retention: %d", eff)
	}
	f.ref(t, a, o, f.hours(6)) // the same origin may extend
	if eff, _ := f.life.EffectiveRetention(ctx, f.scope(t, auth.ArtifactRead), a.ID); eff < f.hours(6)-model.UnixNano(time.Minute) {
		t.Fatalf("extension lost: %d", eff)
	}
	if err := f.life.Unreference(ctx, w, a.ID, o, 999); codeOf(err) != model.Conflict {
		t.Fatalf("stale fence accepted: %v", err)
	}
	if err := f.life.Unreference(ctx, w, a.ID, o, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.life.Reference(ctx, w, a.ID, o, f.hours(8)); codeOf(err) != model.Conflict {
		t.Fatalf("a released occurrence was revived: %v", err)
	}
	early := f.origin(artifacts.ReferenceProfile) // unreference arrives before the reference
	if err := f.life.Unreference(ctx, w, a.ID, early, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.life.Reference(ctx, w, a.ID, early, f.hours(8)); codeOf(err) != model.Conflict {
		t.Fatalf("an unreference that raced ahead did not stick: %v", err)
	}
	if eff, _ := f.life.EffectiveRetention(ctx, f.scope(t, auth.ArtifactRead), a.ID); eff > f.hours(2) {
		t.Fatalf("released references still retain: %d", eff)
	}
}

// GC is a fence: it needs no live reference, no pin and a complete state, and
// once taken nothing can reference or read the map; whichever of a concurrent
// reference and GC commits first wins, never both.
func TestReferenceRacesGCFence(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	w := f.scope(t, auth.ArtifactWrite)

	a := f.put(t, "gc-live", false)
	f.ref(t, a, f.origin(artifacts.ReferenceError), f.hours(5))
	f.at(2 * time.Hour)
	if _, err := f.life.GC(ctx, w, a.ID); codeOf(err) != model.Conflict {
		t.Fatalf("GC took a map with a live reference: %v", err)
	}

	b := f.put(t, "gc-pinned", false)
	f.pins.set(true, nil)
	if _, err := f.life.GC(ctx, w, b.ID); codeOf(err) != model.Conflict {
		t.Fatalf("GC ignored a snapshot pin: %v", err)
	}
	f.pins.set(false, model.Fail(model.Unavailable))
	if _, err := f.life.GC(ctx, w, b.ID); err == nil {
		t.Fatal("GC proceeded with unknown pin state")
	}
	if _, err := f.app.Artifacts.Get(ctx, f.scope(t, auth.ArtifactRead), b.ID); err != nil {
		t.Fatalf("a refused GC still hid the map: %v", err)
	}
	f.pins.set(false, nil)
	before, _ := f.app.Retention.DeleteGeneration(ctx, f.org, []model.ID{f.project})
	d, err := f.life.GC(ctx, w, b.ID)
	if err != nil || d.Seq == 0 {
		t.Fatalf("GC: %+v %v", d, err)
	}
	if after, _ := f.app.Retention.DeleteGeneration(ctx, f.org, []model.ID{f.project}); after <= before {
		t.Fatalf("GC did not advance the delete generation: %d -> %d", before, after)
	}
	if err = f.life.Reference(ctx, w, b.ID, f.origin(artifacts.ReferenceError), f.hours(9)); codeOf(err) != model.Conflict {
		t.Fatalf("reference after the GC fence: %v", err)
	}
	if _, err = f.app.Artifacts.Get(ctx, f.scope(t, auth.ArtifactRead), b.ID); codeOf(err) != model.NotFound {
		t.Fatalf("read after the GC fence: %v", err)
	}
	if d2, err := f.life.GC(ctx, w, b.ID); err != nil || d2.Seq != d.Seq {
		t.Fatalf("GC is not idempotent: %+v %v", d2, err)
	}

	// Concurrent: exactly one of {reference, GC} wins per artifact.
	for i := range 10 {
		c := f.put(t, fmt.Sprintf("race-%d", i), false)
		var refErr, gcErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			refErr = f.life.Reference(ctx, f.scope(t, auth.ArtifactWrite), c.ID, f.origin(artifacts.ReferenceError), f.hours(5))
		}()
		go func() {
			defer wg.Done()
			_, gcErr = f.life.GC(ctx, f.scope(t, auth.ArtifactWrite), c.ID)
		}()
		wg.Wait()
		if (refErr == nil) == (gcErr == nil) {
			t.Fatalf("race %d: reference=%v gc=%v (exactly one may win)", i, refErr, gcErr)
		}
		if refErr == nil && f.latest(t, c) <= model.UnixNano(time.Now().Add(f.durationAhead()).UnixNano()) {
			t.Fatalf("race %d: the winning reference does not retain the map", i)
		}
	}
}

func (f *lifeFx) addProject(t *testing.T, org model.ID) model.ID {
	t.Helper()
	ctx := context.Background()
	actor, err := f.app.Auth.Authenticate(ctx, f.token)
	if err != nil {
		t.Fatal(err)
	}
	project := model.NewID()
	raw, _ := json.Marshal(auth.AdminPayload{ID: project, Name: "other", Reason: "cross scope fixture"})
	var rev model.Revision
	f.app.Control.View(ctx, func(st model.ControlState) error { rev = st.Revision; return nil })
	if _, err = f.app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: "create_project", Payload: raw}); err != nil {
		t.Fatal(err)
	}
	user := f.scope(t, auth.ArtifactRead).PrincipalID()
	if err = f.app.Control.Update(ctx, func(st *model.ControlState) error {
		o := st.Orgs[org.String()]
		o.Members[user.String()] = true
		o.Grants[user.String()+":"+project.String()] = []string{"artifacts.write", "artifacts.read"}
		st.Orgs[org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return project
}
func (f *lifeFx) addOrg(t *testing.T) model.ID {
	t.Helper()
	ctx := context.Background()
	actor, err := f.app.Auth.Authenticate(ctx, f.token)
	if err != nil {
		t.Fatal(err)
	}
	org := model.NewID()
	raw, _ := json.Marshal(auth.AdminPayload{Name: "foreign", Reason: "cross scope fixture"})
	var rev model.Revision
	f.app.Control.View(ctx, func(st model.ControlState) error { rev = st.Revision; return nil })
	if _, err = f.app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: "create_org", Payload: raw}); err != nil {
		t.Fatal(err)
	}
	return org
}
func (f *lifeFx) scopeIn(t *testing.T, org, project model.ID, action auth.Permission) auth.Scope {
	t.Helper()
	actor, err := f.app.Auth.Authenticate(context.Background(), f.token)
	if err != nil {
		t.Fatal(err)
	}
	s, err := f.app.Auth.Authorize(context.Background(), actor, org, []model.ID{project}, action)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// An artifact ID of another project or organization is indistinguishable from
// an absent one on every entry point.
func TestCrossScopeArtifactIDIsIndistinguishableFromAbsent(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	a := f.put(t, "owned", true)
	f.ref(t, a, f.origin(artifacts.ReferenceError), f.hours(5))
	otherProject := f.addProject(t, f.org)
	otherOrg := f.addOrg(t)
	orgProject := f.addProject(t, otherOrg)
	scopes := map[string]func(auth.Permission) auth.Scope{
		"other project": func(p auth.Permission) auth.Scope { return f.scopeIn(t, f.org, otherProject, p) },
		"other org":     func(p auth.Permission) auth.Scope { return f.scopeIn(t, otherOrg, orgProject, p) },
	}
	type call func(read, write auth.Scope, id model.ID) error
	calls := map[string]call{
		"Get":       func(r, _ auth.Scope, id model.ID) error { _, err := f.app.Artifacts.Get(ctx, r, id); return err },
		"GetSource": func(r, _ auth.Scope, id model.ID) error { _, err := f.app.Artifacts.GetSources(ctx, r, id); return err },
		"Read": func(r, _ auth.Scope, id model.ID) error {
			_, err := f.app.Artifacts.ReadAuthorized(ctx, r, id, artifacts.Window{})
			return err
		},
		"ReadSources": func(r, _ auth.Scope, id model.ID) error {
			_, err := f.app.Artifacts.ReadSourcesAuthorized(ctx, r, id, artifacts.Window{})
			return err
		},
		"Reference": func(_, w auth.Scope, id model.ID) error {
			return f.life.Reference(ctx, w, id, f.origin(artifacts.ReferenceProfile), f.hours(3))
		},
		"Unreference": func(_, w auth.Scope, id model.ID) error {
			return f.life.Unreference(ctx, w, id, f.origin(artifacts.ReferenceProfile), 0)
		},
		"GC":        func(_, w auth.Scope, id model.ID) error { _, err := f.life.GC(ctx, w, id); return err },
		"Effective": func(r, _ auth.Scope, id model.ID) error { _, err := f.life.EffectiveRetention(ctx, r, id); return err },
	}
	for sname, mk := range scopes {
		read, write := mk(auth.ArtifactRead), mk(auth.ArtifactWrite)
		for cname, c := range calls {
			foreign, absent := c(read, write, a.ID), c(read, write, model.NewID())
			if foreign == nil || absent == nil || codeOf(foreign) != model.NotFound || foreign.Error() != absent.Error() {
				t.Errorf("%s / %s: foreign=%v absent=%v", sname, cname, foreign, absent)
			}
		}
	}
	// The foreign probes changed nothing for the owner.
	if got := f.latest(t, a); got < f.hours(5)-model.UnixNano(time.Minute) {
		t.Fatalf("foreign probe altered the owner's retention: %d", got)
	}
}

// Advancing only the delete generation stops an open stream before the next
// byte on both the dedicated reader and the common Get path.
func TestDeleteGenerationAdvanceStopsReadMidStream(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	a := f.put(t, "generation", false)
	for name, open := range map[string]func() (io.ReadCloser, error){
		"common Get": func() (io.ReadCloser, error) { return f.app.Artifacts.Get(ctx, f.scope(t, auth.ArtifactRead), a.ID) },
		"ReadAuthorized": func() (io.ReadCloser, error) {
			return f.app.Artifacts.ReadAuthorized(ctx, f.scope(t, auth.ArtifactRead), a.ID, artifacts.Window{})
		},
	} {
		r, err := open()
		if err != nil {
			t.Fatal(name, err)
		}
		if n, err := r.Read(make([]byte, 3)); err != nil || n != 3 {
			t.Fatal(name, n, err)
		}
		f.gens.extra.Add(1) // an unrelated deletion advanced the org generation
		probe := bytes.Repeat([]byte{0x7f}, 8)
		if n, err := r.Read(probe); n != 0 || err == nil || !bytes.Equal(probe, bytes.Repeat([]byte{0x7f}, 8)) {
			t.Fatalf("%s: byte released after the generation advanced: %d %v", name, n, err)
		}
		r.Close()
		// A stream opened at the new generation works.
		r2, err := open()
		if err != nil {
			t.Fatal(name, err)
		}
		if len(readAllClose(t, r2)) == 0 {
			t.Fatal(name, "empty read at the current generation")
		}
	}
}

// Reference state is durable across a restart and fails closed when any part
// of it is tampered with or rolled back to an older, internally valid copy.
func TestTamperedOrRolledBackReferenceStateAfterRestart(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	a := f.put(t, "tamper", false)
	w := f.scope(t, auth.ArtifactWrite)
	f.ref(t, a, f.origin(artifacts.ReferenceError), f.hours(4))
	keyPrefix := "artifact_refs:"
	snapshot := func() (string, json.RawMessage) {
		var key string
		var raw json.RawMessage
		if err := f.app.Control.View(ctx, func(st model.ControlState) error {
			for k, v := range st.Orgs[f.org.String()].Settings {
				if strings.HasPrefix(k, keyPrefix) {
					key, raw = k, append(json.RawMessage(nil), v...)
				}
			}
			return nil
		}); err != nil || key == "" {
			t.Fatalf("no durable ledger: %v", err)
		}
		return key, raw
	}
	key, old := snapshot()
	f.ref(t, a, f.origin(artifacts.ReferenceProfile), f.hours(6))
	_, good := snapshot()

	if err := f.app.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	if f.app, err = appcore.Open(f.dir); err != nil {
		t.Fatal(err)
	}
	f.attach(t, 1<<20)
	if got := f.latest(t, a); got < f.hours(6)-model.UnixNano(time.Minute) {
		t.Fatalf("references lost across restart: %d", got)
	}
	set := func(raw json.RawMessage) {
		t.Helper()
		if err := f.app.Control.Update(ctx, func(st *model.ControlState) error {
			o := st.Orgs[f.org.String()]
			if raw == nil {
				delete(o.Settings, key)
			} else {
				o.Settings[key] = raw
			}
			st.Orgs[f.org.String()] = o
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Shorten the first entry's deadline in the stored text, leaving every other
	// byte (including the stored digest and sequence) untouched.
	text := string(good)
	at := strings.Index(text, `"retain_until_ns":"`) + len(`"retain_until_ns":"`) // decimal-string encoding
	end := at + strings.IndexByte(text[at:], '"')
	shortened := json.RawMessage(text[:at] + "1" + text[end:])
	for name, bad := range map[string]json.RawMessage{
		"rolled back to an older valid ledger": old,
		"entry shortened without its digest":   shortened,
		"ledger removed":                       nil,
		"garbage":                              json.RawMessage(`{"Version":1}`),
	} {
		set(bad)
		if got, err := f.life.LatestReference(ctx, f.candidate(a)); err == nil {
			t.Errorf("%s: LatestReference answered %d from corrupt state", name, got)
		}
		if _, err := f.life.GC(ctx, w, a.ID); err == nil {
			t.Errorf("%s: GC proceeded on corrupt state", name)
		}
		if err := f.life.Reference(ctx, w, a.ID, f.origin(artifacts.ReferenceError), f.hours(7)); err == nil {
			t.Errorf("%s: Reference accepted on corrupt state", name)
		}
		if _, err := f.app.Artifacts.Get(ctx, f.scope(t, auth.ArtifactRead), a.ID); err == nil {
			t.Errorf("%s: read served with corrupt reference state", name)
		}
	}
	set(good)
	if got := f.latest(t, a); got < f.hours(6)-model.UnixNano(time.Minute) {
		t.Fatalf("restored state not honoured: %d", got)
	}
	if _, err = f.app.Artifacts.Get(ctx, f.scope(t, auth.ArtifactRead), a.ID); err != nil {
		t.Fatal(err)
	}
}

// A map larger than several fragments streams through one bounded fragment and
// a bounded cache; windows cross fragment boundaries exactly.
func TestLargeArtifactWindowedReadIsBounded(t *testing.T) {
	const cacheCap = 300 << 10
	f := newLifeFx(t, cacheCap)
	ctx := context.Background()
	var names strings.Builder
	for i := range 60000 {
		if i > 0 {
			names.WriteByte(',')
		}
		fmt.Fprintf(&names, `"name%06d_pad"`, i)
	}
	raw := []byte(`{"version":3,"sources":["a.ts"],"names":[` + names.String() + `],"mappings":"AAAA"}`)
	m := f.manifest(raw)
	m.DebugID, m.Path = "large", "dist/large.js"
	a, err := f.app.Artifacts.Put(ctx, f.scope(t, auth.ArtifactWrite), m, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Map.Fragments) < 3 {
		t.Fatalf("fixture only produced %d fragments", len(a.Map.Fragments))
	}
	read := f.scope(t, auth.ArtifactRead)
	r, err := f.app.Artifacts.ReadAuthorized(ctx, read, a.ID, artifacts.Window{})
	if err != nil {
		t.Fatal(err)
	}
	size := r.Size()
	var full bytes.Buffer
	chunk := make([]byte, 4096)
	for {
		n, rerr := r.Read(chunk)
		full.Write(chunk[:n])
		if s := f.life.CacheStats(); s.Bytes > cacheCap {
			t.Fatalf("cache grew past its bound: %+v", s)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.Fatal(rerr)
		}
	}
	r.Close()
	if uint64(full.Len()) != size || size != uint64(a.Map.Manifest.Size) {
		t.Fatalf("streamed %d bytes, size %d, manifest %d", full.Len(), size, a.Map.Manifest.Size)
	}
	if s := f.life.CacheStats(); s.Bytes > cacheCap || s.Entries == 0 {
		t.Fatalf("cache %+v", s)
	}
	fragment := uint64(model.ArtifactFragmentLimit)
	for _, w := range []artifacts.Window{{Offset: fragment - 7, Length: 20}, {Offset: 2*fragment - 1, Length: fragment + 2}, {Offset: size - 5}, {Offset: 3, Length: 1}} {
		want := full.Bytes()[w.Offset:]
		if w.Length != 0 {
			want = want[:w.Length]
		}
		wr, err := f.app.Artifacts.ReadAuthorized(ctx, read, a.ID, w)
		if err != nil {
			t.Fatal(w, err)
		}
		if got := readAllClose(t, wr); !bytes.Equal(got, want) {
			t.Fatalf("window %+v returned %d bytes, want %d", w, len(got), len(want))
		}
	}
	for _, w := range []artifacts.Window{{Offset: size + 1}, {Offset: size - 1, Length: 2}, {Offset: 1 << 63, Length: 1 << 63}} {
		if _, err := f.app.Artifacts.ReadAuthorized(ctx, read, a.ID, w); codeOf(err) != model.Invalid {
			t.Fatalf("window %+v: %v", w, err)
		}
	}
}

// revokingBlobs releases the real fragment and then lets a revocation land, the
// instant a fetch-time race would be won by the attacker.
type revokingBlobs struct {
	artifacts.BlobStore
	after func()
}

func (r revokingBlobs) ReadBlobFragment(ctx context.Context, scope auth.Scope, rc model.BlobReceipt, ordinal uint32) ([]byte, error) {
	b, err := r.BlobStore.ReadBlobFragment(ctx, scope, rc, ordinal)
	if r.after != nil {
		r.after()
	}
	return b, err
}

// A grant revoked while a fragment is being fetched releases none of it and
// leaves nothing warm for the next caller.
func TestRevocationDuringFragmentFetchReleasesNothing(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	a := f.put(t, "fetch-race", true)
	reader := f.scope(t, auth.ArtifactRead).PrincipalID()
	racing := revokingBlobs{BlobStore: f.app.Storage, after: func() { f.setReaders(t) }}
	svc2, err := artifacts.New(racing, f.app.Control, f.app.Auth)
	if err != nil {
		t.Fatal(err)
	}
	life, err := artifacts.NewLifecycle(svc2, artifacts.LifecycleConfig{State: f.app.Control, Deletes: f.gens, Pins: f.pins, CacheBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	r, err := svc2.ReadSourcesAuthorized(ctx, f.scope(t, auth.ArtifactRead), a.ID, artifacts.Window{})
	if err != nil {
		t.Fatal(err)
	}
	probe := bytes.Repeat([]byte{0x7f}, 16)
	if n, err := r.Read(probe); n != 0 || codeOf(err) != model.NotFound || !bytes.Equal(probe, bytes.Repeat([]byte{0x7f}, 16)) {
		t.Fatalf("bytes released although the grant was revoked during the fetch: n=%d err=%v", n, err)
	}
	if s := life.CacheStats(); s.Entries != 0 || s.Bytes != 0 {
		t.Fatalf("bytes fetched under a revocation were cached: %+v", s)
	}
	f.setReaders(t, reader)
}

// The retention guard honours snapshot pins: a pinned expired map is held (and
// not fenced), unknown pin state vetoes the erasure, and only an unpinned,
// unreferenced map is released.
func TestLatestReferenceHonoursSnapshotPins(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	a := f.put(t, "pins", false)
	f.at(2 * time.Hour)
	f.pins.set(true, nil)
	if got := f.latest(t, a); got <= model.UnixNano(time.Now().Add(f.durationAhead()).UnixNano()) {
		t.Fatalf("a pinned map was released: %d", got)
	}
	if _, err := f.app.Artifacts.Get(ctx, f.scope(t, auth.ArtifactRead), a.ID); err != nil {
		t.Fatalf("a pin hold fenced the map: %v", err)
	}
	f.pins.set(false, model.Fail(model.Unavailable))
	if _, err := f.life.LatestReference(ctx, f.candidate(a)); err == nil {
		t.Fatal("unknown pin state released the map")
	}
	f.pins.set(false, nil)
	if got := f.latest(t, a); got != 0 {
		t.Fatalf("unpinned unreferenced expired map still held: %d", got)
	}
}
