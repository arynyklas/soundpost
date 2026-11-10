// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate_test

import (
	"bytes"
	"context"
	"io"
	"reflect"
	"soundpost/internal/appcore"
	"soundpost/internal/artifacts"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/retention"
	"soundpost/internal/symbolicate"
	"sync"
	"testing"
	"time"
)

const deletionMap = `{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA"}`

// newService is the single construction point the deletion tests use.
func newService(r symbolicate.ArtifactReader, app *appcore.App, c symbolicate.Config) (*symbolicate.Service, error) {
	return symbolicate.New(r, app.Retention, c)
}

// countingReader observes which artifact bytes the service pulls through the
// real protected reader; a warm hit must show no new read, and a denied artifact
// must show none at all.
type countingReader struct {
	*artifacts.Service
	maps, sources int
}

func (r *countingReader) Get(ctx context.Context, s auth.Scope, id model.ID) (io.ReadCloser, error) {
	r.maps++
	return r.Service.Get(ctx, s, id)
}
func (r *countingReader) GetSources(ctx context.Context, s auth.Scope, id model.ID) (io.ReadCloser, error) {
	r.sources++
	return r.Service.GetSources(ctx, s, id)
}

type deletionFx struct {
	*scopedFixture
	reader  *countingReader
	service *symbolicate.Service
	runs    int
	seen    [][]byte // map bytes the worker was handed, one per launch
	art     artifacts.Artifact
	frame   model.Frame
}

func (f *scopedFixture) putPath(t *testing.T, raw []byte, debug, path string, private bool) (artifacts.Artifact, model.Frame) {
	t.Helper()
	generated := []byte("generated " + path)
	m := artifacts.Manifest{Version: 1, Org: f.org, Project: f.project, Source: f.source, Build: f.build, DebugID: debug, GeneratedSHA256: model.HashCanonical(generated), MapSHA256: model.HashCanonical(raw), Path: path, SourceContent: private, Size: model.Uint64(len(raw)), RetainUntil: model.UnixNano(time.Now().Add(time.Hour).UnixNano())}
	r, e := f.app.Artifacts.Put(context.Background(), f.scope(t, auth.ArtifactWrite), m, bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	col := uint32(0)
	return r, model.Frame{Module: "fixture", Function: "original", Artifact: r.ID.String(), Line: 1, Column: &col}
}

func newDeletionFx(t *testing.T, private bool) *deletionFx {
	t.Helper()
	d := &deletionFx{scopedFixture: newScopedFixture(t)}
	d.art, d.frame = d.putPath(t, []byte(deletionMap), "debug-first", "dist/first.mjs", private)
	d.reader = &countingReader{Service: d.app.Artifacts}
	var e error
	if d.service, e = newService(d.reader, d.app, symbolicate.Config{}); e != nil {
		t.Fatal(e)
	}
	d.service.SetFakeWorker(func(_ context.Context, raw []byte, line, col uint32) (symbolicate.Reason, *symbolicate.CodeIdentity) {
		d.runs++
		d.seen = append(d.seen, bytes.Clone(raw))
		return symbolicate.Resolved, &symbolicate.CodeIdentity{Source: "a.ts", Line: line, Column: col}
	})
	return d
}

func (d *deletionFx) resolve(t *testing.T, frame model.Frame, sources bool) symbolicate.SymbolicatedFrame {
	t.Helper()
	return d.resolveWith(t, d.scope(t, auth.ArtifactRead), frame, sources)
}
func (d *deletionFx) resolveWith(t *testing.T, scope auth.Scope, frame model.Frame, sources bool) symbolicate.SymbolicatedFrame {
	t.Helper()
	got, e := d.service.ResolveWithOptions(context.Background(), scope, d.build, []model.Frame{frame}, symbolicate.Options{IncludeSources: sources})
	if e != nil || len(got) != 1 {
		t.Fatalf("resolve: %+v %v", got, e)
	}
	return got[0]
}
func (d *deletionFx) adminScope(t *testing.T) auth.Scope {
	t.Helper()
	actor, e := d.app.Auth.Authenticate(context.Background(), d.token)
	if e != nil {
		t.Fatal(e)
	}
	s, e := d.app.Auth.Authorize(context.Background(), actor, d.org, nil, auth.OrgAdmin)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func (d *deletionFx) revision(t *testing.T) model.Revision {
	t.Helper()
	var r model.Revision
	if e := d.app.Control.View(context.Background(), func(st model.ControlState) error { r = st.Revision; return nil }); e != nil {
		t.Fatal(e)
	}
	return r
}
func (d *deletionFx) del(t *testing.T, mode string, mut func(*retention.DeleteRequest)) retention.DeleteReceipt {
	t.Helper()
	req := retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: d.revision(t), Mode: mode, OrgID: d.org, Reason: "symbolication deletion fixture"}
	mut(&req)
	r, e := d.app.Retention.Delete(context.Background(), d.adminScope(t), req)
	if e != nil {
		t.Fatalf("delete %s: %v", mode, e)
	}
	return r
}
func (d *deletionFx) entity(t *testing.T) retention.DeleteReceipt {
	t.Helper()
	return d.del(t, model.DeleteEntity, func(r *retention.DeleteRequest) {
		r.ProjectIDs, r.EntityIDs = []model.ID{d.project}, []model.ID{d.art.ID}
	})
}
func (d *deletionFx) complete(t *testing.T, id model.ID) retention.DeleteReceipt {
	t.Helper()
	var r retention.DeleteReceipt
	for range 6 {
		if e := d.app.Retention.RunOnce(context.Background()); e != nil {
			t.Fatal(e)
		}
		var e error
		if r, e = d.app.Retention.PollDelete(context.Background(), d.adminScope(t), id); e != nil {
			t.Fatal(e)
		}
		if r.Phase == model.DeletePhaseComplete {
			return r
		}
	}
	t.Fatalf("deletion did not complete: %+v", r)
	return r
}

// denied is the shape of an artifact that is not there at all: same reason, no
// position, no map identity, no source context.
func denied(t *testing.T, label string, got symbolicate.SymbolicatedFrame) {
	t.Helper()
	if got.Reason != symbolicate.Unavailable || got.Resolved != nil || got.SourceContext != nil || got.MapSHA256 != (model.Hash{}) {
		t.Fatalf("%s: deleted artifact still answered: %+v", label, got)
	}
}

func (d *deletionFx) missing(t *testing.T) symbolicate.SymbolicatedFrame {
	t.Helper()
	frame := d.frame
	frame.Artifact = model.NewID().String()
	return d.resolve(t, frame, false)
}

func TestEntityDeletionOfRootEndsWarmCacheSymbolication(t *testing.T) {
	for _, sources := range []bool{false, true} {
		name := "map"
		if sources {
			name = "map and private sources"
		}
		t.Run(name, func(t *testing.T) {
			d := newDeletionFx(t, sources)
			other, otherFrame := d.putPath(t, []byte(`{"version":3,"sources":["b.ts"],"names":[],"mappings":"AAAA"}`), "debug-second", "dist/second.mjs", false)
			warm := d.resolve(t, d.frame, sources)
			if warm.Reason != symbolicate.Resolved || d.runs != 1 || d.reader.maps != 1 {
				t.Fatalf("warm-up: %+v runs=%d maps=%d", warm, d.runs, d.reader.maps)
			}
			if again := d.resolve(t, d.frame, false); again.Reason != symbolicate.Resolved || d.reader.maps != 1 {
				t.Fatalf("second request did not come from the warm cache: %+v maps=%d", again, d.reader.maps)
			}
			runs, maps, privates := d.runs, d.reader.maps, d.reader.sources

			receipt := d.entity(t)
			if receipt.Phase != model.DeletePhaseFencing {
				t.Fatalf("receipt %+v", receipt)
			}
			// Begin alone denies reads: the warm bytes of the deleted root are gone.
			denied(t, "fencing", d.resolve(t, d.frame, false))
			denied(t, "fencing, with sources", d.resolve(t, d.frame, true))
			// Indistinguishable from an artifact that never existed.
			gone, never := d.resolve(t, d.frame, false), d.missing(t)
			gone.Original, never.Original = model.Frame{}, model.Frame{}
			if !reflect.DeepEqual(gone, never) {
				t.Fatalf("deleted root distinguishable from a missing one: %+v vs %+v", gone, never)
			}
			// Another root of the same project is untouched.
			if o := d.resolve(t, otherFrame, false); o.Reason != symbolicate.Resolved {
				t.Fatalf("unrelated artifact %s denied: %+v", other.ID, o)
			}

			d.complete(t, receipt.OperationID)
			denied(t, "complete", d.resolve(t, d.frame, false))
			denied(t, "complete, with sources", d.resolve(t, d.frame, true))
			if o := d.resolve(t, otherFrame, false); o.Reason != symbolicate.Resolved {
				t.Fatalf("unrelated artifact denied after completion: %+v", o)
			}
			// Nothing derived from the deleted root reached the worker or the reader
			// after Begin: the only launches and byte reads since then belong to the
			// other root (one cold read per delete generation it was resolved under).
			deleted := d.seen[0]
			for _, raw := range d.seen[runs:] {
				if bytes.Equal(raw, deleted) {
					t.Fatalf("worker was handed the deleted root's map %q", raw)
				}
			}
			if got := len(d.seen) - runs; got != 2 {
				t.Fatalf("worker launches after Begin: %d, want the 2 of the unrelated root", got)
			}
			if d.reader.sources != privates {
				t.Fatalf("private source bytes of a deleted root were read: %d -> %d", privates, d.reader.sources)
			}
			if got := d.reader.maps - maps; got != 2 {
				t.Fatalf("map reads after Begin: %d, want the 2 cold reads of the unrelated root", got)
			}
		})
	}
}

func TestEntityDeletionLaunchesNoWorkerForDeletedRoot(t *testing.T) {
	d := newDeletionFx(t, false)
	if got := d.resolve(t, d.frame, false); got.Reason != symbolicate.Resolved {
		t.Fatalf("warm-up %+v", got)
	}
	runs := d.runs
	d.complete(t, d.entity(t).OperationID)
	for range 3 {
		denied(t, "after completion", d.resolve(t, d.frame, false))
	}
	if d.runs != runs {
		t.Fatalf("worker launched %d times for a deleted artifact root", d.runs-runs)
	}
}

// A retired project can no longer mint a read scope, so the request-level scope
// minted before the deletion is the one a late caller still holds.
func TestRetireProjectDeletionEndsWarmCacheSymbolication(t *testing.T) {
	d := newDeletionFx(t, false)
	held := d.scope(t, auth.ArtifactRead)
	if got := d.resolveWith(t, held, d.frame, false); got.Reason != symbolicate.Resolved || d.runs != 1 {
		t.Fatalf("warm-up %+v", got)
	}
	receipt := d.del(t, model.DeleteRetireProject, func(r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{d.project} })
	denied(t, "fencing", d.resolveWith(t, held, d.frame, false))
	d.complete(t, receipt.OperationID)
	denied(t, "complete", d.resolveWith(t, held, d.frame, false))
	if d.runs != 1 {
		t.Fatalf("worker launched for a retired project: %d", d.runs)
	}
}

// A signal range never covers an artifact root, so a historical_range deletion
// must not deny symbolication; it still advances the delete generation, so the
// warm bytes may not be reused and are read (and verified) again.
func TestHistoricalRangeDeletionKeepsArtifactsButDropsWarmBytes(t *testing.T) {
	d := newDeletionFx(t, false)
	if got := d.resolve(t, d.frame, false); got.Reason != symbolicate.Resolved || d.reader.maps != 1 {
		t.Fatalf("warm-up %+v maps=%d", got, d.reader.maps)
	}
	receipt := d.del(t, model.DeleteHistoricalRange, func(r *retention.DeleteRequest) {
		r.ProjectIDs, r.Signals, r.Start, r.End = []model.ID{d.project}, []model.Kind{model.Metric}, 0, 1<<62
	})
	for _, phase := range []string{"fencing", "complete"} {
		if phase == "complete" {
			d.complete(t, receipt.OperationID)
		}
		got := d.resolve(t, d.frame, false)
		if got.Reason != symbolicate.Resolved || got.Resolved == nil {
			t.Fatalf("range deletion denied an artifact it does not cover (%s): %+v", phase, got)
		}
	}
	if d.reader.maps < 2 {
		t.Fatalf("warm bytes survived a delete-generation change: maps=%d", d.reader.maps)
	}
}

// Any path that erases readable bytes advances the generation without leaving a
// predicate (retention expiry, artifact GC, erasure after a hold release). Warm
// bytes bound to the older generation must die with it.
func TestWarmCacheIsBoundToTheDeleteGeneration(t *testing.T) {
	d := newDeletionFx(t, false)
	if got := d.resolve(t, d.frame, false); got.Reason != symbolicate.Resolved || d.reader.maps != 1 {
		t.Fatalf("warm-up %+v maps=%d", got, d.reader.maps)
	}
	if got := d.resolve(t, d.frame, false); got.Reason != symbolicate.Resolved || d.reader.maps != 1 {
		t.Fatalf("no warm hit before the generation moved: maps=%d", d.reader.maps)
	}
	if _, e := d.app.Control.AdvanceDeleteGeneration(context.Background(), d.org); e != nil {
		t.Fatal(e)
	}
	if got := d.resolve(t, d.frame, false); got.Reason != symbolicate.Resolved || d.reader.maps != 2 {
		t.Fatalf("warm bytes of an older delete generation were reused: %+v maps=%d", got, d.reader.maps)
	}
}

func TestHeldDeletionSuppressesNothingUntilItBegins(t *testing.T) {
	d := newDeletionFx(t, false)
	if got := d.resolve(t, d.frame, false); got.Reason != symbolicate.Resolved {
		t.Fatalf("warm-up %+v", got)
	}
	hold, e := d.app.Retention.PlaceHold(context.Background(), d.adminScope(t), retention.HoldRequest{CommandID: model.NewID(), ExpectedRevision: d.revision(t), ProjectIDs: []model.ID{d.project}, EntityIDs: []model.ID{d.art.ID}, Reason: "legal hold fixture"})
	if e != nil {
		t.Fatal(e)
	}
	receipt := d.entity(t)
	if receipt.Phase != model.DeletePhaseHeld {
		t.Fatalf("hold did not block Begin: %+v", receipt)
	}
	if got := d.resolve(t, d.frame, false); got.Reason != symbolicate.Resolved {
		t.Fatalf("a deletion that has not begun denied reads: %+v", got)
	}
	if e = d.app.Retention.ReleaseHold(context.Background(), d.adminScope(t), model.NewID(), d.revision(t), hold, "settled"); e != nil {
		t.Fatal(e)
	}
	if got := d.resolve(t, d.frame, false); got.Reason != symbolicate.Resolved {
		t.Fatalf("releasing a hold must not start the deletion: %+v", got)
	}
	if r, e := d.app.Retention.Resume(context.Background(), d.adminScope(t), receipt.OperationID); e != nil || r.Phase != model.DeletePhaseFencing {
		t.Fatalf("resume: %+v %v", r, e)
	}
	denied(t, "resumed", d.resolve(t, d.frame, false))
}

// A hold placed after Begin keeps the bytes physically present; it never
// restores a read. The stored bytes stay intact and the warm entry stays in
// memory, so only the deletion predicate stands between them and the worker.
func TestHoldPlacedAfterBeginKeepsReadsSuppressed(t *testing.T) {
	d := newDeletionFx(t, false)
	if got := d.resolve(t, d.frame, false); got.Reason != symbolicate.Resolved {
		t.Fatalf("warm-up %+v", got)
	}
	runs := d.runs
	receipt := d.entity(t)
	if receipt.Phase != model.DeletePhaseFencing {
		t.Fatalf("receipt %+v", receipt)
	}
	hold, e := d.app.Retention.PlaceHold(context.Background(), d.adminScope(t), retention.HoldRequest{CommandID: model.NewID(), ExpectedRevision: d.revision(t), ProjectIDs: []model.ID{d.project}, EntityIDs: []model.ID{d.art.ID}, Reason: "legal hold after begin"})
	if e != nil {
		t.Fatal(e)
	}
	if r := d.complete(t, receipt.OperationID); r.Physical != retention.PhysicalHeld {
		t.Fatalf("hold did not keep the bytes physically present: %+v", r)
	}
	denied(t, "held after completion", d.resolve(t, d.frame, false))
	if e = d.app.Retention.ReleaseHold(context.Background(), d.adminScope(t), model.NewID(), d.revision(t), hold, "settled"); e != nil {
		t.Fatal(e)
	}
	if err := d.app.Retention.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r, e := d.app.Retention.PollDelete(context.Background(), d.adminScope(t), receipt.OperationID); e != nil || r.Physical != retention.PhysicalDone {
		t.Fatalf("erasure after the hold release: %+v %v", r, e)
	}
	denied(t, "hold released, erased", d.resolve(t, d.frame, false))
	if d.runs != runs {
		t.Fatalf("worker launched %d times for a deleted artifact root", d.runs-runs)
	}
}

// A deletion that begins while the worker runs must not be released: the
// result was derived from bytes read before Begin.
func TestDeletionBegunDuringWorkerRunIsFencedAtRelease(t *testing.T) {
	d := newDeletionFx(t, false)
	reader := &revokeBeforeRelease{Service: d.app.Artifacts, revoke: func() error { d.entity(t); return nil }}
	service, e := newService(reader, d.app, symbolicate.Config{})
	if e != nil {
		t.Fatal(e)
	}
	runs := 0
	service.SetFakeWorker(func(_ context.Context, _ []byte, line, col uint32) (symbolicate.Reason, *symbolicate.CodeIdentity) {
		runs++
		return symbolicate.Resolved, &symbolicate.CodeIdentity{Source: "a.ts", Line: line, Column: col}
	})
	got, e := service.Resolve(context.Background(), d.scope(t, auth.ArtifactRead), d.build, []model.Frame{d.frame})
	if e != nil || len(got) != 1 || runs != 1 {
		t.Fatalf("resolve: %+v %v runs=%d", got, e, runs)
	}
	denied(t, "begun during the run", got[0])
}

// notFoundRead authorizes the reference and then answers the byte read as an
// absent artifact, which is what a deletion committing between the two does.
type notFoundRead struct{ *artifacts.Service }

func (notFoundRead) Get(context.Context, auth.Scope, model.ID) (io.ReadCloser, error) {
	return nil, model.Fail(model.NotFound)
}

// An absent or denied artifact is one answer. Reporting artifact_corrupt for a
// NotFound read would tell the caller the root exists and was just removed.
func TestNotFoundByteReadIsIndistinguishableFromMissingArtifact(t *testing.T) {
	d := newDeletionFx(t, false)
	service, e := newService(notFoundRead{d.app.Artifacts}, d.app, symbolicate.Config{})
	if e != nil {
		t.Fatal(e)
	}
	service.SetFakeWorker(func(context.Context, []byte, uint32, uint32) (symbolicate.Reason, *symbolicate.CodeIdentity) {
		t.Fatal("worker launched without bytes")
		return "", nil
	})
	got, e := service.Resolve(context.Background(), d.scope(t, auth.ArtifactRead), d.build, []model.Frame{d.frame})
	if e != nil || len(got) != 1 {
		t.Fatalf("resolve: %+v %v", got, e)
	}
	denied(t, "not found read", got[0])
}

type failingGenerations struct{}

func (failingGenerations) DeleteGeneration(context.Context, model.ID, []model.ID) (uint64, error) {
	return 0, model.Fail(model.Unavailable)
}

// Without a delete generation the cache cannot be bound, so nothing is served:
// the answer is the same as for an absent artifact and no byte is read.
func TestUnanswerableDeleteGenerationFailsClosed(t *testing.T) {
	d := newDeletionFx(t, false)
	if _, e := symbolicate.New(d.reader, nil, symbolicate.Config{}); e == nil {
		t.Fatal("a service without a delete-generation authority was built")
	}
	service, e := symbolicate.New(d.reader, failingGenerations{}, symbolicate.Config{})
	if e != nil {
		t.Fatal(e)
	}
	service.SetFakeWorker(func(context.Context, []byte, uint32, uint32) (symbolicate.Reason, *symbolicate.CodeIdentity) {
		t.Fatal("worker launched without a delete generation")
		return "", nil
	})
	got, e := service.Resolve(context.Background(), d.scope(t, auth.ArtifactRead), d.build, []model.Frame{d.frame})
	if e != nil || len(got) != 1 {
		t.Fatalf("resolve: %+v %v", got, e)
	}
	denied(t, "no generation", got[0])
	if d.reader.maps != 0 || d.reader.sources != 0 {
		t.Fatalf("bytes read without a delete generation: maps=%d sources=%d", d.reader.maps, d.reader.sources)
	}
}

// Unreachable is not enough: bytes read under an older generation may derive
// from data a deletion just removed and must leave memory on the next request.
func TestBytesOfOlderDeleteGenerationAreDroppedNotJustUnreachable(t *testing.T) {
	d := newDeletionFx(t, false)
	_, otherFrame := d.putPath(t, []byte(deletionMap), "debug-second", "dist/second.mjs", false)
	if got := d.resolve(t, d.frame, false); got.Reason != symbolicate.Resolved || d.service.CachedEntries() != 1 {
		t.Fatalf("warm-up %+v entries=%d", got, d.service.CachedEntries())
	}
	if _, e := d.app.Control.AdvanceDeleteGeneration(context.Background(), d.org); e != nil {
		t.Fatal(e)
	}
	if got := d.resolve(t, otherFrame, false); got.Reason != symbolicate.Resolved || d.service.CachedEntries() != 1 {
		t.Fatalf("older-generation bytes linger: %+v entries=%d", got, d.service.CachedEntries())
	}
}

// gatedReader parks chosen calls so a test can interleave two requests exactly.
type gatedReader struct {
	*countingReader
	mu             sync.Mutex
	lookups, reads int
	onLookup       func(n int)
	onGet          func(n int)
}

func (r *gatedReader) Lookup(ctx context.Context, s auth.Scope, id model.ID) (artifacts.Artifact, error) {
	r.mu.Lock()
	r.lookups++
	n, hook := r.lookups, r.onLookup
	r.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	return r.Service.Lookup(ctx, s, id)
}
func (r *gatedReader) Get(ctx context.Context, s auth.Scope, id model.ID) (io.ReadCloser, error) {
	r.mu.Lock()
	r.reads++
	n, hook := r.reads, r.onGet
	r.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	return r.countingReader.Get(ctx, s, id)
}

// A request that sampled an older generation and is still reading when the
// generation advances files its bytes late, after a newer request already
// purged the older entries. Those bytes must not be reachable by the newer
// generation: the key, not only the purge, binds them.
func TestInFlightReadOfOlderGenerationCannotPoisonTheNewerOne(t *testing.T) {
	d := newDeletionFx(t, false)
	reader := &gatedReader{countingReader: d.reader}
	service, e := newService(reader, d.app, symbolicate.Config{})
	if e != nil {
		t.Fatal(e)
	}
	service.SetFakeWorker(func(context.Context, []byte, uint32, uint32) (symbolicate.Reason, *symbolicate.CodeIdentity) {
		return symbolicate.Resolved, &symbolicate.CodeIdentity{Source: "a.ts", Line: 1}
	})
	inGet, releaseGet := make(chan struct{}), make(chan struct{})
	reader.onGet = func(n int) {
		if n == 1 {
			close(inGet)
			<-releaseGet
		}
	}
	inLookup, releaseLookup := make(chan struct{}), make(chan struct{})
	reader.onLookup = func(n int) {
		if n == 2 { // the second request, after it sampled its generation and purged
			close(inLookup)
			<-releaseLookup
		}
	}
	scope := d.scope(t, auth.ArtifactRead)
	resolve := func() <-chan symbolicate.SymbolicatedFrame {
		out := make(chan symbolicate.SymbolicatedFrame, 1)
		go func() {
			got, e := service.Resolve(context.Background(), scope, d.build, []model.Frame{d.frame})
			if e != nil || len(got) != 1 {
				out <- symbolicate.SymbolicatedFrame{}
				return
			}
			out <- got[0]
		}()
		return out
	}
	first := resolve()
	<-inGet // request 1 sampled generation g and is reading g's bytes
	if _, e = d.app.Control.AdvanceDeleteGeneration(context.Background(), d.org); e != nil {
		t.Fatal(e)
	}
	second := resolve()
	<-inLookup // request 2 sampled g+1 and purged; its cache lookup is still ahead
	close(releaseGet)
	if got := <-first; got.Reason != symbolicate.Resolved {
		t.Fatalf("first request: %+v", got)
	}
	close(releaseLookup)
	if got := <-second; got.Reason != symbolicate.Resolved {
		t.Fatalf("second request: %+v", got)
	}
	if d.reader.maps != 2 {
		t.Fatalf("a request of the newer generation was served bytes read under the older one: map reads=%d, want 2", d.reader.maps)
	}
}
