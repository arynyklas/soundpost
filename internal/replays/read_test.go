// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replays

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
	"github.com/arynyklas/soundpost/internal/storage"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func next(t *testing.T, s ReplayStream) Event {
	t.Helper()
	ev, err := s.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	return ev
}

func TestReplayGrantRevokedBetweenChunks(t *testing.T) {
	f := newFx(t)
	scope, revoke := f.reader(f.main, f.main.project)
	r := newRecorder(f.wall())
	c := r.chain(2 * ReadBatch) // more than one buffered batch
	f.mustAdmit(f.main, c...)
	s, err := f.svc.Read(f.ctx, scope, r.replay, ReplayWindow{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if ev := next(t, s); ev.Kind == EventRevoke || ev.Chunk == nil || ev.Sequence != uint64(i) {
			t.Fatalf("event %d: %+v", i, ev)
		}
	}
	st := s.(*stream)
	if len(st.buf) == 0 {
		t.Fatal("test premise: later chunks should already be buffered")
	}
	revoke()
	scansBefore := f.scan.scans.Load()
	ev := next(t, s)
	if ev.Kind != EventRevoke || ev.Chunk != nil || ev.Reason != ReasonAuthorityRevoked || ev.Sequence != 4 {
		t.Fatalf("after revocation: %+v", ev)
	}
	if st.buf != nil {
		t.Fatal("buffered chunk bodies survived the revocation")
	}
	if _, err = s.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("stream continued after Revoke: %v", err)
	}
	if f.scan.scans.Load() != scansBefore {
		t.Fatal("the store was read again after the revocation")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Next(context.Background()); err == nil {
		t.Fatal("closed stream released an event")
	}
	// A grant revoked before the first chunk releases nothing at all.
	s2scope, revoke2 := f.reader(f.main, f.main.project)
	s2, err := f.svc.Read(f.ctx, s2scope, r.replay, ReplayWindow{})
	if err != nil {
		t.Fatal(err)
	}
	revoke2()
	if ev = next(t, s2); ev.Kind != EventRevoke || ev.Chunk != nil {
		t.Fatalf("first event after revocation: %+v", ev)
	}
	s2.Close()
	// And a reader whose grant is already gone cannot open a stream.
	if _, err = f.svc.Read(f.ctx, s2scope, r.replay, ReplayWindow{}); code(err) != model.NotFound {
		t.Fatalf("revoked scope opened: %v", err)
	}
}

// flaky lets a test make the authority itself unreachable.
type flaky struct {
	ScopeAuthorizer
	down atomic.Bool
}

func (a *flaky) Revalidate(ctx context.Context, s auth.Scope) error {
	if a.down.Load() {
		return model.Fail(model.Unavailable)
	}
	return a.ScopeAuthorizer.Revalidate(ctx, s)
}

func TestReplayUnreachableAuthorityIsAnErrorNotARevocationAndReleasesNothing(t *testing.T) {
	f := newFx(t)
	a := &flaky{ScopeAuthorizer: f.auth}
	f.svc.authorizer = a
	scope, _ := f.reader(f.main, f.main.project)
	r := newRecorder(f.wall())
	f.mustAdmit(f.main, r.chain(3)...)
	s, err := f.svc.Read(f.ctx, scope, r.replay, ReplayWindow{})
	if err != nil {
		t.Fatal(err)
	}
	next(t, s)
	a.down.Store(true)
	ev := next(t, s)
	if ev.Kind != EventError || ev.Code != model.Unavailable || ev.Chunk != nil {
		t.Fatalf("%+v", ev)
	}
	if _, err = s.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatal("stream continued after an Error event")
	}
	if _, err = f.svc.Read(f.ctx, scope, r.replay, ReplayWindow{}); code(err) != model.Unavailable {
		t.Fatalf("open with unreachable authority: %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	a.down.Store(false)
	s, _ = f.svc.Read(f.ctx, scope, r.replay, ReplayWindow{})
	cancel()
	if ev, err := s.Next(cancelled); err != nil || ev.Kind != EventError || ev.Code != model.Cancelled {
		t.Fatalf("cancelled: %+v %v", ev, err)
	}
}

// A denied reader cannot tell a recording of someone else from a missing one.
func TestReplayDeniedReaderCannotDistinguishForeignFromMissing(t *testing.T) {
	f := newFx(t)
	foreignOrg := f.addTenant(model.NewID())
	otherProject := model.NewID()
	f.admin(f.main.org, "create_project", auth.AdminPayload{ID: otherProject, Name: "p2"})
	r := newRecorder(f.wall())
	f.mustAdmit(f.main, r.chain(2)...)
	rf := newRecorder(f.wall())
	f.mustAdmit(foreignOrg, rf.chain(2)...)
	readerCred, _ := f.readerCred(f.main, f.main.project)
	noGrantCred, _ := f.readerCred(f.main, otherProject)
	wrongKindCred, _ := f.readerCred(foreignOrg, foreignOrg.project)
	reader := f.scopeOf(f.main, readerCred, f.main.project)
	noGrant := f.scopeOf(f.main, noGrantCred, otherProject)
	wrongKind := f.scopeOf(foreignOrg, wrongKindCred, foreignOrg.project)

	missing, err := f.svc.Read(f.ctx, reader, model.NewID(), ReplayWindow{})
	if err == nil || missing != nil {
		t.Fatal("missing replay opened")
	}
	want := err.(*model.Fault)
	for name, tc := range map[string]struct {
		scope auth.Scope
		id    model.ID
	}{
		"other organization":                  {wrongKind, r.replay},
		"project not granted":                 {noGrant, r.replay},
		"foreign org recording from this org": {reader, rf.replay},
		"zero id":                             {reader, model.ID{}},
	} {
		s, err := f.svc.Read(f.ctx, tc.scope, tc.id, ReplayWindow{})
		var fault *model.Fault
		if s != nil || !errors.As(err, &fault) || fault.Code != want.Code || fault.SafeDetail != want.SafeDetail || fault.Retryable != want.Retryable {
			t.Errorf("%s: %v is distinguishable from %v", name, err, want)
		}
	}
	// A reader without the read permission (an elevated raw reader is not a replay reader) is the same.
	raw := reader
	if s, err := f.svc.Read(f.ctx, raw, r.replay, ReplayWindow{}); s == nil || err != nil {
		t.Fatalf("authorized read failed: %v", err)
	}
}

func TestReplaySameIDInTwoProjectsIsAmbiguousNotMerged(t *testing.T) {
	f := newFx(t)
	second := model.NewID()
	f.admin(f.main.org, "create_project", auth.AdminPayload{ID: second, Name: "p2"})
	scope, _ := f.reader(f.main, f.main.project, second)
	r := newRecorder(f.wall())
	c := r.chain(1)
	f.mustAdmit(f.main, c...)
	if got, _ := f.read(scope, r.replay, ReplayWindow{}); got != "C1 D2" {
		t.Fatalf("baseline %q", got)
	}
	f.scan.extra = []extraRow{{project: second, chunk: c[1]}}
	if _, err := f.svc.Read(f.ctx, scope, r.replay, ReplayWindow{}); code(err) != model.NotFound {
		t.Fatalf("replay ID claimed by a second project: %v", err)
	}
	// A foreign session claiming the same replay root cannot extend it either.
	f.scan.extra = nil
	// The next chunk of the real chain, but claimed by another session: only the root's
	// session binding keeps it out, since its hash chain is otherwise perfect.
	forged := r.delta()
	forged.Session = model.NewID()
	f.scan.extra = []extraRow{{project: f.main.project, chunk: forged}}
	scope1, _ := f.reader(f.main, f.main.project)
	if got, evs := f.read(scope1, r.replay, ReplayWindow{}); got != "C1 D2 G3-3" || evs[2].Reason != ReasonConflictingChunk {
		t.Fatalf("foreign-session chunk past the end: %q", got)
	}
	// And at an occupied sequence it cannot replace the real chunk either.
	occupied := c[1]
	occupied.Session = forged.Session
	f.scan.extra = []extraRow{{project: f.main.project, chunk: occupied}}
	if got, _ := f.read(scope1, r.replay, ReplayWindow{}); got != "C1 G2-2" {
		t.Fatalf("foreign-session chunk at an occupied sequence: %q", got)
	}
}

func TestReplayDeletedRootIsGoneAndStaysGone(t *testing.T) {
	f := newFx(t)
	scope, _ := f.reader(f.main, f.main.project)
	r := newRecorder(f.wall())
	c := r.chain(2 * ReadBatch)
	f.mustAdmit(f.main, c...)
	s, err := f.svc.Read(f.ctx, scope, r.replay, ReplayWindow{})
	if err != nil {
		t.Fatal(err)
	}
	next(t, s)
	next(t, s)
	admin, err := f.auth.Authorize(f.ctx, f.cred, f.main.org, nil, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.ret.Delete(f.ctx, admin, retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: f.revision(), Mode: model.DeleteEntity, OrgID: f.main.org, ProjectIDs: []model.ID{f.main.project}, EntityIDs: []model.ID{r.replay}, Reason: "root deletion"}); err != nil {
		t.Fatal(err)
	}
	// The open stream ends with a typed revoke before any further chunk, buffered or not.
	if ev := next(t, s); ev.Kind != EventRevoke || ev.Reason != ReasonDeleted || ev.Chunk != nil {
		t.Fatalf("stream after deletion: %+v", ev)
	}
	s.Close()
	// A new reader sees exactly what a never-recorded replay looks like.
	_, missing := f.svc.Read(f.ctx, scope, model.NewID(), ReplayWindow{})
	_, deleted := f.svc.Read(f.ctx, scope, r.replay, ReplayWindow{})
	if code(deleted) != model.NotFound || deleted.(*model.Fault).SafeDetail != missing.(*model.Fault).SafeDetail {
		t.Fatalf("deleted root: %v", deleted)
	}
	// Late chunks of the deleted root are refused at admission and the group answers zero.
	if err = f.rawAppend(f.main, r.delta(), false); err == nil {
		t.Fatal("late chunk of a deleted root was admitted")
	}
	rec := c[0]
	until, err := f.svc.LatestReference(f.ctx, storage.EraseCandidate{Org: f.main.org, Project: f.main.project, Kind: model.Replay, Record: &model.Record{Kind: model.Replay, Payload: model.Payload{Replay: &rec}}})
	if err != nil || until != 0 {
		t.Fatalf("a chunk under deletion is still referenced: %v %v", until, err)
	}
	if err = f.ret.RunOnce(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.storedRows(f.main); n != 0 {
		t.Fatalf("%d chunks of the deleted root remain stored", n)
	}
}

func TestReplayTamperedStoredIndexFailsClosed(t *testing.T) {
	setup := func(t *testing.T) (*fx, auth.Scope, *recorder) {
		f := newFx(t)
		scope, _ := f.reader(f.main, f.main.project)
		r := newRecorder(f.wall())
		c := r.chain(2)
		c = append(c, r.cp(), r.delta())
		f.mustAdmit(f.main, c...)
		if got, _ := f.read(scope, r.replay, ReplayWindow{}); got != "C1 D2 D3 C4 D5" {
			t.Fatalf("baseline %q", got)
		}
		return f, scope, r
	}
	mutate := func(f *fx, r *recorder, edit func(map[string]json.RawMessage, map[string]json.RawMessage)) {
		t := f.t
		err := f.store.Update(f.ctx, func(st *model.ControlState) error {
			o := st.Orgs[f.main.org.String()]
			var pins map[string]json.RawMessage
			if err := json.Unmarshal(o.Settings[pinKey(f.main.project)], &pins); err != nil {
				return err
			}
			edit(o.Settings, pins)
			raw, _ := json.Marshal(pins)
			o.Settings[pinKey(f.main.project)] = raw
			st.Orgs[f.main.org.String()] = o
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	key := func(f *fx, r *recorder) string { return groupKey(f.main.project, r.replay) }
	t.Run("an edited checkpoint entry", func(t *testing.T) {
		f, scope, r := setup(t)
		mutate(f, r, func(s, _ map[string]json.RawMessage) {
			var g group
			_ = json.Unmarshal(s[key(f, r)], &g)
			g.Checkpoints[0].Hash[0] ^= 1 // not re-sealed
			s[key(f, r)], _ = json.Marshal(g)
		})
		if _, err := f.svc.Read(f.ctx, scope, r.replay, ReplayWindow{}); code(err) != model.Corrupt {
			t.Fatalf("%v", err)
		}
	})
	t.Run("an edited and re-sealed index no longer matches its pin", func(t *testing.T) {
		f, scope, r := setup(t)
		mutate(f, r, func(s, _ map[string]json.RawMessage) {
			var g group
			_ = json.Unmarshal(s[key(f, r)], &g)
			g.Checkpoints = g.Checkpoints[:1] // forget the second checkpoint
			g.Head = g.digest()
			s[key(f, r)], _ = json.Marshal(g)
		})
		if _, err := f.svc.Read(f.ctx, scope, r.replay, ReplayWindow{}); code(err) != model.Corrupt {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a rolled-back index", func(t *testing.T) {
		f, scope, r := setup(t)
		var old json.RawMessage
		_ = f.store.View(f.ctx, func(st control.State) error { old = st.Orgs[f.main.org.String()].Settings[key(f, r)]; return nil })
		f.mustAdmit(f.main, func() model.ReplayChunk { c := r.cp(); return c }())
		mutate(f, r, func(s, _ map[string]json.RawMessage) { s[key(f, r)] = old })
		if _, err := f.svc.Read(f.ctx, scope, r.replay, ReplayWindow{}); code(err) != model.Corrupt {
			t.Fatalf("%v", err)
		}
	})
	t.Run("an index removed while its pin stays", func(t *testing.T) {
		f, scope, r := setup(t)
		mutate(f, r, func(s, _ map[string]json.RawMessage) { delete(s, key(f, r)) })
		if _, err := f.svc.Read(f.ctx, scope, r.replay, ReplayWindow{}); code(err) != model.Corrupt {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a pin that does not parse stops the retention guard", func(t *testing.T) {
		f, _, r := setup(t)
		_ = f.store.Update(f.ctx, func(st *model.ControlState) error {
			o := st.Orgs[f.main.org.String()]
			o.Settings[pinKey(f.main.project)] = json.RawMessage(`[1]`)
			st.Orgs[f.main.org.String()] = o
			return nil
		})
		rec := newRecorder(f.wall()).cp()
		_, err := f.svc.LatestReference(f.ctx, storage.EraseCandidate{Org: f.main.org, Project: f.main.project, Kind: model.Replay, Record: &model.Record{Kind: model.Replay, Payload: model.Payload{Replay: &rec}}})
		if code(err) != model.Corrupt {
			t.Fatalf("%v", err)
		}
		_ = r
	})
	t.Run("a forged checkpoint beside the real one loses to the pinned hash", func(t *testing.T) {
		f, scope, r := setup(t)
		forged := newRecorder(f.wall())
		forged.replay, forged.session = r.replay, r.session
		forged.base += 5_000
		fc := forged.cp() // sequence 1 with different content and wall time
		fc.Events = []model.MaskedEvent{{At: 1, Kind: "pointer", Node: 1, X: 123, Y: 123}}
		f.scan.extra = []extraRow{{project: f.main.project, chunk: fc}}
		if got, _ := f.read(scope, r.replay, ReplayWindow{}); got != "C1 D2 D3 C4 D5" {
			t.Fatalf("forged competitor changed the stream: %q", got)
		}
		_, evs := f.read(scope, r.replay, ReplayWindow{})
		if evs[0].Chunk.Events[0].X == 123 {
			t.Fatal("the forged checkpoint body was released")
		}
		// Only the forgery remains in storage: the index refuses it.
		f.scan.extra = nil
		f.scan.drop = func(c *model.ReplayChunk) bool { return c.Sequence == 1 }
		f.scan.extra = []extraRow{{project: f.main.project, chunk: fc}}
		got, evs := f.read(scope, r.replay, ReplayWindow{})
		if want := "G1-3 C4 D5"; got != want || evs[0].Reason != ReasonIndexMismatch {
			t.Fatalf("%q", got)
		}
	})
	t.Run("a stored chunk altered after planning is never released", func(t *testing.T) {
		f, scope, r := setup(t)
		s, err := f.svc.Read(f.ctx, scope, r.replay, ReplayWindow{})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		f.scan.edit = func(c *model.ReplayChunk) {
			if c.Sequence == 3 {
				c.Events = []model.MaskedEvent{{At: 1, Kind: "pointer", Node: 1, X: 5, Y: 5}}
			}
		}
		next(t, s)
		next(t, s)
		ev := next(t, s)
		if ev.Kind != EventError || ev.Code != model.Corrupt || ev.Chunk != nil {
			t.Fatalf("%+v", ev)
		}
	})
}

func TestReplayConcurrentChunkArrivalConvergesToTheSameChain(t *testing.T) {
	f := newFx(t)
	scope, _ := f.reader(f.main, f.main.project)
	r := newRecorder(f.wall())
	var all []model.ReplayChunk
	for i := 0; i < 3; i++ {
		all = append(all, r.chain(9)...) // 3 checkpoints, 27 deltas
	}
	var wg sync.WaitGroup
	var failures atomic.Int64
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := len(all) - 1 - w; i >= 0; i -= 6 { // newest first: maximal disorder
				if err := f.admit(f.main, all[i]); err != nil {
					failures.Add(1)
				}
			}
		}(w)
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d concurrent admissions failed", failures.Load())
	}
	got, evs := f.read(scope, r.replay, ReplayWindow{})
	if len(evs) != len(all) {
		t.Fatalf("released %d events for %d chunks: %q", len(evs), len(all), got)
	}
	for i, ev := range evs {
		if ev.Sequence != uint64(i+1) || (ev.Kind == EventCheckpoint) != (i%10 == 0) {
			t.Fatalf("event %d: %s %d", i, ev.Kind, ev.Sequence)
		}
	}
	var checkpoints int
	_ = f.store.View(f.ctx, func(st control.State) error {
		var g group
		_ = json.Unmarshal(st.Orgs[f.main.org.String()].Settings[groupKey(f.main.project, r.replay)], &g)
		checkpoints = len(g.Checkpoints)
		return nil
	})
	if checkpoints != 3 {
		t.Fatalf("index holds %d checkpoints", checkpoints)
	}
}

// genScanner serves a huge replay without holding it: rows are produced page
// by page and honour the time bounds the reader asks for.
type genScanner struct {
	chunks []model.ReplayChunk // template ring, indexed by sequence-1
	extra  []model.ReplayChunk
	rows   atomic.Int64
}

func (g *genScanner) Scan(_ context.Context, _ auth.Scope, req storage.ScanRequest) (storage.RowIterator, error) {
	return &genRows{g: g, start: req.Start, end: req.End}, nil
}

type genRows struct {
	g          *genScanner
	start, end model.UnixNano
	i          int
}

func (r *genRows) Next(context.Context) (storage.Page, error) {
	var p storage.Page
	total := len(r.g.chunks) + len(r.g.extra)
	for r.i < total && p.Len() < 256 {
		var c model.ReplayChunk
		if r.i < len(r.g.chunks) {
			c = r.g.chunks[r.i]
		} else {
			c = r.g.extra[r.i-len(r.g.chunks)]
		}
		r.i++
		// The engine's time index never reads rows outside the bounds.
		if c.Clock.Wall < r.start || c.Clock.Wall >= r.end {
			continue
		}
		r.g.rows.Add(1)
		cc := c
		p.IDs = append(p.IDs, model.ID{})
		p.Projects = append(p.Projects, projectOfGen)
		p.Values = append(p.Values, model.Payload{Replay: &cc})
	}
	if p.Len() == 0 && r.i >= total {
		return p, io.EOF
	}
	return p, nil
}
func (r *genRows) Watermarks() []model.Cursor { return nil }
func (r *genRows) Close() error               { return nil }

var projectOfGen = model.NewID()

// A replay of the maximum chunk count, stray rows with absurd sequence numbers
// and floods of duplicates neither grow memory with the claimed numbers nor
// make the reader buffer more than a few bodies.
func TestReplayHugeChunkCountsAreBounded(t *testing.T) {
	f := newFx(t)
	scope, _ := f.reader(f.main, f.main.project)
	r := newRecorder(f.wall())
	gen := &genScanner{}
	for i := 0; i < MaxSequence; i++ {
		gen.chunks = append(gen.chunks, r.next(i%64 == 0))
	}
	// Absurd sequences, replays of other IDs, and 4 000 duplicates of one sequence.
	far := gen.chunks[10]
	far.Sequence = 1 << 62
	gen.extra = append(gen.extra, far)
	far.Sequence = MaxSequence + 1
	gen.extra = append(gen.extra, far)
	for i := 0; i < 4000; i++ {
		dup := gen.chunks[500]
		dup.Loss = model.Uint64(i + 1)
		gen.extra = append(gen.extra, dup)
	}
	f.svc.scanner = gen
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	s, err := f.svc.Read(f.ctx, scope, r.replay, ReplayWindow{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	st := s.(*stream)
	if len(st.steps) > MaxSequence {
		t.Fatalf("%d planned steps for a %d-chunk replay", len(st.steps), MaxSequence)
	}
	// Sequence 501 was claimed by 4 000 different chunks: only that sequence is a conflict.
	runtime.ReadMemStats(&after)
	if grew := after.HeapAlloc - before.HeapAlloc; int64(grew) > 96<<20 {
		t.Fatalf("planning a maximum replay grew the heap by %d MiB", grew>>20)
	}
	maxBuffered, events := 0, 0
	for events < 3000 {
		ev, err := s.Next(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		events++
		if ev.Kind == EventError {
			t.Fatalf("%+v", ev)
		}
		maxBuffered = max(maxBuffered, len(st.buf))
	}
	if maxBuffered > ReadBatch {
		t.Fatalf("buffered %d chunk bodies, bound is %d", maxBuffered, ReadBatch)
	}
	// Streaming 3 000 chunks did not rescan the whole replay for every batch.
	if rows := gen.rows.Load(); rows > int64(len(gen.chunks)+len(gen.extra))+3000*2+4000 {
		t.Fatalf("%d rows read to stream 3000 chunks", rows)
	}
}

// The group deadline is the latest chunk deadline: a replay lives and dies with its root.
func TestReplayRetentionGroupLivesAndDiesWithItsRoot(t *testing.T) {
	f := newFx(t)
	r := newRecorder(f.wall())
	c := r.chain(2)
	f.mustAdmit(f.main, c[0])
	day := int64(24 * time.Hour)
	f.clock.Add(10 * day)
	f.mustAdmit(f.main, c[1], c[2])
	first := model.UnixNano(f.clock.Load() - 10*day + 14*day) // the root's own deadline
	latest := model.UnixNano(f.clock.Load() + 14*day)
	cand := func(c model.ReplayChunk) storage.EraseCandidate {
		return storage.EraseCandidate{Org: f.main.org, Project: f.main.project, Kind: model.Replay, Record: &model.Record{Kind: model.Replay, Payload: model.Payload{Replay: &c}}}
	}
	got, err := f.svc.LatestReference(f.ctx, cand(c[0]))
	if err != nil || got != latest || got <= first {
		t.Fatalf("the root is retained until %d (its own deadline %d, latest chunk %d): %v", got, first, latest, err)
	}
	if got, _ = f.svc.LatestReference(f.ctx, cand(newRecorder(f.wall()).cp())); got != 0 {
		t.Fatal("a chunk of an unindexed replay is referenced")
	}
	if got, _ = f.svc.LatestReference(f.ctx, storage.EraseCandidate{Org: f.main.org, Project: f.main.project, Kind: model.Metric}); got != 0 {
		t.Fatal("a non-replay candidate is referenced")
	}
	// The real expiry pass: the root outlived its own deadline and stays; the whole group goes together.
	f.clock.Add(5 * day) // 15 days after the root: its own deadline is over, the group's is not
	if err = f.ret.RunOnce(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.storedRows(f.main); n != 3 {
		t.Fatalf("%d chunks remain after the root's own deadline, want all 3", n)
	}
	f.clock.Add(10 * day)
	if err = f.ret.RunOnce(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.storedRows(f.main); n != 0 {
		t.Fatalf("%d chunks remain after the group deadline", n)
	}
}

func TestReplayRecordIsImmutableAndBounded(t *testing.T) {
	f := newFx(t)
	r := newRecorder(f.wall())
	cp := r.cp()
	f.mustAdmit(f.main, cp)
	g := f.grant(f.main)
	until := model.UnixNano(f.clock.Load() + int64(14*24*time.Hour))
	read := func() (group, pin) {
		var gr group
		var p pin
		_ = f.store.View(f.ctx, func(st control.State) error {
			s := st.Orgs[f.main.org.String()].Settings
			_ = json.Unmarshal(s[groupKey(f.main.project, r.replay)], &gr)
			var pins map[string]pin
			_ = json.Unmarshal(s[pinKey(f.main.project)], &pins)
			p = pins[r.replay.String()]
			return nil
		})
		return gr, p
	}
	g0, p0 := read()
	// Recording the same chunk again changes nothing.
	if err := f.svc.Record(f.ctx, g, f.main.project, cp, until); err != nil {
		t.Fatal(err)
	}
	if g1, p1 := read(); g1.Seq != g0.Seq || p1 != p0 {
		t.Fatal("an idempotent record rewrote the index")
	}
	// A different chunk at a recorded checkpoint sequence, or another session, is a conflict and changes nothing.
	forged := cp
	forged.Events = []model.MaskedEvent{{At: 1, Kind: "pointer", Node: 1, X: 9, Y: 9}}
	if err := f.svc.Record(f.ctx, g, f.main.project, forged, until); code(err) != model.Conflict {
		t.Fatalf("%v", err)
	}
	alien := cp
	alien.Session = model.NewID()
	if err := f.svc.Record(f.ctx, g, f.main.project, alien, until); code(err) != model.Conflict {
		t.Fatalf("%v", err)
	}
	if g1, p1 := read(); g1.Seq != g0.Seq || p1 != p0 {
		t.Fatal("a conflicting record changed the index")
	}
	// A deadline in the past, a project outside the grant and an invalid chunk are refused.
	if code(f.svc.Record(f.ctx, g, f.main.project, cp, model.UnixNano(f.clock.Load()-1))) != model.Invalid {
		t.Fatal("past deadline recorded")
	}
	if code(f.svc.Record(f.ctx, g, model.NewID(), cp, until)) != model.Forbidden {
		t.Fatal("foreign project recorded")
	}
	bad := cp
	bad.Nodes = []model.MaskedNode{{ID: 1, Tag: "div", Text: canary}}
	if code(f.svc.Record(f.ctx, g, f.main.project, bad, until)) != model.Invalid {
		t.Fatal("invalid chunk recorded")
	}
	// The deadline moves with the newest chunk, coalesced to a minute, and never backwards.
	d := r.delta()
	later := until + model.UnixNano(30*time.Second)
	if err := f.svc.Record(f.ctx, g, f.main.project, d, later); err != nil {
		t.Fatal(err)
	}
	if _, p := read(); p.RetainUntil != until {
		t.Fatal("a sub-minute extension rewrote control state")
	}
	later = until + model.UnixNano(5*time.Minute)
	if err := f.svc.Record(f.ctx, g, f.main.project, d, later); err != nil {
		t.Fatal(err)
	}
	if _, p := read(); p.RetainUntil != later {
		t.Fatalf("deadline %d, want %d", p.RetainUntil, later)
	}
	if err := f.svc.Record(f.ctx, g, f.main.project, d, until); err != nil {
		t.Fatal(err)
	}
	if _, p := read(); p.RetainUntil != later {
		t.Fatal("the group deadline moved backwards")
	}
	// An index whose group deadline passed a day ago is forgotten when the next replay records.
	f.clock.Add(int64(14*24*time.Hour) + int64(5*time.Minute) + int64(25*time.Hour))
	n := newRecorder(f.wall())
	f.mustAdmit(f.main, n.cp())
	_ = f.store.View(f.ctx, func(st control.State) error {
		s := st.Orgs[f.main.org.String()].Settings
		if _, ok := s[groupKey(f.main.project, r.replay)]; ok {
			t.Error("an expired index was kept")
		}
		if _, ok := s[groupKey(f.main.project, n.replay)]; !ok {
			t.Error("the new index is missing")
		}
		return nil
	})
}

// Bytes fetched while a revocation lands are discarded, never released.
func TestReplayRevocationLandingDuringFetchReleasesNothing(t *testing.T) {
	f := newFx(t)
	scope, revoke := f.reader(f.main, f.main.project)
	r := newRecorder(f.wall())
	f.mustAdmit(f.main, r.chain(3)...)
	s, err := f.svc.Read(f.ctx, scope, r.replay, ReplayWindow{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	f.scan.end = revoke // the grant is revoked after the pre-fetch fence passed and the bytes were read
	ev := next(t, s)
	if ev.Kind != EventRevoke || ev.Chunk != nil {
		t.Fatalf("%+v", ev)
	}
}

// Any advance of the org delete generation ends open streams, whatever its cause.
func TestReplayDeleteGenerationAdvanceEndsOpenStreams(t *testing.T) {
	f := newFx(t)
	scope, _ := f.reader(f.main, f.main.project)
	r := newRecorder(f.wall())
	f.mustAdmit(f.main, r.chain(3)...)
	s, err := f.svc.Read(f.ctx, scope, r.replay, ReplayWindow{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	next(t, s)
	if err = f.store.Update(f.ctx, func(st *model.ControlState) error {
		if st.DeleteGenerations == nil {
			st.DeleteGenerations = map[string]uint64{}
		}
		st.DeleteGenerations[f.main.org.String()]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if ev := next(t, s); ev.Kind != EventRevoke || ev.Reason != ReasonDeleted || ev.Chunk != nil {
		t.Fatalf("%+v", ev)
	}
}
