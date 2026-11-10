// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/storage"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeFeed is a scripted committed change feed: it implements the same
// Subscribe/ChangeIterator seam as the real C05 engine and delivers exactly the
// pages a test pushes, so "push, not polling" is observable.
type fakeFeed struct {
	mu         sync.Mutex
	iters      []*fakeIter
	subscribes atomic.Int64
	closeCalls atomic.Int64
	subErr     error
	requests   []storage.SubscribeRequest
	marks      []model.Cursor
}

type fakeIter struct {
	feed   *fakeFeed
	ctx    context.Context
	pages  chan storage.ChangePage
	nexts  atomic.Int64
	closed chan struct{}
	errs   chan error
	once   sync.Once
	trip   chan struct{}
}

func (f *fakeFeed) Subscribe(ctx context.Context, scope auth.Scope, req storage.SubscribeRequest) (storage.ChangeIterator, error) {
	f.subscribes.Add(1)
	if f.subErr != nil {
		return nil, f.subErr
	}
	it := &fakeIter{feed: f, ctx: ctx, pages: make(chan storage.ChangePage, 256), errs: make(chan error, 1), closed: make(chan struct{}), trip: make(chan struct{})}
	f.mu.Lock()
	f.iters = append(f.iters, it)
	f.requests = append(f.requests, req)
	f.mu.Unlock()
	return it, nil
}
func (f *fakeFeed) last() *fakeIter {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.iters[len(f.iters)-1]
}
func (it *fakeIter) Next(ctx context.Context) (storage.ChangePage, error) {
	it.nexts.Add(1)
	select {
	case p := <-it.pages:
		return p, nil
	default:
	}
	select {
	case p := <-it.pages:
		return p, nil
	case <-ctx.Done():
		return storage.ChangePage{}, model.Fail(model.Cancelled)
	case <-it.ctx.Done():
		return storage.ChangePage{}, model.Fail(model.Cancelled)
	case err := <-it.errs:
		return storage.ChangePage{}, err
	case <-it.trip:
		panic("SECRET-ROW-CONTENT injected pump panic")
	case <-it.closed:
		return storage.ChangePage{}, io.ErrClosedPipe
	}
}
func (it *fakeIter) Watermarks() []model.Cursor { return it.feed.marks }
func (it *fakeIter) Close() error {
	it.feed.closeCalls.Add(1)
	it.once.Do(func() { close(it.closed) })
	return nil
}
func (it *fakeIter) push(p storage.ChangePage) { it.pages <- p }

var liveGroup = model.NewID()

func cur(n uint64) []model.Cursor { return []model.Cursor{{Group: liveGroup, Index: model.Uint64(n)}} }

// rowsPage builds one committed page of logs for a project and source.
func rowsPage(t *testing.T, project, source model.ID, at uint64, lines ...string) storage.ChangePage {
	t.Helper()
	var p storage.Page
	for i, line := range lines {
		r := logRow(t, project, int64(1_000+i), line, model.Labels{{Name: "app", Value: "web"}})
		p.IDs = append(p.IDs, model.NewID())
		p.Times = append(p.Times, r.at)
		p.Values = append(p.Values, r.payload)
		p.Projects = append(p.Projects, project)
		p.Sources = append(p.Sources, source)
	}
	return storage.ChangePage{Page: p, Cursors: cur(at)}
}

type liveEnv struct {
	*fx
	feed *fakeFeed
	svc  *LiveService
	cfg  LiveLimits
}

func newLiveEnv(t *testing.T, mutate func(*LiveLimits)) *liveEnv {
	t.Helper()
	f := newFx(t)
	e := &liveEnv{fx: f, feed: &fakeFeed{marks: cur(100)}, cfg: DefaultLiveLimits()}
	e.cfg.Heartbeat = time.Hour
	if mutate != nil {
		mutate(&e.cfg)
	}
	var err error
	e.svc, err = NewLiveService(e.feed, f.svc, testRegistry(t), testLimits(), WithLiveDeleteGenerations(f.deletes), WithLiveLimits(e.cfg), WithLiveClock(func() time.Time { return time.Unix(0, f.now.Load()) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.svc.Close() })
	return e
}

func (e *liveEnv) req(expr string, projects ...model.ID) LiveRequest {
	return LiveRequest{Projects: projects, Profile: logql352, FeatureSet: logFeatureSet, Expression: expr}
}

func (e *liveEnv) open(t *testing.T, scope auth.Scope, req LiveRequest, after *uint64) (LiveIterator, error) {
	t.Helper()
	tk, err := e.svc.CreateLiveTicket(e.ctx, scope, req)
	if err != nil {
		return nil, err
	}
	return e.svc.Live(e.ctx, scope, tk.ID, after)
}

func (e *liveEnv) mustOpen(t *testing.T, scope auth.Scope, req LiveRequest, after *uint64) (LiveIterator, LiveEvent) {
	t.Helper()
	it, err := e.open(t, scope, req, after)
	if err != nil {
		t.Fatal(err)
	}
	ev := nextEvent(t, it)
	if ev.Type != LiveOpen || ev.StreamID == (model.ID{}) {
		t.Fatalf("first event must open the stream, got %+v", ev)
	}
	return it, ev
}

func nextEvent(t *testing.T, it LiveIterator) LiveEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ev, err := it.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	return ev
}

// quiet requires that nothing is deliverable within d.
func quiet(t *testing.T, it LiveIterator, d time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	ev, err := it.Next(ctx)
	if err == nil {
		t.Fatalf("unexpected event while nothing was committed: %+v", ev)
	}
	if faultCode(err) != model.Timeout && faultCode(err) != model.Cancelled {
		t.Fatalf("idle wait must end by the caller's deadline, got %v", err)
	}
}

func mustJSON(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func wantRecord(t *testing.T, ev LiveEvent, line string) {
	t.Helper()
	if ev.Type != LiveRecord || ev.Entry == nil || ev.Entry.Line != line {
		t.Fatalf("want record %q, got %+v", line, ev)
	}
}

func wantEOF(t *testing.T, it LiveIterator) {
	t.Helper()
	if _, err := it.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("a terminal event must be followed by io.EOF, got %v", err)
	}
}

// settle waits for every stream, iterator, charge and goroutine of the service
// to be released and requires each iterator to have been closed exactly once.
func (e *liveEnv) settle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var u LiveUsage
	for time.Now().Before(deadline) {
		u = e.svc.Usage()
		if u.Streams == 0 && u.OpenIterators == 0 && u.MemoryUsed == 0 && u.Goroutines == 0 && u.Attached == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if u.Streams != 0 || u.OpenIterators != 0 || u.MemoryUsed != 0 || u.Goroutines != 0 || u.Attached != 0 || u.LeakedBytes != 0 {
		t.Fatalf("live service did not return to idle: %+v", u)
	}
	if subs, closes := e.feed.subscribes.Load(), e.feed.closeCalls.Load(); subs != closes {
		t.Fatalf("every subscription must be closed exactly once: subscribed %d, Close calls %d", subs, closes)
	}
}

func fixture(t *testing.T, e *liveEnv) (org model.ID, project model.ID, alice person, scope auth.Scope) {
	t.Helper()
	org, ps := e.newOrg("live org", 1)
	alice = e.user(org, "alice@example.test", ps, auth.Read)
	return org, ps[0], alice, e.scope(alice, org, ps[0])
}

// TestLiveIsPushNotPolling blocks the feed and requires exactly the newly
// committed record to unblock Next, with no further feed or query activity.
func TestLiveIsPushNotPolling(t *testing.T) {
	e := newLiveEnv(t, nil)
	_, project, _, scope := fixture(t, e)
	it, _ := e.mustOpen(t, scope, e.req(`{app="web"}`, project), nil)
	defer it.Close()
	feed := e.feed.last()
	quiet(t, it, 200*time.Millisecond)
	if feed.nexts.Load() != 1 {
		t.Fatalf("a blocked stream must be parked in exactly one feed wait, saw %d Next calls", feed.nexts.Load())
	}
	got := make(chan LiveEvent, 1)
	go func() {
		ev, err := it.Next(context.Background())
		if err != nil {
			t.Error(err)
		}
		got <- ev
	}()
	select {
	case ev := <-got:
		t.Fatalf("Next returned with nothing committed: %+v", ev)
	case <-time.After(100 * time.Millisecond):
	}
	feed.push(rowsPage(t, project, model.NewID(), 101, "first committed"))
	select {
	case ev := <-got:
		wantRecord(t, ev, "first committed")
		if ev.Sequence != 1 || ev.Project == nil || *ev.Project != project {
			t.Fatalf("record identity wrong: %+v", ev)
		}
		if len(ev.Cursors) != 1 || ev.Cursors[0].Index != 101 {
			t.Fatalf("record must carry its commit cursor: %+v", ev.Cursors)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the committed record did not unblock Next")
	}
	if e.feed.subscribes.Load() != 1 {
		t.Fatalf("steady state must not resubscribe or re-execute: %d subscriptions", e.feed.subscribes.Load())
	}
	if req := e.feed.requests[0]; req.Signal != model.Log || len(req.Selectors) != 0 || len(req.After) != 0 {
		t.Fatalf("subscription must be a plain log feed (selection is the pipeline's job): %+v", req)
	}
}

func TestLivePipelineFiltersAndLabels(t *testing.T) {
	e := newLiveEnv(t, nil)
	_, project, _, scope := fixture(t, e)
	it, _ := e.mustOpen(t, scope, e.req(`{app="web"} |= "keep"`, project), nil)
	defer it.Close()
	e.feed.last().push(rowsPage(t, project, model.NewID(), 101, "drop me", "keep me", "also drop"))
	ev := nextEvent(t, it)
	wantRecord(t, ev, "keep me")
	if ev.Sequence != 1 {
		t.Fatalf("filtered rows must not consume sequences: %+v", ev)
	}
	if len(ev.Entry.StreamLabels) != 1 || ev.Entry.StreamLabels[0].Value != "web" {
		t.Fatalf("stream labels lost: %+v", ev.Entry.StreamLabels)
	}
	quiet(t, it, 100*time.Millisecond)
}

// TestLiveReplayAndGap reconnects within the replay window and receives only
// the subsequent events once; after buffer eviction it receives an explicit gap
// with exact bounds, never an apparently complete empty stream.
func TestLiveReplayAndGap(t *testing.T) {
	e := newLiveEnv(t, nil)
	_, project, _, scope := fixture(t, e)
	src := model.NewID()
	req := e.req(`{app="web"}`, project)
	it, open := e.mustOpen(t, scope, req, nil)
	feed := e.feed.last()
	feed.push(rowsPage(t, project, src, 101, "a1", "a2"))
	wantRecord(t, nextEvent(t, it), "a1")
	last := nextEvent(t, it)
	wantRecord(t, last, "a2")
	it.Close()

	// Committed while nobody is attached.
	feed.push(rowsPage(t, project, src, 102, "b1"))
	feed.push(rowsPage(t, project, src, 103, "b2"))
	for deadline := time.Now().Add(2 * time.Second); ; {
		e.svc.mu.Lock()
		st := e.svc.streams[open.StreamID]
		e.svc.mu.Unlock()
		if st != nil && st.lastSequence() == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("detached stream did not keep consuming the committed feed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	resume := req
	resume.ResumeStreamID = &open.StreamID
	after := uint64(last.Sequence)
	it2, open2 := e.mustOpen(t, scope, resume, &after)
	defer it2.Close()
	if open2.StreamID != open.StreamID {
		t.Fatal("reconnect must attach to the retained stream")
	}
	b1, b2 := nextEvent(t, it2), nextEvent(t, it2)
	wantRecord(t, b1, "b1")
	wantRecord(t, b2, "b2")
	if b1.Sequence != 3 || b2.Sequence != 4 {
		t.Fatalf("replay must continue exactly after Last-Event-ID: %d %d", b1.Sequence, b2.Sequence)
	}
	quiet(t, it2, 100*time.Millisecond)
	if e.feed.subscribes.Load() != 1 {
		t.Fatal("reconnect inside the window must not resubscribe")
	}
}

func TestLiveReplayEvictionReportsExactGap(t *testing.T) {
	e := newLiveEnv(t, nil)
	_, project, _, scope := fixture(t, e)
	src := model.NewID()
	req := e.req(`{app="web"}`, project)
	req.Budget.MaxReturned = 2 // replay keeps two entries
	it, open := e.mustOpen(t, scope, req, nil)
	feed := e.feed.last()
	feed.push(rowsPage(t, project, src, 101, "a1"))
	first := nextEvent(t, it)
	wantRecord(t, first, "a1")
	it.Close()
	for i := 0; i < 5; i++ {
		feed.push(rowsPage(t, project, src, uint64(102+i), "lost"+strconv.Itoa(i)))
	}
	waitSequence(t, e, open.StreamID, 6)
	resume := req
	resume.ResumeStreamID = &open.StreamID
	after := uint64(first.Sequence)
	it2, _ := e.mustOpen(t, scope, resume, &after)
	defer it2.Close()
	gap := nextEvent(t, it2)
	if gap.Type != LiveGap || gap.Gap == nil || gap.Gap.Reason != GapReplayEvicted {
		t.Fatalf("an evicted replay must be an explicit gap, got %+v", gap)
	}
	// Sequences 2..4 were evicted; 5 and 6 remain.
	if gap.Gap.FromSequence != 2 || gap.Gap.ToSequence != 4 || gap.Sequence != 4 {
		t.Fatalf("gap bounds not exact: %+v", gap.Gap)
	}
	if len(gap.Gap.After) != 1 || gap.Gap.After[0].Index != 101 || len(gap.Gap.Through) != 1 || gap.Gap.Through[0].Index != 104 {
		t.Fatalf("gap cursor bounds not exact: after %+v through %+v", gap.Gap.After, gap.Gap.Through)
	}
	wantRecord(t, nextEvent(t, it2), "lost3")
	wantRecord(t, nextEvent(t, it2), "lost4")
	quiet(t, it2, 100*time.Millisecond)
}

func waitSequence(t *testing.T, e *liveEnv, id LiveStreamID, seq uint64) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); ; {
		e.svc.mu.Lock()
		st := e.svc.streams[id]
		e.svc.mu.Unlock()
		if st != nil && st.lastSequence() >= seq {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("stream never reached sequence %d", seq)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// An expired replay (the window lapsed) is a gap, not a silent restart.
func TestLiveExpiredReplayIsExplicitGap(t *testing.T) {
	e := newLiveEnv(t, nil)
	_, project, _, scope := fixture(t, e)
	req := e.req(`{app="web"}`, project)
	it, open := e.mustOpen(t, scope, req, nil)
	feed := e.feed.last()
	feed.push(rowsPage(t, project, model.NewID(), 101, "a1"))
	last := nextEvent(t, it)
	it.Close()
	e.advance(e.cfg.ReplayWindow + time.Second)
	for deadline := time.Now().Add(3 * time.Second); e.svc.Usage().Streams != 0; {
		if time.Now().After(deadline) {
			t.Fatal("a detached stream must end when its replay window lapses")
		}
		time.Sleep(5 * time.Millisecond)
	}
	resume := req
	resume.ResumeStreamID = &open.StreamID
	after := uint64(last.Sequence)
	it2, open2 := e.mustOpen(t, scope, resume, &after)
	defer it2.Close()
	if open2.StreamID == open.StreamID {
		t.Fatal("an expired stream must not be silently reused")
	}
	gap := nextEvent(t, it2)
	if gap.Type != LiveGap || gap.Gap.Reason != GapReplayExpired || gap.Sequence != last.Sequence+1 || gap.Gap.FromSequence != last.Sequence+1 {
		t.Fatalf("expired replay must open with a replay_expired gap right after Last-Event-ID: %+v", gap)
	}
	if len(gap.Gap.Through) != 1 || gap.Gap.Through[0].Index != 100 {
		t.Fatalf("expired-replay gap must state the new stream's start watermark: %+v", gap.Gap)
	}
	e.feed.last().push(rowsPage(t, project, model.NewID(), 101, "after gap"))
	rec := nextEvent(t, it2)
	wantRecord(t, rec, "after gap")
	if rec.Sequence != gap.Sequence+1 {
		t.Fatalf("sequences must continue after the gap: %d", rec.Sequence)
	}
}

func TestLiveResumeValidationAndOwnership(t *testing.T) {
	e := newLiveEnv(t, nil)
	org, ps := e.newOrg("live org", 1)
	project := ps[0]
	alice := e.user(org, "alice@example.test", ps, auth.Read)
	mallory := e.user(org, "mallory@example.test", ps, auth.Read)
	scope := e.scope(alice, org, project)
	req := e.req(`{app="web"}`, project)
	it, open := e.mustOpen(t, scope, req, nil)
	defer it.Close()
	resume := req
	resume.ResumeStreamID = &open.StreamID
	beyond := uint64(50)
	if _, err := e.open(t, scope, resume, &beyond); faultCode(err) != model.Invalid {
		t.Fatalf("Last-Event-ID beyond the stream must be Invalid, got %v", err)
	}
	plain := uint64(1)
	if _, err := e.open(t, scope, req, &plain); faultCode(err) != model.Invalid {
		t.Fatalf("Last-Event-ID without a resumable stream must be Invalid, got %v", err)
	}
	// Another principal naming this stream ID gets a fresh stream (with a gap),
	// never this stream's events, and cannot tell the stream exists.

	e.feed.last().push(rowsPage(t, project, model.NewID(), 101, "alice only"))
	wantRecord(t, nextEvent(t, it), "alice only")
	zero := uint64(0)
	it2, open2 := e.mustOpen(t, e.scope(mallory, org, project), resume, &zero)
	defer it2.Close()
	if open2.StreamID == open.StreamID {
		t.Fatal("another principal attached to a stream it does not own")
	}
	if ev := nextEvent(t, it2); ev.Type != LiveGap || ev.Gap.Reason != GapReplayExpired {
		t.Fatalf("a foreign stream ID must look exactly like an expired one: %+v", ev)
	}
	quiet(t, it2, 100*time.Millisecond)
	// A different selector under the same stream ID is not a resume either.
	other := e.req(`{app="web"} |= "x"`, project)
	other.ResumeStreamID = &open.StreamID
	it3, open3 := e.mustOpen(t, scope, other, nil)
	defer it3.Close()
	if open3.StreamID == open.StreamID {
		t.Fatal("a different expression must not attach to the retained stream")
	}
}

// TestLiveRevokeDeleteAndScope changes policy and deletion between chunks and
// requires a terminal safe event before any next record; a ticket copied to
// another session or org is rejected.
func TestLiveRevokeDeleteAndScope(t *testing.T) {
	t.Run("revoke between chunks", func(t *testing.T) {
		e := newLiveEnv(t, nil)
		org, project, alice, scope := fixture(t, e)
		it, _ := e.mustOpen(t, scope, e.req(`{app="web"}`, project), nil)
		defer it.Close()
		feed := e.feed.last()
		src := model.NewID()
		feed.push(rowsPage(t, project, src, 101, "before"))
		wantRecord(t, nextEvent(t, it), "before")
		feed.push(rowsPage(t, project, src, 102, "secret-after-revoke"))
		waitSequence(t, e, feedStream(t, e), 2)
		e.revoke(org, alice, project, auth.Read)
		ev := nextEvent(t, it)
		if ev.Type != LiveRevoke || ev.Entry != nil || ev.Failure == nil {
			t.Fatalf("a revoked scope must end the stream with a safe revoke before any further record: %+v", ev)
		}
		wantEOF(t, it)
		feed.push(rowsPage(t, project, src, 103, "never"))
		it.Close()
		e.settle(t)
	})
	t.Run("revoke while idle", func(t *testing.T) {
		e := newLiveEnv(t, nil)
		org, project, alice, scope := fixture(t, e)
		it, _ := e.mustOpen(t, scope, e.req(`{app="web"}`, project), nil)
		defer it.Close()
		got := make(chan LiveEvent, 1)
		go func() {
			ev, _ := it.Next(context.Background())
			got <- ev
		}()
		time.Sleep(50 * time.Millisecond)
		e.revoke(org, alice, project, auth.Read)
		select {
		case ev := <-got:
			if ev.Type != LiveRevoke {
				t.Fatalf("idle stream must learn of the revocation without traffic: %+v", ev)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("revocation never ended an idle stream")
		}
		it.Close()
		e.settle(t)
	})
	t.Run("deletion between chunks", func(t *testing.T) {
		e := newLiveEnv(t, nil)
		_, project, _, scope := fixture(t, e)
		it, _ := e.mustOpen(t, scope, e.req(`{app="web"}`, project), nil)
		defer it.Close()
		feed := e.feed.last()
		feed.push(rowsPage(t, project, model.NewID(), 101, "before", "doomed"))
		wantRecord(t, nextEvent(t, it), "before")
		e.deletes.bump.Add(1)
		ev := nextEvent(t, it)
		if ev.Type != LiveRevoke || ev.Reason != reasonDeleted || ev.Entry != nil {
			t.Fatalf("a deletion must end the stream before the next record: %+v", ev)
		}
		wantEOF(t, it)
		it.Close()
		e.settle(t)
	})
	t.Run("deletion before a page is buffered", func(t *testing.T) {
		e := newLiveEnv(t, nil)
		_, project, _, scope := fixture(t, e)
		it, _ := e.mustOpen(t, scope, e.req(`{app="web"}`, project), nil)
		defer it.Close()
		e.deletes.bump.Add(1)
		e.feed.last().push(rowsPage(t, project, model.NewID(), 101, "covered by deletion"))
		for {
			ev := nextEvent(t, it)
			if ev.Type == LiveRecord {
				t.Fatalf("a record released after a deletion: %+v", ev)
			}
			if ev.Terminal() {
				break
			}
		}
		it.Close()
		e.settle(t)
	})
	t.Run("feed revoke page", func(t *testing.T) {
		e := newLiveEnv(t, nil)
		_, project, _, scope := fixture(t, e)
		it, _ := e.mustOpen(t, scope, e.req(`{app="web"}`, project), nil)
		defer it.Close()
		e.feed.last().push(storage.ChangePage{Revoked: true, Cursors: cur(100)})
		ev := nextEvent(t, it)
		if ev.Type != LiveRevoke || ev.Reason != reasonRevoked {
			t.Fatalf("the feed's revoke page must end the stream: %+v", ev)
		}
		wantEOF(t, it)
		it.Close()
		e.settle(t)
	})
	t.Run("ticket bound to issuer", func(t *testing.T) {
		e := newLiveEnv(t, nil)
		org, ps := e.newOrg("live org", 1)
		project := ps[0]
		orgB, psB := e.newOrg("other org", 1)
		alice := e.user(org, "alice@example.test", ps, auth.Read)
		carol := e.user(orgB, "carol@example.test", psB, auth.Read)
		bob := e.user(org, "bob@example.test", ps, auth.Read)
		scope := e.scope(alice, org, project)
		tk, err := e.svc.CreateLiveTicket(e.ctx, scope, e.req(`{app="web"}`, project))
		if err != nil {
			t.Fatal(err)
		}
		for name, who := range map[string]auth.Scope{"another org": e.scope(carol, orgB, psB[0]), "another principal in the same org": e.scope(bob, org, project)} {
			if _, err := e.svc.Live(e.ctx, who, tk.ID, nil); faultCode(err) != model.NotFound {
				t.Fatalf("%s must not use the ticket, got %v", name, err)
			}
		}
		if _, err := e.svc.Live(WithLiveSession(e.ctx, "another-session"), scope, tk.ID, nil); faultCode(err) != model.NotFound {
			t.Fatalf("another session must not use the ticket, got %v", err)
		}
		if _, err := e.svc.LiveTicketRequest(WithLiveSession(e.ctx, "another-session"), tk.ID); faultCode(err) != model.NotFound {
			t.Fatalf("another session must not read the ticket's request, got %v", err)
		}
		if e.feed.subscribes.Load() != 0 {
			t.Fatal("a refused ticket reached the feed")
		}
		it, err := e.svc.Live(e.ctx, scope, tk.ID, nil)
		if err != nil {
			t.Fatalf("a refused presenter must not burn the owner's ticket: %v", err)
		}
		it.Close()
		if _, err := e.svc.Live(e.ctx, scope, tk.ID, nil); faultCode(err) != model.NotFound {
			t.Fatalf("a ticket is single use, got %v", err)
		}
	})
	t.Run("ticket expires", func(t *testing.T) {
		e := newLiveEnv(t, nil)
		_, project, _, scope := fixture(t, e)
		tk, err := e.svc.CreateLiveTicket(e.ctx, scope, e.req(`{app="web"}`, project))
		if err != nil {
			t.Fatal(err)
		}
		e.advance(61 * time.Second)
		if _, err := e.svc.Live(e.ctx, scope, tk.ID, nil); faultCode(err) != model.NotFound {
			t.Fatalf("an expired ticket must be refused, got %v", err)
		}
	})
	t.Run("revoked before use", func(t *testing.T) {
		e := newLiveEnv(t, nil)
		org, project, alice, scope := fixture(t, e)
		tk, err := e.svc.CreateLiveTicket(e.ctx, scope, e.req(`{app="web"}`, project))
		if err != nil {
			t.Fatal(err)
		}
		e.revoke(org, alice, project, auth.Read)
		if _, err := e.svc.Live(e.ctx, scope, tk.ID, nil); err == nil {
			t.Fatal("a revoked scope attached with a valid ticket")
		}
		if e.feed.subscribes.Load() != 0 {
			t.Fatal("a revoked scope reached the feed")
		}
	})
}

func feedStream(t *testing.T, e *liveEnv) LiveStreamID {
	t.Helper()
	e.svc.mu.Lock()
	defer e.svc.mu.Unlock()
	for id := range e.svc.streams {
		return id
	}
	t.Fatal("no stream")
	return model.ID{}
}

// TestLiveGapThenRevocation is the brief's assertion: after a replay-buffer
// overrun and a subsequent revocation the gap is visible and no record follows.
func TestLiveGapThenRevocation(t *testing.T) {
	e := newLiveEnv(t, nil)
	org, project, alice, scope := fixture(t, e)
	it, _ := e.mustOpen(t, scope, e.req(`{app="web"}`, project), nil)
	defer it.Close()
	feed := e.feed.last()
	src := model.NewID()
	feed.push(storage.ChangePage{Gap: &storage.ChangeGap{After: cur(10), Through: cur(40), Reason: "slow_consumer"}, Cursors: cur(40)})
	feed.push(rowsPage(t, project, src, 41, "kept"))
	var receivedGap bool
	var recordsAfterRevocation int
	revoked := false
	for i := 0; i < 2; i++ {
		ev := nextEvent(t, it)
		switch ev.Type {
		case LiveGap:
			receivedGap = true
			if ev.Gap.Reason != GapFeedOverrun || ev.Gap.After[0].Index != 10 || ev.Gap.Through[0].Index != 40 {
				t.Fatalf("feed gap bounds must pass through exactly: %+v", ev.Gap)
			}
		case LiveRecord:
			wantRecord(t, ev, "kept")
		default:
			t.Fatalf("unexpected %+v", ev)
		}
	}
	feed.push(rowsPage(t, project, src, 42, "after revoke"))
	waitSequence(t, e, feedStream(t, e), 3)
	e.revoke(org, alice, project, auth.Read)
	revoked = true
	for {
		ev := nextEvent(t, it)
		if ev.Type == LiveRecord && revoked {
			recordsAfterRevocation++
		}
		if ev.Terminal() {
			if ev.Type != LiveRevoke {
				t.Fatalf("revocation must be reported as a revoke: %+v", ev)
			}
			break
		}
	}
	if !receivedGap || recordsAfterRevocation != 0 {
		t.Fatal("live stream hid a gap or released revoked data")
	}
}

func TestLiveFeedGapReasonsAndPartialPages(t *testing.T) {
	e := newLiveEnv(t, nil)
	_, project, _, scope := fixture(t, e)
	it, _ := e.mustOpen(t, scope, e.req(`{app="web"}`, project), nil)
	defer it.Close()
	feed := e.feed.last()
	feed.push(storage.ChangePage{Gap: &storage.ChangeGap{After: cur(1), Through: cur(9), Reason: "catch_up_required"}, Cursors: cur(9)})
	if ev := nextEvent(t, it); ev.Type != LiveGap || ev.Gap.Reason != GapFeedCatchUp || ev.Sequence != 1 || ev.Gap.FromSequence != 1 || ev.Gap.ToSequence != 1 {
		t.Fatalf("catch-up gap: %+v", ev)
	}
	partial := rowsPage(t, project, model.NewID(), 10, "partial row")
	partial.Page.Partial = true
	feed.push(partial)
	gap := nextEvent(t, it)
	if gap.Type != LiveGap || gap.Gap.Reason != GapPartialShard {
		t.Fatalf("a partial page must be a gap, never silently complete: %+v", gap)
	}
	wantRecord(t, nextEvent(t, it), "partial row")
}

// TestLiveBackpressureBounds requires a slow consumer to receive an explicit
// gap and a typed disconnect, with memory bounded by the replay budget.
func TestLiveBackpressureBounds(t *testing.T) {
	e := newLiveEnv(t, nil)
	_, project, _, scope := fixture(t, e)
	req := e.req(`{app="web"}`, project)
	req.Budget.MaxReturned = 4
	req.Budget.MemoryBytes = 64 << 10
	it, open := e.mustOpen(t, scope, req, nil)
	defer it.Close()
	feed := e.feed.last()
	src := model.NewID()
	peak := int64(0)
	for i := 0; i < 200; i++ {
		feed.push(rowsPage(t, project, src, uint64(101+i), "burst "+strconv.Itoa(i)))
		if i%20 == 19 {
			waitSequence(t, e, open.StreamID, uint64(i+1))
			if used := e.svc.Usage().MemoryUsed; used > peak {
				peak = used
			}
		}
	}
	waitSequence(t, e, open.StreamID, 200)
	if peak > 64<<10+e.cfg.WorkingBytes {
		t.Fatalf("buffer exceeded its budget: %d bytes", peak)
	}
	e.svc.mu.Lock()
	st := e.svc.streams[open.StreamID]
	e.svc.mu.Unlock()
	st.mu.Lock()
	buffered := len(st.buf)
	st.mu.Unlock()
	if buffered > 4 {
		t.Fatalf("replay buffer holds %d entries, bound is 4", buffered)
	}
	gap := nextEvent(t, it)
	if gap.Type != LiveGap || gap.Gap.Reason != GapReplayEvicted || gap.Gap.FromSequence != 1 || gap.Gap.ToSequence != 196 {
		t.Fatalf("slow consumer must be told exactly what it lost: %+v", gap)
	}
	slow := nextEvent(t, it)
	if slow.Type != LiveError || slow.Reason != reasonSlow || slow.Failure == nil || slow.Failure.Code != string(model.Quota) {
		t.Fatalf("slow consumer must be disconnected with a typed event: %+v", slow)
	}
	wantEOF(t, it)
	// The stream is retained: the consumer resumes after the gap and the bounded
	// tail arrives intact.
	resume := req
	resume.ResumeStreamID = &open.StreamID
	after := uint64(gap.Sequence)
	it2, _ := e.mustOpen(t, scope, resume, &after)
	defer it2.Close()
	for i := 196; i < 200; i++ {
		wantRecord(t, nextEvent(t, it2), "burst "+strconv.Itoa(i))
	}
}

func TestLiveOversizedRecordFailsTyped(t *testing.T) {
	e := newLiveEnv(t, nil)
	_, project, _, scope := fixture(t, e)
	req := e.req(`{app="web"}`, project)
	req.Budget.MemoryBytes = 1 << 10
	it, _ := e.mustOpen(t, scope, req, nil)
	defer it.Close()
	big := make([]byte, 4<<10)
	for i := range big {
		big[i] = 'x'
	}
	e.feed.last().push(rowsPage(t, project, model.NewID(), 101, string(big)))
	ev := nextEvent(t, it)
	if ev.Type != LiveError || ev.Failure == nil || ev.Failure.Code != string(model.Quota) || ev.Reason != reasonQuota {
		t.Fatalf("a record beyond the buffer budget must end the stream with a typed quota error, not be dropped or truncated: %+v", ev)
	}
	wantEOF(t, it)
	it.Close()
	e.settle(t)
}

func TestLiveHeartbeatAndDeadline(t *testing.T) {
	e := newLiveEnv(t, func(l *LiveLimits) { l.Heartbeat = 30 * time.Millisecond })
	_, project, _, scope := fixture(t, e)
	req := e.req(`{app="web"}`, project)
	req.Budget.TimeoutNS = model.Int64(5 * time.Minute)
	it, _ := e.mustOpen(t, scope, req, nil)
	defer it.Close()
	hb := nextEvent(t, it)
	if hb.Type != LiveHeartbeat || hb.Sequence != 0 || len(hb.Watermarks) != 1 || hb.Watermarks[0].Index != 100 {
		t.Fatalf("an idle stream must heartbeat with the feed watermarks: %+v", hb)
	}
	feed := e.feed.last()
	feed.push(rowsPage(t, project, model.NewID(), 101, "last words"))
	for {
		ev := nextEvent(t, it)
		if ev.Type == LiveRecord {
			wantRecord(t, ev, "last words")
			break
		}
	}
	e.advance(6 * time.Minute)
	for {
		ev := nextEvent(t, it)
		if ev.Type == LiveHeartbeat {
			continue
		}
		if ev.Type != LiveError || ev.Reason != reasonDeadline || ev.Failure.Code != string(model.Timeout) {
			t.Fatalf("the stream deadline must end it with a typed timeout: %+v", ev)
		}
		break
	}
	wantEOF(t, it)
	it.Close()
	e.settle(t)
}

func TestLiveDeadlineDeliversBufferedRecordsFirst(t *testing.T) {
	e := newLiveEnv(t, nil)
	_, project, _, scope := fixture(t, e)
	req := e.req(`{app="web"}`, project)
	req.Budget.TimeoutNS = model.Int64(30 * time.Second)
	it, open := e.mustOpen(t, scope, req, nil)
	defer it.Close()
	e.feed.last().push(rowsPage(t, project, model.NewID(), 101, "buffered before deadline"))
	waitSequence(t, e, open.StreamID, 1)
	e.advance(45 * time.Second)
	wantRecord(t, nextEvent(t, it), "buffered before deadline")
	if ev := nextEvent(t, it); ev.Type != LiveError || ev.Reason != reasonDeadline {
		t.Fatalf("deadline terminal missing: %+v", ev)
	}
	wantEOF(t, it)
	it.Close()
	e.settle(t)
}

func TestLiveSingleAttachmentSupersedes(t *testing.T) {
	e := newLiveEnv(t, nil)
	_, project, _, scope := fixture(t, e)
	req := e.req(`{app="web"}`, project)
	it1, open := e.mustOpen(t, scope, req, nil)
	defer it1.Close()
	resume := req
	resume.ResumeStreamID = &open.StreamID
	it2, _ := e.mustOpen(t, scope, resume, nil)
	defer it2.Close()
	ev := nextEvent(t, it1)
	if ev.Type != LiveError || ev.Reason != reasonSuperseded {
		t.Fatalf("the replaced attachment must be told it was superseded: %+v", ev)
	}
	wantEOF(t, it1)
	e.feed.last().push(rowsPage(t, project, model.NewID(), 101, "to the new consumer"))
	wantRecord(t, nextEvent(t, it2), "to the new consumer")
}

// TestLiveConnectionCaps bounds streams per principal, per organization and in
// total, and tickets per principal; capacity returns when streams end.
func TestLiveConnectionCaps(t *testing.T) {
	e := newLiveEnv(t, func(l *LiveLimits) {
		l.MaxStreams, l.MaxStreamsPerOrg, l.MaxStreamsPerPrincipal = 3, 2, 1
		l.MaxTickets, l.MaxTicketsPerPrincipal = 4, 2
	})
	org, ps := e.newOrg("cap org", 1)
	a := e.user(org, "a@example.test", ps, auth.Read)
	b := e.user(org, "b@example.test", ps, auth.Read)
	c := e.user(org, "c@example.test", ps, auth.Read)
	orgB, psB := e.newOrg("cap org B", 1)
	d := e.user(orgB, "d@example.test", psB, auth.Read)
	req := e.req(`{app="web"}`, ps[0])
	itA, _ := e.mustOpen(t, e.scope(a, org, ps[0]), req, nil)
	if _, err := e.open(t, e.scope(a, org, ps[0]), req, nil); faultCode(err) != model.Quota {
		t.Fatalf("per-principal stream cap: %v", err)
	}
	itB, _ := e.mustOpen(t, e.scope(b, org, ps[0]), req, nil)
	if _, err := e.open(t, e.scope(c, org, ps[0]), req, nil); faultCode(err) != model.Quota {
		t.Fatalf("per-organization stream cap: %v", err)
	}
	itD, _ := e.mustOpen(t, e.scope(d, orgB, psB[0]), e.req(`{app="web"}`, psB[0]), nil)
	// A principal of a third organization holds nothing: neither the per-org nor
	// the per-principal cap can refuse it, so only the global cap can.
	orgE, psE := e.newOrg("cap org E", 1)
	g := e.user(orgE, "g@example.test", psE, auth.Read)
	if _, err := e.open(t, e.scope(g, orgE, psE[0]), e.req(`{app="web"}`, psE[0]), nil); faultCode(err) != model.Quota {
		t.Fatalf("the global stream cap must refuse with Quota, got %v", err)
	}
	// Refused attempts hold no resource.
	if u := e.svc.Usage(); u.Streams != 3 || u.OpenIterators != 3 {
		t.Fatalf("refused attachments leaked: %+v", u)
	}
	// Tickets are capped per principal and in total.
	sc := e.scope(c, org, ps[0])
	for i := 0; i < 2; i++ {
		if _, err := e.svc.CreateLiveTicket(e.ctx, sc, req); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.svc.CreateLiveTicket(e.ctx, sc, req); faultCode(err) != model.Quota {
		t.Fatalf("per-principal ticket cap: %v", err)
	}
	// Ending a stream returns its slot.
	e.deletes.bump.Add(1)
	for _, it := range []LiveIterator{itA, itB, itD} {
		for {
			ev, err := it.Next(context.Background())
			if err != nil || ev.Terminal() {
				break
			}
		}
		it.Close()
	}
	e.settle(t)
	if _, err := e.open(t, e.scope(a, org, ps[0]), req, nil); err != nil {
		t.Fatalf("capacity must return after streams end: %v", err)
	}
}

// TestLiveIsolationMatrix runs the adversarial scope matrix: two orgs, two
// projects, a restricted source. Nothing outside the scope reaches the feed and
// nothing outside it is ever delivered.
func TestLiveIsolationMatrix(t *testing.T) {
	e := newLiveEnv(t, nil)
	orgA, psA := e.newOrg("org A", 2)
	orgB, psB := e.newOrg("org B", 1)
	p1, p2, p3 := psA[0], psA[1], psB[0]
	alice := e.user(orgA, "alice@example.test", []model.ID{p1}, auth.Read, auth.RawRead)
	bob := e.user(orgA, "bob@example.test", []model.ID{p2}, auth.Read)
	carol := e.user(orgB, "carol@example.test", []model.ID{p3}, auth.Read)
	scopeA, scopeC := e.scope(alice, orgA, p1), e.scope(carol, orgB, p3)
	guess := model.NewID()
	var reference *model.Fault
	for name, c := range map[string]struct {
		scope    auth.Scope
		projects []model.ID
	}{
		"sibling project":         {scopeA, []model.ID{p2}},
		"another org's project":   {scopeA, []model.ID{p3}},
		"guessed project":         {scopeA, []model.ID{guess}},
		"granted plus foreign":    {scopeA, []model.ID{p1, p2}},
		"carol into org A":        {scopeC, []model.ID{p1}},
		"carol guessed":           {scopeC, []model.ID{guess}},
		"alice duplicate project": {scopeA, []model.ID{p1, p1}},
	} {
		_, err := e.svc.CreateLiveTicket(e.ctx, c.scope, e.req(`{app="web"}`, c.projects...))
		if err == nil {
			t.Fatalf("%s: ticket issued across the scope", name)
		}
		f := faultOf(t, err)
		if name == "alice duplicate project" {
			if f.Code != model.Invalid {
				t.Fatalf("%s: %v", name, err)
			}
			continue
		}
		if f.Code != model.NotFound {
			t.Fatalf("%s: want NotFound, got %v", name, err)
		}
		if reference == nil {
			reference = f
		} else if f.SafeDetail != reference.SafeDetail || f.Retryable != reference.Retryable {
			t.Fatalf("%s: denial distinguishable from the others", name)
		}
	}
	if e.feed.subscribes.Load() != 0 {
		t.Fatal("a denied request reached the feed")
	}
	// A project outside the stream's set is never delivered, even if the feed
	// handed it over: the stream ends with a typed error instead.
	it, _ := e.mustOpen(t, scopeA, e.req(`{app="web"}`, p1), nil)
	defer it.Close()
	if req := e.feed.requests[0]; len(req.Projects) != 1 || req.Projects[0] != p1 {
		t.Fatalf("the subscription must name exactly the granted projects: %+v", req.Projects)
	}
	e.feed.last().push(rowsPage(t, p2, model.NewID(), 101, "bob's secret"))
	ev := nextEvent(t, it)
	if ev.Type != LiveError || ev.Entry != nil {
		t.Fatalf("a row of a foreign project was not stopped: %+v", ev)
	}
	_ = bob
	// Read scopes never name a source; raw.read must name exactly its own.
	if _, err := e.svc.CreateLiveTicket(e.ctx, scopeA, LiveRequest{Projects: []model.ID{p1}, Profile: logql352, FeatureSet: logFeatureSet, Expression: `{app="web"}`, Source: &guess}); faultCode(err) != model.Invalid {
		t.Fatalf("a telemetry.read stream must not name a source: %v", err)
	}
}

func TestLiveRestrictedSourceIsolation(t *testing.T) {
	e := newLiveEnv(t, nil)
	org, ps := e.newOrg("raw org", 1)
	project := ps[0]
	a := e.user(org, "a@example.test", ps, auth.Read, auth.RawRead)
	b := e.user(org, "b@example.test", ps, auth.Read, auth.RawRead)
	x := e.restricted(org, project, a.id)
	y := e.restricted(org, project, b.id)
	rawA, err := e.rawScope(a, org, project, x)
	if err != nil {
		t.Fatal(err)
	}
	req := e.req(`{app="web"}`, project)
	// raw.read without a source, or with someone else's source, is refused.
	if _, err = e.svc.CreateLiveTicket(e.ctx, rawA, req); faultCode(err) != model.Invalid {
		t.Fatalf("raw.read stream without a source: %v", err)
	}
	req.Source = &y
	if _, err = e.svc.CreateLiveTicket(e.ctx, rawA, req); faultCode(err) != model.NotFound {
		t.Fatalf("a reader of x must not stream y: %v", err)
	}
	if e.feed.subscribes.Load() != 0 {
		t.Fatal("refused raw stream reached the feed")
	}
	req.Source = &x
	it, _ := e.mustOpen(t, rawA, req, nil)
	defer it.Close()
	feed := e.feed.last()
	if sel := e.feed.requests[0].Selectors; len(sel) != 1 || sel[0].Name != "source_id" || sel[0].Op != storage.MatchEqual || sel[0].Literal.String != x.String() {
		t.Fatalf("a restricted-raw feed must be pinned to its one named source: %+v", sel)
	}
	feed.push(rowsPage(t, project, y, 101, "y only"))
	feed.push(rowsPage(t, project, x, 102, "x only"))
	ev := nextEvent(t, it)
	wantRecord(t, ev, "x only")
	if ev.Entry.Source == nil || *ev.Entry.Source != x {
		t.Fatalf("the record must name its source: %+v", ev.Entry)
	}
	quiet(t, it, 100*time.Millisecond)
	// Losing the named-reader entitlement ends the stream.
	e.cmd(org, "source_policy", auth.AdminPayload{ID: x, Config: mustJSON(auth.SourcePolicyConfig{ProjectID: project, Restricted: true, Readers: []model.ID{b.id}, Enabled: true})})
	feed.push(rowsPage(t, project, x, 103, "after reader removed"))
	for {
		ev := nextEvent(t, it)
		if ev.Type == LiveRecord {
			t.Fatalf("a record was released after the reader entitlement was removed: %+v", ev)
		}
		if ev.Terminal() {
			break
		}
	}
}

func TestLiveRejectsNonStreamableAndInvalidRequests(t *testing.T) {
	e := newLiveEnv(t, nil)
	_, project, _, scope := fixture(t, e)
	for name, mutate := range map[string]func(*LiveRequest){
		"metric expression": func(r *LiveRequest) { r.Expression = `rate({app="web"}[1m])` },
		"syntax error":      func(r *LiveRequest) { r.Expression = `{app="web"` },
		"empty expression":  func(r *LiveRequest) { r.Expression = "" },
		"promql profile":    func(r *LiveRequest) { r.Profile = prom310 },
		"unknown profile":   func(r *LiveRequest) { r.Profile = "logql-loki-0.0.0" },
		"no projects":       func(r *LiveRequest) { r.Projects = nil },
		"huge budget":       func(r *LiveRequest) { r.Budget.MemoryBytes = 1 << 40 },
		"negative timeout":  func(r *LiveRequest) { r.Budget.TimeoutNS = -1 },
		"too long":          func(r *LiveRequest) { r.Budget.TimeoutNS = model.Int64(24 * time.Hour) },
		"zero stream id":    func(r *LiveRequest) { z := model.ID{}; r.ResumeStreamID = &z },
	} {
		req := e.req(`{app="web"}`, project)
		mutate(&req)
		if _, err := e.svc.CreateLiveTicket(e.ctx, scope, req); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if e.feed.subscribes.Load() != 0 {
		t.Fatal("an invalid request reached the feed")
	}
}

func TestLiveSubscribeFailureIsTypedAndReleases(t *testing.T) {
	e := newLiveEnv(t, nil)
	_, project, _, scope := fixture(t, e)
	e.feed.subErr = model.Fail(model.TooLarge)
	if _, err := e.open(t, scope, e.req(`{app="web"}`, project), nil); faultCode(err) != model.TooLarge {
		t.Fatalf("subscribe failure must surface typed: %v", err)
	}
	e.settle2(t)
}

// settle2 is settle for paths where the feed never created an iterator.
func (e *liveEnv) settle2(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var u LiveUsage
	for time.Now().Before(deadline) {
		u = e.svc.Usage()
		if u.Streams == 0 && u.Goroutines == 0 && u.MemoryUsed == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("not idle: %+v", u)
}

func TestLiveFeedErrorIsTerminalAfterBufferedRecords(t *testing.T) {
	e := newLiveEnv(t, nil)
	_, project, _, scope := fixture(t, e)
	it, _ := e.mustOpen(t, scope, e.req(`{app="web"}`, project), nil)
	defer it.Close()
	feed := e.feed.last()
	feed.push(rowsPage(t, project, model.NewID(), 101, "kept"))
	feed.fail(model.Fail(model.Unavailable))
	wantRecord(t, nextEvent(t, it), "kept")
	ev := nextEvent(t, it)
	if ev.Type != LiveError || ev.Reason != reasonFeedError || ev.Failure == nil {
		t.Fatalf("a feed failure must be a typed terminal event: %+v", ev)
	}
	wantEOF(t, it)
	it.Close()
	e.settle(t)
}

func (it *fakeIter) fail(err error) { it.errs <- err }

// TestLiveTeardownReleasesEverything walks every end of a stream and requires
// the same idle state: no stream, iterator, charge, attachment or goroutine, and
// every subscription closed exactly once.
func TestLiveTeardownReleasesEverything(t *testing.T) {
	before := runtime.NumGoroutine()
	ends := map[string]func(t *testing.T, e *liveEnv, it LiveIterator, project model.ID){
		"service close": func(t *testing.T, e *liveEnv, it LiveIterator, _ model.ID) { _ = e.svc.Close() },
		"idle expiry": func(t *testing.T, e *liveEnv, it LiveIterator, _ model.ID) {
			it.Close()
			e.advance(e.cfg.ReplayWindow + time.Second)
		},
		"deletion": func(t *testing.T, e *liveEnv, it LiveIterator, _ model.ID) {
			e.deletes.bump.Add(1)
			for {
				if ev, err := it.Next(context.Background()); err != nil || ev.Terminal() {
					return
				}
			}
		},
		"revoked feed page": func(t *testing.T, e *liveEnv, it LiveIterator, _ model.ID) {
			e.feed.last().push(storage.ChangePage{Revoked: true})
			for {
				if ev, err := it.Next(context.Background()); err != nil || ev.Terminal() {
					return
				}
			}
		},
		"close then expire with buffered data": func(t *testing.T, e *liveEnv, it LiveIterator, project model.ID) {
			e.feed.last().push(rowsPage(t, project, model.NewID(), 101, "x", "y", "z"))
			waitSequence(t, e, feedStream(t, e), 3)
			it.Close()
			e.advance(e.cfg.ReplayWindow + time.Second)
		},
	}
	for name, end := range ends {
		t.Run(name, func(t *testing.T) {
			e := newLiveEnv(t, nil)
			_, project, _, scope := fixture(t, e)
			it, _ := e.mustOpen(t, scope, e.req(`{app="web"}`, project), nil)
			end(t, e, it, project)
			it.Close()
			it.Close() // idempotent
			e.settle(t)
		})
	}
	t.Run("cancelled Next does not end the stream", func(t *testing.T) {
		e := newLiveEnv(t, nil)
		_, project, _, scope := fixture(t, e)
		it, _ := e.mustOpen(t, scope, e.req(`{app="web"}`, project), nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := it.Next(ctx); faultCode(err) != model.Cancelled {
			t.Fatalf("cancelled Next must be a typed Cancelled: %v", err)
		}
		e.feed.last().push(rowsPage(t, project, model.NewID(), 101, "still alive"))
		wantRecord(t, nextEvent(t, it), "still alive")
		it.Close()
		_ = e.svc.Close()
		e.settle(t)
	})
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before+2 {
		buf := make([]byte, 1<<16)
		n := runtime.Stack(buf, true)
		t.Fatalf("goroutines leaked: %d before, %d after\n%s", before, after, buf[:n])
	}
}

func TestLiveClosedServiceRefuses(t *testing.T) {
	e := newLiveEnv(t, nil)
	_, project, _, scope := fixture(t, e)
	tk, err := e.svc.CreateLiveTicket(e.ctx, scope, e.req(`{app="web"}`, project))
	if err != nil {
		t.Fatal(err)
	}
	_ = e.svc.Close()
	if _, err := e.svc.Live(e.ctx, scope, tk.ID, nil); faultCode(err) != model.Unavailable {
		t.Fatalf("closed service must refuse attachments: %v", err)
	}
	if _, err := e.svc.CreateLiveTicket(e.ctx, scope, e.req(`{app="web"}`, project)); faultCode(err) != model.Unavailable {
		t.Fatalf("closed service must refuse tickets: %v", err)
	}
}

func TestNewLiveServiceValidates(t *testing.T) {
	f := newFx(t)
	reg := testRegistry(t)
	feed := &fakeFeed{}
	for name, build := range map[string]func() (*LiveService, error){
		"nil feed":     func() (*LiveService, error) { return NewLiveService(nil, f.svc, reg, testLimits()) },
		"nil policy":   func() (*LiveService, error) { return NewLiveService(feed, nil, reg, testLimits()) },
		"nil registry": func() (*LiveService, error) { return NewLiveService(feed, f.svc, nil, testLimits()) },
		"bad limits":   func() (*LiveService, error) { return NewLiveService(feed, f.svc, reg, Limits{}) },
		"bad live limits": func() (*LiveService, error) {
			l := DefaultLiveLimits()
			l.ReplayWindow = 0
			return NewLiveService(feed, f.svc, reg, testLimits(), WithLiveLimits(l))
		},
	} {
		if _, err := build(); faultCode(err) != model.Invalid {
			t.Fatalf("%s: want Invalid, got %v", name, err)
		}
	}
}

// gateKey marks a context whose delete-generation read parks while the gate is
// armed. Only the test's own Next call carries it, so the guard and pump
// goroutines never trip the gate.
type gateKey struct{}

type gateDeletes struct {
	inner   auth.DeleteGenerations
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func newGateDeletes(inner auth.DeleteGenerations) *gateDeletes {
	return &gateDeletes{inner: inner, entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *gateDeletes) DeleteGeneration(ctx context.Context, org model.ID, projects []model.ID) (uint64, error) {
	if ctx.Value(gateKey{}) != nil && g.armed.CompareAndSwap(true, false) {
		close(g.entered)
		<-g.release
	}
	return g.inner.DeleteGeneration(ctx, org, projects)
}

// panicPolicy panics once, in a stream worker (never in a call that carries the
// gate key), when armed.
type panicPolicy struct {
	inner Revalidator
	armed atomic.Bool
}

func (p *panicPolicy) Revalidate(ctx context.Context, scope auth.Scope) error {
	if ctx.Value(gateKey{}) == nil && p.armed.CompareAndSwap(true, false) {
		panic("SECRET-ROW-CONTENT injected guard panic")
	}
	return p.inner.Revalidate(ctx, scope)
}

// rebuild replaces the environment's service with one over the given policy and
// delete-generation source (the real ones wrapped by a test seam).
func (e *liveEnv) rebuild(t *testing.T, policy Revalidator, deletes auth.DeleteGenerations) {
	t.Helper()
	_ = e.svc.Close()
	svc, err := NewLiveService(e.feed, policy, testRegistry(t), testLimits(), WithLiveDeleteGenerations(deletes), WithLiveLimits(e.cfg), WithLiveClock(func() time.Time { return time.Unix(0, e.now.Load()) }))
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	t.Cleanup(func() { _ = svc.Close() })
}

func (e *liveEnv) streamByID(id LiveStreamID) *liveStream {
	e.svc.mu.Lock()
	defer e.svc.mu.Unlock()
	return e.svc.streams[id]
}

// A panic in the pump or guard worker ends only that stream with a typed
// terminal event that carries neither the panic value nor row content; other
// streams on the same service keep working and nothing leaks.
func TestLivePanicIsContainedToOneStream(t *testing.T) {
	for _, mode := range []string{"pump", "guard"} {
		t.Run(mode, func(t *testing.T) {
			e := newLiveEnv(t, nil)
			org, ps := e.newOrg("panic org", 1)
			project := ps[0]
			alice := e.user(org, "alice@example.test", ps, auth.Read)
			bob := e.user(org, "bob@example.test", ps, auth.Read)
			scope := e.scope(alice, org, project)
			policy := &panicPolicy{inner: e.fx.svc}
			e.rebuild(t, policy, e.deletes)
			req := e.req(`{app="web"}`, project)
			baseline := runtime.NumGoroutine()
			victim, vopen := e.mustOpen(t, scope, req, nil)
			var bystander LiveIterator
			var bystanderFeed *fakeIter
			if mode == "pump" {
				bystander, _ = e.mustOpen(t, e.scope(bob, org, project), req, nil)
				bystanderFeed = e.feed.last()
				close(e.feed.iters[0].trip)
			} else {
				policy.armed.Store(true)
			}
			ev := nextEvent(t, victim)
			if ev.Type != LiveError || ev.Reason != reasonInternal || ev.Failure == nil || ev.Failure.Code != string(model.Unavailable) || ev.StreamID != vopen.StreamID {
				t.Fatalf("a worker panic must end its stream with a typed internal error: %+v", ev)
			}
			raw, _ := json.Marshal(ev)
			if strings.Contains(string(raw), "SECRET") || strings.Contains(string(raw), "panic") {
				t.Fatalf("the panic value leaked into the event: %s", raw)
			}
			wantEOF(t, victim)
			victim.Close()
			if bystander != nil {
				bystanderFeed.push(rowsPage(t, project, model.NewID(), 101, "bystander survives"))
				wantRecord(t, nextEvent(t, bystander), "bystander survives")
				bystander.Close()
			}
			// The service is still usable for new streams.
			fresh, _ := e.mustOpen(t, scope, req, nil)
			e.feed.last().push(rowsPage(t, project, model.NewID(), 101, "new stream works"))
			wantRecord(t, nextEvent(t, fresh), "new stream works")
			fresh.Close()
			_ = e.svc.Close()
			e.settle(t)
			deadline := time.Now().Add(3 * time.Second)
			for runtime.NumGoroutine() > baseline+2 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if got := runtime.NumGoroutine(); got > baseline+2 {
				t.Fatalf("goroutines leaked after a contained panic: %d before, %d after", baseline, got)
			}
		})
	}
}

// A corrupt row ends the stream with its own reason, not the generic feed_error.
func TestLiveTerminalReasonForCorruptRow(t *testing.T) {
	e := newLiveEnv(t, nil)
	_, project, _, scope := fixture(t, e)
	it, _ := e.mustOpen(t, scope, e.req(`{app="web"}`, project), nil)
	e.feed.last().push(rowsPage(t, model.NewID(), model.NewID(), 101, "row of a project the stream never named"))
	ev := nextEvent(t, it)
	if ev.Type != LiveError || ev.Reason != reasonCorrupt || ev.Failure == nil || ev.Failure.Code != string(model.Corrupt) || ev.Entry != nil {
		t.Fatalf("a corrupt row must end the stream as corrupt_record: %+v", ev)
	}
	wantEOF(t, it)
	it.Close()
	e.settle(t)
}

// A revocation that commits after the next event was picked and while its
// per-event check is running must not let that event escape.
func TestLiveRevokeBetweenPickAndRelease(t *testing.T) {
	e := newLiveEnv(t, nil)
	_, project, _, scope := fixture(t, e)
	gate := newGateDeletes(e.deletes)
	e.rebuild(t, e.fx.svc, gate)
	it, open := e.mustOpen(t, scope, e.req(`{app="web"}`, project), nil)
	e.feed.last().push(rowsPage(t, project, model.NewID(), 101, "must not escape"))
	waitSequence(t, e, open.StreamID, 1)
	gate.armed.Store(true)
	type result struct {
		ev  LiveEvent
		err error
	}
	done := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), gateKey{}, true), 5*time.Second)
		defer cancel()
		ev, err := it.Next(ctx)
		done <- result{ev, err}
	}()
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the per-event check never ran")
	}
	// The event is picked and its check is parked: commit the revocation now.
	e.feed.last().push(storage.ChangePage{Revoked: true})
	st := e.streamByID(open.StreamID)
	for deadline := time.Now().Add(3 * time.Second); ; {
		st.mu.Lock()
		committed := st.terminal != nil && st.preempt
		st.mu.Unlock()
		if committed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the revocation never committed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(gate.release)
	r := <-done
	if r.err != nil || r.ev.Type != LiveRevoke || r.ev.Entry != nil {
		t.Fatalf("no event may be delivered after a committed revocation, got %+v err %v", r.ev, r.err)
	}
	wantEOF(t, it)
	it.Close()
	e.settle(t)
}

// The consumer whose next wanted sequence is exactly the last evicted one gets
// the explicit gap (From == To), and a consumer just past the window gets its
// record: no unsigned underflow, no starvation.
func TestLiveEvictionBoundary(t *testing.T) {
	e := newLiveEnv(t, nil)
	_, project, _, scope := fixture(t, e)
	src := model.NewID()
	req := e.req(`{app="web"}`, project)
	req.Budget.MaxReturned = 2
	it, open := e.mustOpen(t, scope, req, nil)
	it.Close()
	feed := e.feed.last()
	for i := 0; i < 4; i++ {
		feed.push(rowsPage(t, project, src, uint64(101+i), "r"+strconv.Itoa(i)))
	}
	waitSequence(t, e, open.StreamID, 4) // sequences 1 and 2 are evicted; 3 and 4 remain
	resume := req
	resume.ResumeStreamID = &open.StreamID
	attach := func(after uint64) LiveIterator {
		it2, _ := e.mustOpen(t, scope, resume, &after)
		return it2
	}
	one := attach(1) // next wanted sequence 2 is exactly the last evicted one
	gap := nextEvent(t, one)
	if gap.Type != LiveGap || gap.Gap == nil || gap.Gap.Reason != GapReplayEvicted || gap.Gap.FromSequence != 2 || gap.Gap.ToSequence != 2 || gap.Sequence != 2 {
		t.Fatalf("the boundary consumer must get a gap with From==To==2: %+v", gap)
	}
	wantRecord(t, nextEvent(t, one), "r2")
	wantRecord(t, nextEvent(t, one), "r3")
	one.Close()
	zero := attach(0)
	if gap := nextEvent(t, zero); gap.Type != LiveGap || gap.Gap.FromSequence != 1 || gap.Gap.ToSequence != 2 {
		t.Fatalf("both evicted sequences must be reported: %+v", gap)
	}
	zero.Close()
	two := attach(2) // first retained sequence 3: no loss, no gap
	wantRecord(t, nextEvent(t, two), "r2")
	wantRecord(t, nextEvent(t, two), "r3")
	two.Close()
}

// A principal who logged in again presents the old stream's identifier and
// Last-Event-ID: a different visibility fingerprint is a different owner, so
// the old replay buffer is never attached.
func TestLiveResumeRefusesAnotherLoginOfTheSamePrincipal(t *testing.T) {
	e := newLiveEnv(t, nil)
	org, ps := e.newOrg("relogin org", 1)
	project := ps[0]
	alice := e.user(org, "alice@example.test", ps, auth.Read)
	old := e.scope(alice, org, project)
	login, err := e.fx.svc.Login(e.ctx, "alice@example.test", "query reader password", "")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := e.fx.svc.Authenticate(e.ctx, login.Token)
	if err != nil {
		t.Fatal(err)
	}
	again := e.scope(person{id: alice.id, cred: cred}, org, project)
	if old.PrincipalID() != again.PrincipalID() || old.VisibilityFingerprint() == again.VisibilityFingerprint() {
		t.Fatal("precondition: the same principal must have a different fingerprint after another login")
	}
	req := e.req(`{app="web"}`, project)
	it, open := e.mustOpen(t, old, req, nil)
	defer it.Close()
	e.feed.last().push(rowsPage(t, project, model.NewID(), 101, "old session only"))
	first := nextEvent(t, it)
	wantRecord(t, first, "old session only")
	resume := req
	resume.ResumeStreamID = &open.StreamID
	after := uint64(first.Sequence)
	it2, open2 := e.mustOpen(t, again, resume, &after)
	defer it2.Close()
	if open2.StreamID == open.StreamID {
		t.Fatal("a different login attached to the old stream")
	}
	gap := nextEvent(t, it2)
	if gap.Type != LiveGap || gap.Gap.Reason != GapReplayExpired || gap.Gap.FromSequence != first.Sequence+1 {
		t.Fatalf("a different login must get a fresh stream with a replay_expired gap: %+v", gap)
	}
	quiet(t, it2, 100*time.Millisecond)
}

// Eviction whose window straddles a feed-gap event keeps the exact After bound
// that the gap event itself established.
func TestLiveEvictionKeepsGapEventBound(t *testing.T) {
	e := newLiveEnv(t, nil)
	_, project, _, scope := fixture(t, e)
	src := model.NewID()
	req := e.req(`{app="web"}`, project)
	req.Budget.MaxReturned = 2
	it, open := e.mustOpen(t, scope, req, nil)
	it.Close()
	feed := e.feed.last()
	feed.push(rowsPage(t, project, src, 101, "s1"))
	feed.push(storage.ChangePage{Gap: &storage.ChangeGap{After: cur(102), Through: cur(105), Reason: "slow_consumer"}, Cursors: cur(105)})
	feed.push(rowsPage(t, project, src, 106, "s3"))
	feed.push(rowsPage(t, project, src, 107, "s4"))
	feed.push(rowsPage(t, project, src, 108, "s5"))
	waitSequence(t, e, open.StreamID, 5) // 1..3 evicted; the gap is sequence 2
	resume := req
	resume.ResumeStreamID = &open.StreamID
	after := uint64(2)
	it2, _ := e.mustOpen(t, scope, resume, &after)
	defer it2.Close()
	gap := nextEvent(t, it2)
	if gap.Type != LiveGap || gap.Gap.Reason != GapReplayEvicted || gap.Gap.FromSequence != 3 || gap.Gap.ToSequence != 3 {
		t.Fatalf("unexpected eviction gap: %+v", gap)
	}
	if len(gap.Gap.After) != 1 || gap.Gap.After[0].Index != 105 || len(gap.Gap.Through) != 1 || gap.Gap.Through[0].Index != 106 {
		t.Fatalf("the gap must keep the feed gap's exact bound (after 105 through 106): after %+v through %+v", gap.Gap.After, gap.Gap.Through)
	}
}

// Expired tickets that were only minted, never used, disappear from the table.
func TestLiveExpiredTicketsArePurged(t *testing.T) {
	e := newLiveEnv(t, nil)
	_, project, _, scope := fixture(t, e)
	req := e.req(`{app="web"}`, project)
	for i := 0; i < 2; i++ {
		if _, err := e.svc.CreateLiveTicket(e.ctx, scope, req); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.svc.Usage().Tickets; n != 2 {
		t.Fatalf("two live tickets expected, have %d", n)
	}
	e.advance(e.cfg.TicketTTL + time.Second)
	if _, err := e.svc.CreateLiveTicket(e.ctx, scope, req); err != nil {
		t.Fatal(err)
	}
	if n := e.svc.Usage().Tickets; n != 1 {
		t.Fatalf("expired mint-only tickets must be purged: %d tickets remain", n)
	}
}
