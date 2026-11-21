// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// gatedFeed is a change feed whose pump is slow: a page is handed to the stream only when the test lets
// it through (the real feed spends a read fence and a page read on every page). Its iterator keeps the
// accounting of the storage engine's (WaitCaughtUp returns once the stream has come back for more after
// every page that was queued when it was called).
type gatedFeed struct {
	mu    sync.Mutex
	iters []*gatedIter
}

type gatedIter struct {
	pages  chan storage.ChangePage
	gate   chan struct{}
	ctx    context.Context
	closed chan struct{}
	once   sync.Once

	mu              sync.Mutex
	queued, settled uint64
	holding         bool
	moved           chan struct{}
}

func (f *gatedFeed) Subscribe(ctx context.Context, _ auth.Scope, _ storage.SubscribeRequest) (storage.ChangeIterator, error) {
	it := &gatedIter{pages: make(chan storage.ChangePage, 64), gate: make(chan struct{}, 64), ctx: ctx, closed: make(chan struct{}), moved: make(chan struct{})}
	f.mu.Lock()
	f.iters = append(f.iters, it)
	f.mu.Unlock()
	return it, nil
}

func (f *gatedFeed) last() *gatedIter {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.iters[len(f.iters)-1]
}

func (it *gatedIter) push(p storage.ChangePage) {
	it.mu.Lock()
	it.queued++
	it.mu.Unlock()
	it.pages <- p
}

// settleLocked marks the page the consumer held as done.
func (it *gatedIter) settleLocked() {
	if it.holding {
		it.holding = false
		it.settled++
		close(it.moved)
		it.moved = make(chan struct{})
	}
}

func (it *gatedIter) Next(ctx context.Context) (storage.ChangePage, error) {
	it.mu.Lock()
	it.settleLocked()
	it.mu.Unlock()
	select {
	case p := <-it.pages:
		select {
		case <-it.gate:
		case <-ctx.Done():
			return storage.ChangePage{}, model.Fail(model.Cancelled)
		case <-it.closed:
			return storage.ChangePage{}, io.ErrClosedPipe
		}
		it.mu.Lock()
		it.holding = true
		it.mu.Unlock()
		return p, nil
	case <-ctx.Done():
		return storage.ChangePage{}, model.Fail(model.Cancelled)
	case <-it.closed:
		return storage.ChangePage{}, io.ErrClosedPipe
	}
}

func (it *gatedIter) WaitCaughtUp(ctx context.Context) error {
	it.mu.Lock()
	target := it.queued
	it.mu.Unlock()
	for {
		it.mu.Lock()
		done, moved := it.settled >= target, it.moved
		it.mu.Unlock()
		if done {
			return nil
		}
		select {
		case <-moved:
		case <-ctx.Done():
			return model.Fail(model.Timeout)
		case <-it.closed:
			return nil
		}
	}
}

func (it *gatedIter) Watermarks() []model.Cursor { return cur(100) }

func (it *gatedIter) Close() error {
	it.once.Do(func() { close(it.closed) })
	return nil
}

// A client that reconnects right after an acknowledged write must be told the replay position of a
// buffer that has seen the write. The feed hands a commit to the stream some milliseconds after it was
// acknowledged, so a resumed attach that does not wait for the commits the feed already holds picks its
// first event from a buffer that is behind: here a record that the three pages push out of the replay
// buffer a moment later, where the eviction gap belongs (the live smoke's reconnect-after-eviction, which
// then left two records unread and had the revocation step read them).
func TestLiveResumeWaitsForTheFeedToHandOverWhatWasAcknowledged(t *testing.T) {
	f := newFx(t)
	feed := &gatedFeed{}
	cfg := DefaultLiveLimits()
	cfg.Heartbeat = time.Hour
	svc, err := NewLiveService(feed, f.svc, testRegistry(t), testLimits(), WithLiveDeleteGenerations(f.deletes), WithLiveLimits(cfg), WithLiveClock(func() time.Time { return time.Unix(0, f.now.Load()) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	e := &liveEnv{fx: f, feed: &fakeFeed{}, svc: svc, cfg: cfg}
	_, project, _, scope := fixture(t, e)
	src := model.NewID()
	req := e.req(`{app="web"}`, project)
	req.Budget.MaxReturned = 2
	it, open := e.mustOpen(t, scope, req, nil)
	it.Close()
	slow := feed.last()
	for i, line := range []string{"s1", "s2", "s3"} {
		slow.push(rowsPage(t, project, src, uint64(101+i), line))
	}

	resume := req
	resume.ResumeStreamID = &open.StreamID
	after := uint64(0)
	type attached struct {
		it  LiveIterator
		err error
	}
	got := make(chan attached, 1)
	go func() {
		it2, err := e.open(t, scope, resume, &after)
		got <- attached{it2, err}
	}()
	select {
	case a := <-got:
		if a.it != nil {
			a.it.Close()
		}
		t.Fatalf("the resumed attach returned while the feed still held three acknowledged commits the stream had not absorbed (err %v)", a.err)
	case <-time.After(300 * time.Millisecond):
	}
	for range 3 {
		slow.gate <- struct{}{}
	}
	var a attached
	select {
	case a = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("the resumed attach did not return after the feed handed the commits over")
	}
	if a.err != nil {
		t.Fatal(a.err)
	}
	defer a.it.Close()
	if ev := nextEvent(t, a.it); ev.Type != LiveOpen || ev.StreamID != open.StreamID {
		t.Fatalf("want the open of the resumed stream, got %+v", ev)
	}
	gap := nextEvent(t, a.it)
	if gap.Type != LiveGap || gap.Gap == nil || gap.Gap.Reason != GapReplayEvicted || gap.Gap.FromSequence != 1 || gap.Gap.ToSequence != 1 {
		t.Fatalf("want the replay_evicted gap for sequence 1 first, got %+v", gap)
	}
	wantRecord(t, nextEvent(t, a.it), "s2")
	wantRecord(t, nextEvent(t, a.it), "s3")
}

// The wait is a bound, not a promise: a feed that never hands its commits over (a stuck page read) does not
// keep a reconnecting client from the stream it can still use.
func TestLiveResumeAttachesWhenTheFeedStaysBehind(t *testing.T) {
	f := newFx(t)
	feed := &gatedFeed{}
	cfg := DefaultLiveLimits()
	cfg.Heartbeat = time.Hour
	svc, err := NewLiveService(feed, f.svc, testRegistry(t), testLimits(), WithLiveDeleteGenerations(f.deletes), WithLiveLimits(cfg), WithLiveClock(func() time.Time { return time.Unix(0, f.now.Load()) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	e := &liveEnv{fx: f, feed: &fakeFeed{}, svc: svc, cfg: cfg}
	_, project, _, scope := fixture(t, e)
	req := e.req(`{app="web"}`, project)
	it, open := e.mustOpen(t, scope, req, nil)
	it.Close()
	feed.last().push(rowsPage(t, project, model.NewID(), 101, "stuck"))
	resume := req
	resume.ResumeStreamID = &open.StreamID
	after := uint64(0)
	start := time.Now()
	it2, err := e.open(t, scope, resume, &after)
	if err != nil {
		t.Fatal(err)
	}
	defer it2.Close()
	if d := time.Since(start); d < resumeCatchUpWait/2 || d > resumeCatchUpWait+3*time.Second {
		t.Fatalf("the resumed attach took %v with the feed stuck, want about the %v bound", d, resumeCatchUpWait)
	}
	if ev := nextEvent(t, it2); ev.Type != LiveOpen {
		t.Fatalf("want open, got %+v", ev)
	}
	gap := nextEvent(t, it2)
	if gap.Type != LiveGap || gap.Gap == nil || gap.Gap.Reason != GapFeedCatchUp || gap.Gap.FromSequence != 1 || len(gap.Gap.Through) != 1 {
		t.Fatalf("a feed that stayed behind must be reported as a feed_catch_up gap, not left unsaid: %+v", gap)
	}
}
