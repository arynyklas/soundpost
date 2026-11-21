// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"github.com/arynyklas/soundpost/internal/storage"
)

// http2Server serves the environment's handler over HTTPS with HTTP/2, the protocol every
// browser uses. In HTTP/2 the response write deadline is a per-stream timer that resets the
// stream when it fires, whether or not a write is blocked, so it must only ever be armed
// for the duration of a write.
func (e *liveEnv) http2Server() *httptest.Server {
	e.t.Helper()
	srv := httptest.NewUnstartedServer(e.server.Config.Handler)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	e.t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
	})
	return srv
}

// failingFeed is the real committed feed whose Next, once the subscription has been idle for
// `after`, reports that a shard stopped answering.
type failingFeed struct {
	query.ChangeSubscriber
	after time.Duration
}

func (f failingFeed) Subscribe(ctx context.Context, scope auth.Scope, req storage.SubscribeRequest) (storage.ChangeIterator, error) {
	it, err := f.ChangeSubscriber.Subscribe(ctx, scope, req)
	if err != nil {
		return nil, err
	}
	return &failingIterator{ChangeIterator: it, after: f.after}, nil
}

type failingIterator struct {
	storage.ChangeIterator
	after time.Duration
}

func (it *failingIterator) Next(ctx context.Context) (storage.ChangePage, error) {
	select {
	case <-time.After(it.after):
		return storage.ChangePage{}, model.Fail(model.Unavailable)
	case <-ctx.Done():
		return storage.ChangePage{}, model.Fail(model.Cancelled)
	}
}

// A stream that stays quiet for longer than the per-frame write deadline is not a stalled
// reader: nothing is being written, so the deadline has nothing to expire on. Over HTTP/2 the
// server must therefore keep delivering what it has to say (here: heartbeats) on a stream that
// was idle for several deadlines.
func TestLiveIdleStreamOutlivesTheWriteDeadlineOverHTTP2(t *testing.T) {
	const deadline = 300 * time.Millisecond
	t.Cleanup(httpapi.SetLiveWriteTimeoutForTest(deadline))
	e := newLiveEnv(t, func(l *query.LiveLimits) { l.Heartbeat = 4 * deadline })
	p := model.NewID()
	org := e.org("live org", p)
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, p, true, auth.Read)
	srv := e.http2Server()
	conn, _, _ := e.connectOn(srv, alice, e.mustTicket(alice, e.body(org, p, `{app="web"}`)), "")
	defer conn.close()
	if conn.resp.ProtoMajor != 2 {
		t.Fatalf("the stream must run over HTTP/2: %s", conn.resp.Proto)
	}
	conn.expect("open")
	conn.expect("heartbeat")
	conn.expect("heartbeat")
}

// When the change feed fails while the stream is idle for longer than the write deadline, the
// consumer is still told, with the stated terminal error event, before the stream closes.
func TestLiveFeedErrorIsDeliveredAfterAnIdleStretchOverHTTP2(t *testing.T) {
	const deadline = 300 * time.Millisecond
	t.Cleanup(httpapi.SetLiveWriteTimeoutForTest(deadline))
	e := newLiveEnv(t, func(l *query.LiveLimits) { l.Heartbeat = time.Hour })
	e.feed.inner = failingFeed{ChangeSubscriber: e.app.Storage, after: 3 * deadline}
	p := model.NewID()
	org := e.org("live org", p)
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, p, true, auth.Read)
	srv := e.http2Server()
	conn, _, _ := e.connectOn(srv, alice, e.mustTicket(alice, e.body(org, p, `{app="web"}`)), "")
	defer conn.close()
	if conn.resp.ProtoMajor != 2 {
		t.Fatalf("the stream must run over HTTP/2: %s", conn.resp.Proto)
	}
	conn.expect("open")
	ev := conn.expect("error")
	if ev.Data.Reason != "feed_error" || ev.Data.Failure == nil {
		t.Fatalf("a feed failure is a stated feed_error with its failure: %+v", ev.Data)
	}
	conn.ended()
}
