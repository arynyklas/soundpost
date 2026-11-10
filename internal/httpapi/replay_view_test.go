// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"soundpost/internal/replays"
)

// scriptedStream is a labelled test double of replays.ReplayStream. It does NOT
// revalidate anything on its own (unlike the real service), so a test can prove
// the HTTP handler's own fence. gate, when set, releases one Next per receive.
type scriptedStream struct {
	mu     sync.Mutex
	events func(i int) (replays.Event, error)
	gate   chan struct{}
	i      int
	closed atomic.Bool
}

func (s *scriptedStream) Next(ctx context.Context) (replays.Event, error) {
	if s.gate != nil {
		select {
		case <-s.gate:
		case <-ctx.Done():
			return replays.Event{}, ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ev, err := s.events(s.i)
	s.i++
	return ev, err
}
func (s *scriptedStream) Close() error { s.closed.Store(true); return nil }

type fakeReplays struct {
	mu     sync.Mutex
	calls  int
	scope  auth.Scope
	replay model.ID
	window replays.ReplayWindow
	answer func() (replays.ReplayStream, error)
}

func (f *fakeReplays) Read(_ context.Context, scope auth.Scope, replay model.ID, window replays.ReplayWindow) (replays.ReplayStream, error) {
	f.mu.Lock()
	f.calls++
	f.scope, f.replay, f.window = scope, replay, window
	f.mu.Unlock()
	return f.answer()
}
func (f *fakeReplays) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

func deltaEvent(seq uint64) replays.Event {
	return replays.Event{Kind: replays.EventDelta, Sequence: seq, Policy: 7, Chunk: &model.ReplayChunk{Replay: model.ID{1}, Session: model.ID{2}, Clock: model.TraceClock{Domain: model.ClockDomain{Host: model.ID{3}, Boot: model.ID{4}, Runtime: model.ID{5}}}, Recorder: "1", Sequence: model.Uint64(seq), CheckpointSequence: 1, Nodes: []model.MaskedNode{}, Events: []model.MaskedEvent{}, PolicyRevision: 7}}
}

type rpEnv struct {
	*isoEnv
	srv *httptest.Server
}

func newRpEnv(t *testing.T, reader httpapi.ReplayReader, configure ...func(*httpapi.Replays) *httpapi.Replays) *rpEnv {
	t.Helper()
	e := &rpEnv{isoEnv: newIsoEnv(t)}
	h := httpapi.NewReplays(reader)
	for _, c := range configure {
		h = c(h)
	}
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterReplayRoutes(mux, e.app.Auth, h)
		httpapi.RegisterIngestRoutes(mux, e.app.Auth, e.app.Ingest)
	}).Handler)
	t.Cleanup(e.srv.Close)
	return e
}

func replayBody(org, project, replay model.ID) map[string]any {
	return map[string]any{"org": org.String(), "project": project.String(), "replay": replay.String()}
}

func (e *rpEnv) open(who person, body any, mutate func(*http.Request)) *http.Response {
	e.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		e.t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/replays/stream", bytes.NewReader(raw))
	if who.Session.Token != "" {
		req.Header.Set("Cookie", "__Host-soundpost="+who.Session.Token)
		req.Header.Set("X-CSRF-Token", who.Session.CSRF)
	}
	req.Header.Set("Origin", e.srv.URL)
	req.Header.Set("Content-Type", "application/json")
	if mutate != nil {
		mutate(req)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

type lineReader struct {
	t *testing.T
	s *bufio.Scanner
}

func newLines(t *testing.T, resp *http.Response) *lineReader {
	s := bufio.NewScanner(resp.Body)
	s.Buffer(make([]byte, 1<<20), 1<<24)
	return &lineReader{t, s}
}

// next returns the next line, or ok=false at the end of the body.
func (l *lineReader) next() (httpapi.ReplayLine, string, bool) {
	l.t.Helper()
	if !l.s.Scan() {
		return httpapi.ReplayLine{}, "", false
	}
	var line httpapi.ReplayLine
	if err := json.Unmarshal(l.s.Bytes(), &line); err != nil {
		l.t.Fatalf("not a replay line: %v\n%s", err, l.s.Text())
	}
	return line, l.s.Text(), true
}

func (l *lineReader) all() []httpapi.ReplayLine {
	l.t.Helper()
	var out []httpapi.ReplayLine
	for {
		line, _, ok := l.next()
		if !ok {
			return out
		}
		out = append(out, line)
	}
}

func types(lines []httpapi.ReplayLine) string {
	var out []string
	for _, l := range lines {
		out = append(out, l.Type)
	}
	return strings.Join(out, " ")
}

func TestReplayStreamScopeFirstAndIndistinguishable(t *testing.T) {
	replay := model.NewID()
	src := &fakeReplays{}
	src.answer = func() (replays.ReplayStream, error) {
		return &scriptedStream{events: func(i int) (replays.Event, error) {
			switch i {
			case 0:
				return replays.Event{Kind: replays.EventCheckpoint, Sequence: 1, Chunk: &model.ReplayChunk{Replay: model.ID{1}, Session: model.ID{2}, Clock: model.TraceClock{Domain: model.ClockDomain{Host: model.ID{3}, Boot: model.ID{4}, Runtime: model.ID{5}}}, Recorder: "1", Sequence: 1, CheckpointSequence: 1}}, nil
			case 1:
				return deltaEvent(2), nil
			}
			return replays.Event{}, io.EOF
		}}, nil
	}
	e := newRpEnv(t, src)
	pA, pB, pX := model.NewID(), model.NewID(), model.NewID()
	orgA, orgB := e.org("replay A", pA, pB), e.org("replay B", pX)
	reader := e.user(orgA, "replay-reader@example.test")
	e.grant(orgA, reader, pA, true, auth.Read, httpapi.ReplayRead)
	outsider := e.user(orgB, "replay-outsider@example.test")
	e.grant(orgB, outsider, pX, true, auth.Read, httpapi.ReplayRead)

	body := replayBody(orgA, pA, replay)
	body["from"], body["to"] = "2", "9"
	resp := e.open(reader, body, nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/x-ndjson") || resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("reader: %d %v", resp.StatusCode, resp.Header)
	}
	lines := newLines(t, resp).all()
	if types(lines) != "open checkpoint delta end" {
		t.Fatalf("lines = %s", types(lines))
	}
	open := lines[0]
	if open.Org == nil || *open.Org != orgA || open.Project == nil || *open.Project != pA || open.Replay == nil || *open.Replay != replay {
		t.Fatalf("open line names another scope: %+v", open)
	}
	if lines[2].Chunk == nil || lines[2].Chunk.Sequence != 2 || lines[2].Policy == nil || *lines[2].Policy != 7 {
		t.Fatalf("delta line lost its chunk or policy revision: %+v", lines[2])
	}
	if src.scope.OrgID() != orgA || !src.scope.AllowsProject(pA) || src.scope.AllowsProject(pB) || src.scope.Permission() != auth.Read || src.replay != replay || src.window != (replays.ReplayWindow{From: 2, To: 9}) {
		t.Fatalf("service saw a different request than the scoped one: %+v", src)
	}

	before := src.count()
	var want string
	for name, c := range map[string]struct {
		who      person
		org, prj model.ID
	}{
		"other org's member naming org A": {outsider, orgA, pA},
		"ungranted sibling project":       {reader, orgA, pB},
		"guessed project":                 {reader, orgA, model.NewID()},
		"guessed org":                     {reader, model.NewID(), pA},
		"org A's project under org B":     {reader, orgB, pX},
	} {
		resp := e.open(c.who, replayBody(c.org, c.prj, replay), nil)
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 404 {
			t.Fatalf("%s: %d %s", name, resp.StatusCode, raw)
		}
		got := denial(t, resp.StatusCode, raw)
		if want == "" {
			want = got
		} else if got != want {
			t.Fatalf("%s is distinguishable: %q vs %q", name, got, want)
		}
	}
	if src.count() != before {
		t.Fatal("the replay service was reached before scope was proven")
	}
}

func TestReplayStreamRejectsUncredentialedAndMalformedRequests(t *testing.T) {
	src := &fakeReplays{answer: func() (replays.ReplayStream, error) { t.Error("service reached"); return nil, io.EOF }}
	e := newRpEnv(t, src)
	p := model.NewID()
	org := e.org("replay req", p)
	reader := e.user(org, "replay-req@example.test")
	e.grant(org, reader, p, true, auth.Read, httpapi.ReplayRead)

	if resp := e.open(person{}, replayBody(org, p, model.NewID()), nil); resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Fatalf("no credential: %d", resp.StatusCode)
	}
	noCSRF := e.open(reader, replayBody(org, p, model.NewID()), func(r *http.Request) { r.Header.Del("X-CSRF-Token") })
	if noCSRF.StatusCode < 400 || noCSRF.StatusCode >= 500 {
		t.Fatalf("session without CSRF binding: %d", noCSRF.StatusCode)
	}
	for name, body := range map[string]map[string]any{
		"zero replay id":     {"org": org.String(), "project": p.String(), "replay": model.ID{}.String()},
		"zero project":       {"org": org.String(), "project": model.ID{}.String(), "replay": model.NewID().String()},
		"to before from":     {"org": org.String(), "project": p.String(), "replay": model.NewID().String(), "from": "9", "to": "3"},
		"caller-named scope": {"org": org.String(), "project": p.String(), "replay": model.NewID().String(), "scope": "x"},
	} {
		resp := e.open(reader, body, nil)
		if resp.StatusCode != 400 && resp.StatusCode != 422 {
			t.Fatalf("%s: %d", name, resp.StatusCode)
		}
	}
}

func TestReplayStreamNotWiredIsTypedNotAvailableAfterScope(t *testing.T) {
	e := newRpEnv(t, nil)
	pA, pX := model.NewID(), model.NewID()
	orgA, orgB := e.org("replay nw A", pA), e.org("replay nw B", pX)
	reader := e.user(orgA, "replay-nw@example.test")
	e.grant(orgA, reader, pA, true, auth.Read, httpapi.ReplayRead)

	lines := newLines(t, e.open(reader, replayBody(orgA, pA, model.NewID()), nil)).all()
	if len(lines) != 1 || lines[0].Type != "not_available" || lines[0].State != httpapi.StateNotAvailable || lines[0].Reason != httpapi.ReasonReplayServiceNotWired || lines[0].Chunk != nil {
		t.Fatalf("unwired = %+v", lines)
	}
	// A caller outside the scope learns nothing about wiring: it is the one not-found.
	outsider := e.user(orgB, "replay-nw-out@example.test")
	e.grant(orgB, outsider, pX, true, auth.Read, httpapi.ReplayRead)
	resp := e.open(outsider, replayBody(orgA, pA, model.NewID()), nil)
	if resp.StatusCode != 404 {
		t.Fatalf("outsider saw %d on an unwired service", resp.StatusCode)
	}
}

func TestReplayStreamRevokedMidStreamEndsBeforeAnotherChunk(t *testing.T) {
	gate := make(chan struct{})
	var stream *scriptedStream
	src := &fakeReplays{}
	src.answer = func() (replays.ReplayStream, error) {
		// This double never notices a revocation: only the handler's own fence can end the stream.
		stream = &scriptedStream{gate: gate, events: func(i int) (replays.Event, error) { return deltaEvent(uint64(i + 1)), nil }}
		return stream, nil
	}
	e := newRpEnv(t, src)
	p := model.NewID()
	org := e.org("replay revoke", p)
	reader := e.user(org, "replay-revoke@example.test")
	e.grant(org, reader, p, true, auth.Read, httpapi.ReplayRead)

	lines := newLines(t, e.open(reader, replayBody(org, p, model.NewID()), nil))
	if l, _, ok := lines.next(); !ok || l.Type != "open" {
		t.Fatalf("first line = %+v", l)
	}
	for seq := uint64(1); seq <= 2; seq++ {
		gate <- struct{}{}
		if l, _, ok := lines.next(); !ok || l.Type != "delta" || l.Sequence == nil || uint64(*l.Sequence) != seq {
			t.Fatalf("chunk %d line = %+v ok=%v", seq, l, ok)
		}
	}
	e.grant(org, reader, p, false, auth.Read)
	gate <- struct{}{} // the double now produces sequence 3, which must never be delivered
	l, raw, ok := lines.next()
	if !ok || l.Type != "revoke" || l.Reason != replays.ReasonAuthorityRevoked || l.Chunk != nil || strings.Contains(raw, "chunk") {
		t.Fatalf("after revocation: %q ok=%v", raw, ok)
	}
	if extra, _, more := lines.next(); more {
		t.Fatalf("a line followed the revoke: %+v", extra)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !stream.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !stream.closed.Load() {
		t.Fatal("the service stream was not closed after the revoke")
	}
}

func TestReplayStreamServiceRevokeAndDeletionEndWithTypedLine(t *testing.T) {
	for _, reason := range []string{replays.ReasonAuthorityRevoked, replays.ReasonDeleted} {
		src := &fakeReplays{}
		src.answer = func() (replays.ReplayStream, error) {
			return &scriptedStream{events: func(i int) (replays.Event, error) {
				switch i {
				case 0:
					return deltaEvent(1), nil
				case 1:
					return replays.Event{Kind: replays.EventRevoke, Sequence: 2, Reason: reason}, nil
				}
				return deltaEvent(uint64(i + 1)), nil // a misbehaving service must still never reach the browser
			}}, nil
		}
		e := newRpEnv(t, src)
		p := model.NewID()
		org := e.org("replay svc revoke", p)
		reader := e.user(org, "replay-svc@example.test")
		e.grant(org, reader, p, true, auth.Read, httpapi.ReplayRead)
		lines := newLines(t, e.open(reader, replayBody(org, p, model.NewID()), nil)).all()
		if types(lines) != "open delta revoke" || lines[2].Reason != reason || lines[2].Chunk != nil {
			t.Fatalf("%s: lines = %s %+v", reason, types(lines), lines)
		}
	}
}

func TestReplayStreamGapUnsupportedAndErrorLines(t *testing.T) {
	src := &fakeReplays{}
	src.answer = func() (replays.ReplayStream, error) {
		return &scriptedStream{events: func(i int) (replays.Event, error) {
			switch i {
			case 0:
				return replays.Event{Kind: replays.EventGap, Sequence: 4, Through: 5, Reason: replays.ReasonMissingChunk}, nil
			case 1:
				return replays.Event{Kind: replays.EventUnsupported, Sequence: 6, Through: 6, Reason: replays.ReasonRecorderVersion}, nil
			}
			return replays.Event{Kind: replays.EventError, Sequence: 7, Code: model.Unavailable}, nil
		}}, nil
	}
	e := newRpEnv(t, src)
	p := model.NewID()
	org := e.org("replay gap", p)
	reader := e.user(org, "replay-gap@example.test")
	e.grant(org, reader, p, true, auth.Read, httpapi.ReplayRead)
	lines := newLines(t, e.open(reader, replayBody(org, p, model.NewID()), nil)).all()
	if types(lines) != "open gap unsupported error" {
		t.Fatalf("lines = %s", types(lines))
	}
	g := lines[1]
	if g.Sequence == nil || *g.Sequence != 4 || g.Through == nil || *g.Through != 5 || g.Reason != replays.ReasonMissingChunk {
		t.Fatalf("gap line = %+v", g)
	}
	if lines[2].Reason != replays.ReasonRecorderVersion || lines[3].Code != string(model.Unavailable) {
		t.Fatalf("typed lines = %+v %+v", lines[2], lines[3])
	}
}

func TestReplayStreamIsBoundedByEventsAndBytes(t *testing.T) {
	endless := func() (replays.ReplayStream, error) {
		return &scriptedStream{events: func(i int) (replays.Event, error) { return deltaEvent(uint64(i + 1)), nil }}, nil
	}
	e := newRpEnv(t, &fakeReplays{answer: endless}, func(h *httpapi.Replays) *httpapi.Replays { return h.WithLimits(5, 1<<20) })
	p := model.NewID()
	org := e.org("replay bound", p)
	reader := e.user(org, "replay-bound@example.test")
	e.grant(org, reader, p, true, auth.Read, httpapi.ReplayRead)
	lines := newLines(t, e.open(reader, replayBody(org, p, model.NewID()), nil)).all()
	if types(lines) != "open delta delta delta delta delta truncated" || lines[6].Next == nil || *lines[6].Next != 6 {
		t.Fatalf("event bound: %s %+v", types(lines), lines[len(lines)-1])
	}

	one := func() int {
		raw, _ := json.Marshal(httpapi.ReplayLine{Type: "delta", Chunk: deltaEvent(1).Chunk})
		return len(raw)
	}()
	e2 := newRpEnv(t, &fakeReplays{answer: endless}, func(h *httpapi.Replays) *httpapi.Replays { return h.WithLimits(100, 3*one) })
	org2 := e2.org("replay bound2", p)
	r2 := e2.user(org2, "replay-bound2@example.test")
	e2.grant(org2, r2, p, true, auth.Read, httpapi.ReplayRead)
	lines = newLines(t, e2.open(r2, replayBody(org2, p, model.NewID()), nil)).all()
	if lines[len(lines)-1].Type != "truncated" || len(lines) > 5 {
		t.Fatalf("byte bound: %s", types(lines))
	}
}

func TestReplayStreamEndsWhenTheClientHangsUp(t *testing.T) {
	var stream *scriptedStream
	src := &fakeReplays{}
	src.answer = func() (replays.ReplayStream, error) {
		stream = &scriptedStream{events: func(i int) (replays.Event, error) {
			time.Sleep(5 * time.Millisecond)
			return deltaEvent(uint64(i + 1)), nil
		}}
		return stream, nil
	}
	e := newRpEnv(t, src)
	p := model.NewID()
	org := e.org("replay hangup", p)
	reader := e.user(org, "replay-hangup@example.test")
	e.grant(org, reader, p, true, auth.Read, httpapi.ReplayRead)
	resp := e.open(reader, replayBody(org, p, model.NewID()), nil)
	lines := newLines(t, resp)
	lines.next()
	lines.next()
	resp.Body.Close()
	deadline := time.Now().Add(10 * time.Second)
	for !stream.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !stream.closed.Load() {
		t.Fatal("the server kept reading the replay after the client left")
	}
}

func TestReplayStreamNeverEchoesServiceErrorText(t *testing.T) {
	canary := "REPLAY-ERR-CANARY-" + model.NewID().String()
	e := newRpEnv(t, &fakeReplays{answer: func() (replays.ReplayStream, error) { return nil, errors.New(canary) }})
	p := model.NewID()
	org := e.org("replay err", p)
	reader := e.user(org, "replay-err@example.test")
	e.grant(org, reader, p, true, auth.Read, httpapi.ReplayRead)
	resp := e.open(reader, replayBody(org, p, model.NewID()), nil)
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 503 || strings.Contains(string(raw), canary) {
		t.Fatalf("open error: %d %s", resp.StatusCode, raw)
	}

	e2 := newRpEnv(t, &fakeReplays{answer: func() (replays.ReplayStream, error) {
		return &scriptedStream{events: func(i int) (replays.Event, error) { return replays.Event{}, errors.New(canary) }}, nil
	}})
	org2 := e2.org("replay err2", p)
	r2 := e2.user(org2, "replay-err2@example.test")
	e2.grant(org2, r2, p, true, auth.Read, httpapi.ReplayRead)
	resp = e2.open(r2, replayBody(org2, p, model.NewID()), nil)
	raw, _ = io.ReadAll(resp.Body)
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if strings.Contains(string(raw), canary) || len(lines) != 2 || !strings.Contains(string(lines[1]), `"type":"error"`) || !strings.Contains(string(lines[1]), `"code":"unavailable"`) {
		t.Fatalf("stream error: %s", raw)
	}
}

// ---- the real replay service over the real storage engine and the real ingest route ----

type chainRecorder struct {
	replay, session model.ID
	domain          model.ClockDomain
	seq, cpSeq      uint64
	prev, cpHash    model.Hash
}

func newChainRecorder() *chainRecorder {
	return &chainRecorder{replay: model.NewID(), session: model.NewID(), domain: model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}}
}

func (r *chainRecorder) next(t *testing.T, checkpoint bool) model.ReplayChunk {
	t.Helper()
	r.seq++
	wall := model.UnixNano(time.Now().UnixNano())
	c := model.ReplayChunk{Replay: r.replay, Session: r.session, Recorder: "1", Sequence: model.Uint64(r.seq), Previous: r.prev, Clock: model.TraceClock{Wall: wall, Mono: model.MonoNano(r.seq) * 1000, Domain: r.domain}, PolicyRevision: 1,
		Events: []model.MaskedEvent{{At: model.MonoNano(wall), Kind: "pointer", Node: 1, X: int32(r.seq), Y: 3}}}
	if checkpoint {
		c.CheckpointSequence, c.Checkpoint = model.Uint64(r.seq), r.prev
		c.Nodes = []model.MaskedNode{{ID: 1, Tag: "div", Class: "masked", Text: "[masked]"}, {ID: 2, Parent: 1, Tag: "button", Text: "[masked]"}}
	} else {
		c.CheckpointSequence, c.Checkpoint = model.Uint64(r.cpSeq), r.cpHash
	}
	h, err := replays.ChunkHash(c)
	if err != nil {
		t.Fatal(err)
	}
	r.prev = h
	if checkpoint {
		r.cpSeq, r.cpHash = r.seq, h
	}
	return c
}

func realReplayEnv(t *testing.T) (*rpEnv, model.ID, model.ID, person, *chainRecorder) {
	t.Helper()
	e := &rpEnv{isoEnv: newIsoEnv(t)}
	svc, err := replays.New(e.app.Storage, e.app.Auth, e.app.Control)
	if err != nil {
		t.Fatal(err)
	}
	h := httpapi.NewReplays(svc)
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) { httpapi.RegisterReplayRoutes(mux, e.app.Auth, h) }).Handler)
	t.Cleanup(e.srv.Close)
	p := model.NewID()
	org := e.org("replay real", p)
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	pol := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Replay}, Replay: true, RetentionDays: map[model.Kind]uint32{model.Replay: 14}, MaxBytes: 1 << 30, MaxSeries: 100}
	src := e.onboard(org, p, model.NewID(), ids, pol, auth.SourcePolicyConfig{ProjectID: p, Enabled: true})
	r := newChainRecorder()
	for i := range 10 {
		i++
		c := r.next(t, i == 1 || i == 6)
		if i == 4 {
			continue // lost in transit: the next checkpoint is the only way back
		}
		e.ingest(src, model.Record{ID: model.NewID(), Kind: model.Replay, ObservedAt: c.Clock.Wall, Resource: e.resource(src), Payload: model.Payload{Replay: &c}})
	}
	reader := e.user(org, "replay-real-reader@example.test")
	e.grant(org, reader, p, true, auth.Read, httpapi.ReplayRead)
	return e, org, p, reader, r
}

func TestReplayStreamRealServicePausesAtGapAndResumesAtCheckpoint(t *testing.T) {
	e, org, p, reader, r := realReplayEnv(t)
	lines := newLines(t, e.open(reader, replayBody(org, p, r.replay), nil)).all()
	var got []string
	for _, l := range lines {
		switch l.Type {
		case "checkpoint", "delta":
			got = append(got, strings.ToUpper(l.Type[:1])+itoa(uint64(*l.Sequence)))
		case "gap":
			got = append(got, "G"+itoa(uint64(*l.Sequence))+"-"+itoa(uint64(*l.Through))+"("+l.Reason+")")
		default:
			got = append(got, l.Type)
		}
	}
	if strings.Join(got, " ") != "open C1 D2 D3 G4-5(missing_chunk) C6 D7 D8 D9 D10 end" {
		t.Fatalf("stream = %v", got)
	}
	for _, l := range lines {
		if l.Chunk != nil && (l.Chunk.PolicyRevision != 1 || l.Policy == nil || *l.Policy != 1) {
			t.Fatalf("policy revision lost: %+v", l)
		}
	}
}

func TestReplayStreamRealServiceRevokeEndsDeliveryAndReopenIsNotFound(t *testing.T) {
	e, org, p, reader, r := realReplayEnv(t)
	resp := e.open(reader, replayBody(org, p, r.replay), nil)
	lines := newLines(t, resp)
	for range 3 { // open + two chunks
		if _, _, ok := lines.next(); !ok {
			t.Fatal("stream ended early")
		}
	}
	e.grant(org, reader, p, false, auth.Read)
	var rest []httpapi.ReplayLine
	for {
		l, _, ok := lines.next()
		if !ok {
			break
		}
		rest = append(rest, l)
	}
	// The real service prefetches up to a batch, but never releases a body after the fence fails:
	// the first line after the revocation is the typed revoke and nothing follows it.
	for i, l := range rest {
		if l.Type == "revoke" {
			if i != len(rest)-1 {
				t.Fatalf("lines after the revoke: %s", types(rest))
			}
			if l.Reason != replays.ReasonAuthorityRevoked {
				t.Fatalf("reason = %q", l.Reason)
			}
			again := e.open(reader, replayBody(org, p, r.replay), nil)
			raw, _ := io.ReadAll(again.Body)
			if again.StatusCode != 404 {
				t.Fatalf("reopen after revocation: %d %s", again.StatusCode, raw)
			}
			return
		}
		if l.Type == "checkpoint" || l.Type == "delta" {
			if l.Sequence != nil && *l.Sequence > 3 {
				t.Fatalf("chunk %d delivered after the revocation committed: %s", *l.Sequence, types(rest))
			}
		}
	}
	t.Fatalf("no revoke line: %s", types(rest))
}

func itoa(v uint64) string { return strconv.FormatUint(v, 10) }

func TestReplayStreamUnencodableChunkIsACorruptLineNotSilence(t *testing.T) {
	src := &fakeReplays{answer: func() (replays.ReplayStream, error) {
		return &scriptedStream{events: func(i int) (replays.Event, error) {
			return replays.Event{Kind: replays.EventDelta, Sequence: 1, Chunk: &model.ReplayChunk{}}, nil // zero IDs cannot be encoded
		}}, nil
	}}
	e := newRpEnv(t, src)
	p := model.NewID()
	org := e.org("replay enc", p)
	reader := e.user(org, "replay-enc@example.test")
	e.grant(org, reader, p, true, auth.Read, httpapi.ReplayRead)
	lines := newLines(t, e.open(reader, replayBody(org, p, model.NewID()), nil)).all()
	if types(lines) != "open error" || lines[1].Code != string(model.Corrupt) {
		t.Fatalf("lines = %s %+v", types(lines), lines)
	}
}

func TestReplayStreamNeedsItsOwnReplayReadGrant(t *testing.T) {
	src := &fakeReplays{answer: func() (replays.ReplayStream, error) { t.Error("service reached"); return nil, io.EOF }}
	e := newRpEnv(t, src)
	p := model.NewID()
	org := e.org("replay grant", p)
	telemetryOnly := e.user(org, "replay-telemetry@example.test")
	e.grant(org, telemetryOnly, p, true, auth.Read)
	replayOnly := e.user(org, "replay-only@example.test")
	e.grant(org, replayOnly, p, true, httpapi.ReplayRead)
	var want string
	for name, who := range map[string]person{"telemetry.read without replay.read": telemetryOnly, "replay.read without telemetry.read": replayOnly} {
		resp := e.open(who, replayBody(org, p, model.NewID()), nil)
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 404 {
			t.Fatalf("%s: %d %s", name, resp.StatusCode, raw)
		}
		if got := denial(t, resp.StatusCode, raw); want == "" {
			want = got
		} else if got != want {
			t.Fatalf("%s is distinguishable", name)
		}
	}
	elevated := replayBody(org, p, model.NewID())
	elevated["elevation"] = model.NewID().String()
	if resp := e.open(telemetryOnly, elevated, nil); resp.StatusCode != 403 {
		t.Fatalf("elevation on a replay read: %d", resp.StatusCode)
	}
}

func TestReplayStreamEndsWhenOnlyReplayReadIsRevoked(t *testing.T) {
	gate := make(chan struct{})
	src := &fakeReplays{}
	src.answer = func() (replays.ReplayStream, error) {
		return &scriptedStream{gate: gate, events: func(i int) (replays.Event, error) { return deltaEvent(uint64(i + 1)), nil }}, nil
	}
	e := newRpEnv(t, src)
	p := model.NewID()
	org := e.org("replay gate revoke", p)
	reader := e.user(org, "replay-gate@example.test")
	e.grant(org, reader, p, true, auth.Read, httpapi.ReplayRead)
	lines := newLines(t, e.open(reader, replayBody(org, p, model.NewID()), nil))
	lines.next()
	gate <- struct{}{}
	if l, _, ok := lines.next(); !ok || l.Type != "delta" {
		t.Fatalf("first chunk: %+v", l)
	}
	// Dropping the whole grant of the user removes both permissions; to prove the replay.read fence alone,
	// the grant is re-issued with telemetry.read only.
	e.grant(org, reader, p, true, auth.Read)
	gate <- struct{}{}
	if l, raw, ok := lines.next(); !ok || l.Type != "revoke" || l.Chunk != nil {
		t.Fatalf("after replay.read was withdrawn: %q", raw)
	}
}

func TestReplayStreamProbeRevalidatesWithoutReleasingAnyChunk(t *testing.T) {
	var stream *scriptedStream
	src := &fakeReplays{}
	src.answer = func() (replays.ReplayStream, error) {
		stream = &scriptedStream{events: func(i int) (replays.Event, error) { t.Error("a probe read a chunk"); return deltaEvent(1), nil }}
		return stream, nil
	}
	e := newRpEnv(t, src)
	p := model.NewID()
	org := e.org("replay probe", p)
	reader := e.user(org, "replay-probe@example.test")
	e.grant(org, reader, p, true, auth.Read, httpapi.ReplayRead)
	body := replayBody(org, p, model.NewID())
	body["probe"] = true
	lines := newLines(t, e.open(reader, body, nil)).all()
	if types(lines) != "open end" || !stream.closed.Load() {
		t.Fatalf("probe = %s closed=%v", types(lines), stream.closed.Load())
	}
	e.grant(org, reader, p, false, auth.Read, httpapi.ReplayRead)
	if resp := e.open(reader, body, nil); resp.StatusCode != 404 {
		t.Fatalf("probe after revocation: %d", resp.StatusCode)
	}
}
