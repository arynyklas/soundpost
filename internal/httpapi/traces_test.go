// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"github.com/arynyklas/soundpost/internal/storage"
	"github.com/arynyklas/soundpost/internal/traces"
)

// fakeSpans is a labelled test double for the span read seam: it records what the
// handler hands it and answers a configured set. The real storage scan is
// exercised by TestStorageSpanSourceRequest (fake scanner) and by the browser
// e2e (real ingest and real storage).
type fakeSpans struct {
	mu     sync.Mutex
	calls  int
	scope  auth.Scope
	proj   model.ID
	trace  model.ID
	window query.TimeRange
	answer func() (httpapi.SpanSet, error)
}

func (f *fakeSpans) TraceSpans(_ context.Context, scope auth.Scope, project, trace model.ID, window query.TimeRange) (httpapi.SpanSet, error) {
	f.mu.Lock()
	f.calls++
	f.scope, f.proj, f.trace, f.window = scope, project, trace, window
	f.mu.Unlock()
	return f.answer()
}

func (f *fakeSpans) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

func tSpan(trace model.ID, id, parent uint64, startMs, endMs int64) model.Span {
	var sid, pid model.SpanID
	binary.BigEndian.PutUint64(sid[:], id)
	clock := func(ms int64) model.TraceClock {
		return model.TraceClock{Wall: model.UnixNano(1_700_000_000_000_000_000 + ms*1_000_000), Mono: model.MonoNano(5_000_000_000_000 + uint64(ms)*1_000_000), Domain: model.ClockDomain{Host: model.ID{1}, Boot: model.ID{2}, Runtime: model.ID{3}}}
	}
	e := clock(endMs)
	s := model.Span{Trace: trace, ID: sid, Kind: "internal", Operation: "op.request", Start: clock(startMs), End: &e, Status: "ok", SampleProbability: model.FloatBits(math.Float64bits(1)), SampleDecision: "keep"}
	if parent != 0 {
		binary.BigEndian.PutUint64(pid[:], parent)
		s.Parent = &pid
	}
	return s
}

type trEnv struct {
	*isoEnv
	srv *httptest.Server
}

func newTrEnv(t *testing.T, source httpapi.SpanSource) *trEnv {
	t.Helper()
	e := &trEnv{isoEnv: newIsoEnv(t)}
	tr := httpapi.NewTraces(source)
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) { httpapi.RegisterTraceRoutes(mux, e.app.Auth, tr) }).Handler)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *trEnv) view(who person, body map[string]any) (int, []byte) {
	e.t.Helper()
	ev := &evEnv{isoEnv: e.isoEnv, srv: e.srv}
	return ev.post(who, "/api/v1/traces/view", body, nil)
}

func traceBody(org, project, trace model.ID) map[string]any {
	return map[string]any{"org": org.String(), "project": project.String(), "trace": trace.String(), "window": map[string]any{"start": "1699999999000000000", "end": "1700000100000000000"}}
}

func decodeTrace(t *testing.T, raw []byte) httpapi.TraceView {
	t.Helper()
	var v httpapi.TraceView
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("not a trace view: %v\n%s", err, raw)
	}
	return v
}

func TestTraceViewScopeFirstAndIndistinguishable(t *testing.T) {
	trace := model.NewID()
	src := &fakeSpans{answer: func() (httpapi.SpanSet, error) {
		return httpapi.SpanSet{Spans: []model.Span{tSpan(trace, 1, 0, 0, 100), tSpan(trace, 2, 1, 0, 70), tSpan(trace, 3, 1, 0, 40)}}, nil
	}}
	e := newTrEnv(t, src)
	pA, pB, pX := model.NewID(), model.NewID(), model.NewID()
	orgA, orgB := e.org("trace A", pA, pB), e.org("trace B", pX)
	reader := e.user(orgA, "trace-reader@example.test")
	e.grant(orgA, reader, pA, true, auth.Read)
	outsider := e.user(orgB, "trace-outsider@example.test")
	e.grant(orgB, outsider, pX, true, auth.Read)

	status, raw := e.view(reader, traceBody(orgA, pA, trace))
	if status != 200 {
		t.Fatalf("reader: %d %s", status, raw)
	}
	v := decodeTrace(t, raw)
	if v.State != httpapi.StateReady || v.Path == nil || len(v.Path.Trees) != 1 || len(v.Path.Trees[0].Segments) != 2 || v.Path.Observed.Min != v.Path.Observed.Max || v.Path.Observed.Min != model.Int64(100_000_000) {
		t.Fatalf("view = %s", raw)
	}
	if src.scope.OrgID() != orgA || !src.scope.AllowsProject(pA) || src.scope.AllowsProject(pB) || src.scope.Permission() != auth.Read || src.proj != pA || src.trace != trace || src.window.Start != 1699999999000000000 || src.window.End != 1700000100000000000 {
		t.Fatalf("source saw a different request than the scoped one: %+v", src)
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
		status, raw = e.view(c.who, traceBody(c.org, c.prj, trace))
		if status != 404 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		got := denial(t, status, raw)
		if want == "" {
			want = got
		} else if got != want {
			t.Fatalf("%s distinguishable: %q vs %q", name, got, want)
		}
	}
	if src.count() != before {
		t.Fatal("the span source was reached for an out-of-scope request")
	}

	// A body cannot name another scope or widen the permission.
	for name, mutate := range map[string]func(map[string]any){
		"projects":    func(b map[string]any) { b["projects"] = []string{pA.String(), pB.String()} },
		"source":      func(b map[string]any) { b["source"] = model.NewID().String() },
		"permission":  func(b map[string]any) { b["permission"] = "org.admin" },
		"raw":         func(b map[string]any) { b["permission"] = "raw.read" },
		"unknown":     func(b map[string]any) { b["scope"] = map[string]any{"org": orgB.String()} },
		"zero trace":  func(b map[string]any) { b["trace"] = model.ID{}.String() },
		"reversed":    func(b map[string]any) { b["window"] = map[string]any{"start": "5", "end": "5"} },
		"no window":   func(b map[string]any) { delete(b, "window") },
		"no project":  func(b map[string]any) { delete(b, "project") },
		"number time": func(b map[string]any) { b["window"] = map[string]any{"start": 1, "end": 2} },
	} {
		body := traceBody(orgA, pA, trace)
		mutate(body)
		status, raw = e.view(reader, body)
		if status == 200 {
			t.Fatalf("%s: accepted: %s", name, raw)
		}
	}
	if src.count() != before {
		t.Fatal("the span source was reached for a malformed or widened request")
	}
}

func TestTraceViewSourceStatesAreExplicit(t *testing.T) {
	trace := model.NewID()
	e0 := newTrEnv(t, nil)
	p := model.NewID()
	org := e0.org("trace states", p)
	u := e0.user(org, "trace-states@example.test")
	e0.grant(org, u, p, true, auth.Read)
	outsider := e0.user(e0.org("trace states other", model.NewID()), "trace-states-out@example.test")

	status, raw := e0.view(u, traceBody(org, p, trace))
	v := decodeTrace(t, raw)
	if status != 200 || v.State != httpapi.StateNotAvailable || v.Reason != httpapi.ReasonSpanSourceNotWired || v.Path != nil {
		t.Fatalf("unwired source must be not_available: %d %s", status, raw)
	}
	if status, _ = e0.view(outsider, traceBody(org, p, trace)); status != 404 {
		t.Fatalf("unwired source must not weaken scope: %d", status)
	}

	for name, c := range map[string]struct {
		set    httpapi.SpanSet
		err    error
		status int
		state  httpapi.ViewState
		reason string
		path   bool
	}{
		"empty":      {httpapi.SpanSet{}, nil, 200, httpapi.StateEmpty, httpapi.ReasonNoSpansInWindow, false},
		"empty+part": {httpapi.SpanSet{Partial: true}, nil, 200, httpapi.StateIncomplete, httpapi.ReasonSpansPartial, false},
		"partial":    {httpapi.SpanSet{Partial: true, Spans: []model.Span{tSpan(trace, 1, 0, 0, 10)}}, nil, 200, httpapi.StateIncomplete, httpapi.ReasonSpansPartial, true},
		"foreign":    {httpapi.SpanSet{Spans: []model.Span{tSpan(model.NewID(), 1, 0, 0, 10)}}, nil, 503, "", "", false},
		"too deep":   {httpapi.SpanSet{Spans: deepChain(trace, traces.MaxDepth+1)}, nil, 413, "", "", false},
		"source err": {httpapi.SpanSet{}, model.Fail(model.Timeout), 504, "", "", false},
	} {
		src := &fakeSpans{answer: func() (httpapi.SpanSet, error) { return c.set, c.err }}
		e := newTrEnv(t, src)
		// Reuse e's own org/user (each env has its own app).
		p2 := model.NewID()
		o2 := e.org("trace states "+name, p2)
		u2 := e.user(o2, "trace-"+name+"@example.test")
		e.grant(o2, u2, p2, true, auth.Read)
		status, raw := e.view(u2, traceBody(o2, p2, trace))
		if status != c.status {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if c.status != 200 {
			continue
		}
		v := decodeTrace(t, raw)
		if v.State != c.state || v.Reason != c.reason || (v.Path != nil) != c.path || v.Partial != c.set.Partial {
			t.Fatalf("%s: %s", name, raw)
		}
	}
}

func deepChain(trace model.ID, n int) []model.Span {
	out := make([]model.Span, n)
	for i := range out {
		out[i] = tSpan(trace, uint64(i+1), uint64(i), 0, int64(n-i))
	}
	return out
}

// fakeScanner is a labelled double for *storage.Engine's Scan: it records the
// request and serves one borrowed page it scribbles over afterwards, the way the
// real iterator reuses its buffers.
type fakeScanner struct {
	req   storage.ScanRequest
	pages []storage.Page
	err   error
	scope auth.Scope
}

type fakeRows struct {
	pages []storage.Page
	i     int
}

func (r *fakeRows) Next(context.Context) (storage.Page, error) {
	if r.i >= len(r.pages) {
		return storage.Page{}, io.EOF
	}
	r.i++
	return r.pages[r.i-1], nil
}
func (r *fakeRows) Watermarks() []model.Cursor { return nil }
func (r *fakeRows) Close() error               { return nil }

func (f *fakeScanner) Scan(_ context.Context, scope auth.Scope, req storage.ScanRequest) (storage.RowIterator, error) {
	f.req, f.scope = req, scope
	if f.err != nil {
		return nil, f.err
	}
	return &fakeRows{pages: f.pages}, nil
}

func pageOf(partial bool, spans ...*model.Span) storage.Page {
	p := storage.Page{Partial: partial}
	for range spans {
		p.IDs = append(p.IDs, model.NewID())
	}
	for _, s := range spans {
		p.Values = append(p.Values, model.Payload{Span: s})
	}
	return p
}

func TestStorageSpanSourceRequest(t *testing.T) {
	trace, project := model.NewID(), model.NewID()
	own, other := tSpan(trace, 1, 0, 0, 10), tSpan(model.NewID(), 2, 0, 0, 10)
	log := model.Payload{Log: &model.LogRecord{}}
	page := pageOf(true, &own, &other)
	page.IDs, page.Values = append(page.IDs, model.NewID()), append(page.Values, log)
	sc := &fakeScanner{pages: []storage.Page{page}}
	src := httpapi.NewStorageSpanSource(sc)
	win := query.TimeRange{Start: 10, End: 20}
	set, err := src.TraceSpans(context.Background(), auth.Scope{}, project, trace, win)
	if err != nil {
		t.Fatal(err)
	}
	r := sc.req
	if r.Signal != model.SpanKind || len(r.Projects) != 1 || r.Projects[0] != project || r.Start != 10 || r.End != 20 || len(r.Selectors) != 1 {
		t.Fatalf("scan request = %+v", r)
	}
	m := r.Selectors[0]
	if m.Target != storage.MatchField || m.Name != "trace_id" || m.Op != storage.MatchEqual || m.Literal.Kind != storage.LiteralString || m.Literal.String != trace.String() {
		t.Fatalf("trace selector = %+v", m)
	}
	if !set.Partial || len(set.Spans) != 1 || set.Spans[0].ID != own.ID {
		t.Fatalf("set = %+v (a span of another trace or a non-span row leaked)", set)
	}
	// The result must not alias the borrowed page.
	own.Operation, own.End.Wall = "scribbled", 0
	if set.Spans[0].Operation != "op.request" || set.Spans[0].End == own.End || set.Spans[0].End.Wall == 0 {
		t.Fatalf("result aliases the borrowed page: %+v", set.Spans[0])
	}
	// A scan refusal is passed through typed, never an empty set.
	sc.err = model.Fail(model.NotFound)
	if _, err = src.TraceSpans(context.Background(), auth.Scope{}, project, trace, win); faultCode(err) != model.NotFound {
		t.Fatalf("scan refusal = %v", err)
	}
}

func TestStorageSpanSourcePartialOnAnyPageStaysPartial(t *testing.T) {
	trace := model.NewID()
	a, b := tSpan(trace, 1, 0, 0, 10), tSpan(trace, 2, 1, 0, 5)
	sc := &fakeScanner{pages: []storage.Page{pageOf(true, &a), pageOf(false, &b)}} // the missing shard answered on the first page only
	set, err := httpapi.NewStorageSpanSource(sc).TraceSpans(context.Background(), auth.Scope{}, model.NewID(), trace, query.TimeRange{Start: 1, End: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !set.Partial || len(set.Spans) != 2 {
		t.Fatalf("set = %+v: a later complete page must not clear an earlier partial flag", set)
	}
}

func TestStorageSpanSourceBoundsMemory(t *testing.T) {
	trace := model.NewID()
	spans := make([]*model.Span, traces.MaxSpans+50)
	for i := range spans {
		s := tSpan(trace, uint64(i+1), 0, 0, 1)
		spans[i] = &s
	}
	sc := &fakeScanner{pages: []storage.Page{pageOf(false, spans...)}}
	set, err := httpapi.NewStorageSpanSource(sc).TraceSpans(context.Background(), auth.Scope{}, model.NewID(), trace, query.TimeRange{Start: 1, End: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Spans) != traces.MaxSpans+1 {
		t.Fatalf("read %d spans, want the cap plus one so the analysis can refuse it", len(set.Spans))
	}
	if _, err = traces.CriticalPath(set.Spans); err == nil {
		t.Fatal("oversized trace analyzed")
	}
}
