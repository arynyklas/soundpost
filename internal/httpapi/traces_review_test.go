// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"github.com/arynyklas/soundpost/internal/storage"
)

// Finding 05.06#12 (a): a link read that could not be made is an explicit read failure, never an account
// fact. The caller's session ends while the view is being built, so the replay-grant check fails with the
// authenticator's own error (not the one not-found of an absent grant): the view must fail with that error
// and must not answer 200 with the replay target "unavailable".
func TestTraceViewFailedGrantCheckIsAReadFailureNotAnUnavailableTarget(t *testing.T) {
	trace := model.NewID()
	replay := model.NewID()
	s1 := tSpan(trace, 1, 0, 0, 100)
	s1.Replay = &replay
	e := newIsoEnv(t)
	p := model.NewID()
	org := e.org("trace grant failure", p)
	reader := e.user(org, "trace-grant-failure@example.test")
	e.grant(org, reader, p, true, auth.Read, httpapi.ReplayRead)
	src := &fakeSpans{answer: func() (httpapi.SpanSet, error) {
		if err := e.app.Auth.Logout(e.ctx, reader.Session.Token); err != nil {
			t.Fatal(err)
		}
		return httpapi.SpanSet{Spans: []model.Span{s1}}, nil
	}}
	links := &fakeTargets{available: map[model.ID]bool{replay: true}}
	tr := httpapi.NewTraces(src).WithLinks(links)
	body := httpapi.TraceBody{ScopeFields: httpapi.ScopeFields{Org: org}, Project: p, Trace: trace, Window: query.TimeRange{Start: 1699999999000000000, End: 1700000100000000000}}
	view, _, err := tr.View(e.ctx, e.app.Auth, reader.Cred, body)
	if err == nil {
		t.Fatalf("a grant check that failed was reported as a view: state %s targets %+v", view.State, view.Targets)
	}
	var f *model.Fault
	if !errors.As(err, &f) || f.Code == model.NotFound {
		t.Fatalf("error = %v, want the authorizer's own failure, not the not-found of an absent grant", err)
	}
	if len(view.Targets) != 0 {
		t.Fatalf("targets of a failed read: %+v", view.Targets)
	}
}

// An absent grant stays an honest answer: the replay target is unavailable and the view is served.
func TestTraceViewAbsentReplayGrantIsStillAnUnavailableTarget(t *testing.T) {
	trace := model.NewID()
	replay := model.NewID()
	s1 := tSpan(trace, 1, 0, 0, 100)
	s1.Replay = &replay
	src := &fakeSpans{answer: func() (httpapi.SpanSet, error) { return httpapi.SpanSet{Spans: []model.Span{s1}}, nil }}
	links := &fakeTargets{available: map[model.ID]bool{replay: true}}
	e := newTrLinksEnv(t, src, links)
	p := model.NewID()
	org := e.org("trace grant absent", p)
	reader := e.user(org, "trace-grant-absent@example.test")
	e.grant(org, reader, p, true, auth.Read)
	status, raw := e.view(reader, traceBody(org, p, trace))
	if status != 200 {
		t.Fatalf("view: %d %s", status, raw)
	}
	tg, ok := targetOf(decodeTrace(t, raw), 1, "replay")
	if !ok || tg.Available {
		t.Fatalf("replay target = %+v %v, want listed and unavailable", tg, ok)
	}
	if links.count() != 0 {
		t.Fatal("a replay without its grant reached the resolver")
	}
}

// Finding 05.06#12 (c): the loss read of a trace is bounded. The loss records of every producer in the window
// are scanned to find the producers of this trace; past the scan bound the read stops and the whole read says
// it is partial instead of reading an unbounded stream.
func TestStorageSpanSourceBoundsTheLossScanAndSaysPartial(t *testing.T) {
	trace, project := model.NewID(), model.NewID()
	srcA := model.NewID()
	a := tSpan(trace, 1, 0, 0, 10)
	page := pageOf(false, &a)
	page.Sources = []model.ID{srcA}
	page.ObservedTimes = []model.UnixNano{111}
	other := model.NewID()
	noise := make([]model.LossReport, 50_001)
	for i := range noise {
		noise[i] = model.LossReport{Source: other, Producer: other, Start: 5, End: 9, Signal: model.SpanKind, Reason: "transport", Count: 1}
	}
	sc := &fakeScanner{pages: []storage.Page{page}, lossPages: []storage.Page{lossPage(false, noise...)}}
	set, err := httpapi.NewStorageSpanSource(sc).TraceSpans(context.Background(), auth.Scope{}, project, trace, query.TimeRange{Start: 10, End: 20})
	if err != nil {
		t.Fatal(err)
	}
	if !set.Partial {
		t.Fatal("a loss scan cut at its bound was not reported partial")
	}
	// Under the bound nothing is partial.
	sc = &fakeScanner{pages: []storage.Page{page}, lossPages: []storage.Page{lossPage(false, noise[:100]...)}}
	set, err = httpapi.NewStorageSpanSource(sc).TraceSpans(context.Background(), auth.Scope{}, project, trace, query.TimeRange{Start: 10, End: 20})
	if err != nil || set.Partial {
		t.Fatalf("a loss scan inside its bound: partial %v err %v", set.Partial, err)
	}
}

// Finding 05.06#12 (d): the edge list is bounded at the client's bound and says when it was cut.
func TestTraceViewBoundsEdgesAtTheClientLimitAndFlagsTruncation(t *testing.T) {
	trace := model.NewID()
	over := tSpan(trace, 1, 0, 0, 100)
	foreign := model.NewID()
	for i := range httpapi.MaxPathEdges + 1 {
		over.Links = append(over.Links, model.SpanLink{Trace: foreign, Span: spanID(uint64(i%250) + 1)})
	}
	few := tSpan(trace, 1, 0, 0, 100)
	few.Links = []model.SpanLink{{Trace: foreign, Span: spanID(9)}}
	serve := func(s model.Span) *trEnv { // a fresh environment per trace
		return newTrEnv(t, &fakeSpans{answer: func() (httpapi.SpanSet, error) { return httpapi.SpanSet{Spans: []model.Span{s}}, nil }})
	}
	run := func(e *trEnv, name string) httpapi.TraceView {
		p := model.NewID()
		org := e.org(name, p)
		reader := e.user(org, name+"@example.test")
		e.grant(org, reader, p, true, auth.Read)
		status, raw := e.view(reader, traceBody(org, p, trace))
		if status != 200 {
			t.Fatalf("%s: %d %.200s", name, status, raw)
		}
		return decodeTrace(t, raw)
	}
	v := run(serve(few), "edges-few")
	if v.EdgesTruncated || v.Path == nil || len(v.Path.Edges) != 1 {
		t.Fatalf("a short edge list was reported truncated or changed: truncated %v edges %d", v.EdgesTruncated, len(v.Path.Edges))
	}
	v = run(serve(over), "edges-over")
	if v.Path == nil || len(v.Path.Edges) != httpapi.MaxPathEdges || !v.EdgesTruncated {
		t.Fatalf("an oversized edge list: truncated %v, edges %d, want %d and truncated", v.EdgesTruncated, len(v.Path.Edges), httpapi.MaxPathEdges)
	}
	if v.State != httpapi.StateIncomplete || v.Reason != httpapi.ReasonEdgesTruncated {
		t.Fatalf("state %s reason %s, want incomplete edges_truncated", v.State, v.Reason)
	}
	if s, ok := traceSection(v, "edges"); !ok || s.State != httpapi.StateIncomplete || s.Reason != httpapi.ReasonEdgesTruncated {
		t.Fatalf("edges section = %+v %v", s, ok)
	}
}

// Finding 05.06#12 (e): the issue of an error occurrence is looked up by (kind, id) inside one project. An
// error occurrence and a job that share an ID never exchange issues, and the resolver is only ever handed the
// one requested project, so the same ID in another project cannot collide.
func TestTraceViewIssueLookupIsKeyedByKindNotByIDAlone(t *testing.T) {
	trace := model.NewID()
	shared := model.NewID()
	s1 := tSpan(trace, 1, 0, 0, 100)
	s1.Job = &shared
	s2 := tSpan(trace, 2, 1, 0, 50)
	issue := model.NewID()
	src := &fakeSpans{answer: func() (httpapi.SpanSet, error) {
		return httpapi.SpanSet{Spans: []model.Span{s1, s2}, Errors: []httpapi.ErrorRef{{Span: s2.ID, Occurrence: shared}}}, nil
	}}
	links := &fakeIssueTargets{fakeTargets: &fakeTargets{available: map[model.ID]bool{shared: true}}, issues: map[model.ID]model.ID{shared: issue}}
	e := newTrLinksEnv(t, src, links)
	p := model.NewID()
	org := e.org("trace issue key", p)
	reader := e.user(org, "trace-issue-key@example.test")
	e.grant(org, reader, p, true, auth.Read)
	status, raw := e.view(reader, traceBody(org, p, trace))
	if status != 200 {
		t.Fatalf("view: %d %s", status, raw)
	}
	v := decodeTrace(t, raw)
	job, okJ := targetOf(v, 1, "job")
	errT, okE := targetOf(v, 2, "error")
	if !okJ || !okE || job.Issue != nil || errT.Issue == nil || *errT.Issue != issue {
		t.Fatalf("job %+v %v error %+v %v: the job must carry no issue, the error occurrence its own", job, okJ, errT, okE)
	}
}
