// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/link"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"github.com/arynyklas/soundpost/internal/storage"
)

// fakeTargets is a labelled double of the C04 resolver: it records the scope and references the
// handler hands it and answers from a fixed set. The real resolver is exercised by internal/link.
type fakeTargets struct {
	mu        sync.Mutex
	calls     int
	scope     auth.Scope
	refs      []link.Reference
	available map[model.ID]bool
	err       error
}

func (f *fakeTargets) Resolve(_ context.Context, scope auth.Scope, refs []link.Reference) ([]link.ResolvedReference, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.scope, f.refs = scope, append([]link.Reference(nil), refs...)
	if f.err != nil {
		return nil, f.err
	}
	out := make([]link.ResolvedReference, len(refs))
	for i, r := range refs {
		if f.available[r.ID] {
			owned := r
			out[i] = link.ResolvedReference{Reference: &owned, Available: true}
		}
	}
	return out, nil
}

func (f *fakeTargets) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

func newTrLinksEnv(t *testing.T, source httpapi.SpanSource, links httpapi.TargetResolver) *trEnv {
	t.Helper()
	e := &trEnv{isoEnv: newIsoEnv(t)}
	tr := httpapi.NewTraces(source)
	if links != nil {
		tr.WithLinks(links)
	}
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) { httpapi.RegisterTraceRoutes(mux, e.app.Auth, tr) }).Handler)
	t.Cleanup(e.srv.Close)
	return e
}

func spanID(n uint64) model.SpanID {
	var id model.SpanID
	id[7] = byte(n)
	return id
}

func targetOf(v httpapi.TraceView, span uint64, kind string) (httpapi.SpanTarget, bool) {
	for _, tg := range v.Targets {
		if tg.Span == spanID(span) && tg.Kind == kind {
			return tg, true
		}
	}
	return httpapi.SpanTarget{}, false
}

func traceSection(v httpapi.TraceView, name string) (httpapi.ViewSection, bool) {
	for _, s := range v.Sections {
		if s.Name == name {
			return s, true
		}
	}
	return httpapi.ViewSection{}, false
}

// A span's job, replay and profile, and the error occurrences recorded in it, are resolved through
// C04 under the caller's own scope: each is listed once per span, with exactly the availability the
// resolver answered, and a target the resolver cannot reach is the one unavailable value.
func TestTraceViewResolvesSpanTargetsThroughC04(t *testing.T) {
	trace := model.NewID()
	job, replay, profile, errored, hidden := model.NewID(), model.NewID(), model.NewID(), model.NewID(), model.NewID()
	s1, s2 := tSpan(trace, 1, 0, 0, 100), tSpan(trace, 2, 1, 10, 60)
	s1.Job, s1.Replay, s1.Profile = &job, &replay, &profile
	s2.Job = &job // the same job on a second span is a second reference: each span links on its own
	src := &fakeSpans{answer: func() (httpapi.SpanSet, error) {
		return httpapi.SpanSet{Spans: []model.Span{s1, s2}, Errors: []httpapi.ErrorRef{{Span: spanID(2), Occurrence: errored}, {Span: spanID(2), Occurrence: errored}, {Span: spanID(1), Occurrence: hidden}}}, nil
	}}
	links := &fakeTargets{available: map[model.ID]bool{job: true, replay: true, profile: true, errored: true}} // the profile would resolve, but the reader holds no profiles.read
	e := newTrLinksEnv(t, src, links)
	p, other := model.NewID(), model.NewID()
	org, orgB := e.org("trace links", p), e.org("trace links outsider", other)
	reader := e.user(org, "trace-links-reader@example.test")
	e.grant(org, reader, p, true, auth.Read, httpapi.ReplayRead)
	outsider := e.user(orgB, "trace-links-outsider@example.test")
	e.grant(orgB, outsider, other, true, auth.Read)

	status, raw := e.view(reader, traceBody(org, p, trace))
	if status != 200 {
		t.Fatalf("view: %d %s", status, raw)
	}
	v := decodeTrace(t, raw)
	want := []struct {
		span      uint64
		kind      string
		id        model.ID
		available bool
	}{{1, "job", job, true}, {1, "replay", replay, true}, {1, "profile", profile, false}, {2, "job", job, true}, {2, "error", errored, true}, {1, "error", hidden, false}}
	if len(v.Targets) != len(want) {
		t.Fatalf("targets = %+v, want %d (a repeated reference is listed once)", v.Targets, len(want))
	}
	for _, w := range want {
		got, ok := targetOf(v, w.span, w.kind)
		if !ok || got.ID != w.id || got.Available != w.available || got.Relation != link.RelationExplicit {
			t.Errorf("span %d %s: %+v (found %v), want id %v available %v", w.span, w.kind, got, ok, w.id, w.available)
		}
	}
	if s, ok := traceSection(v, "links"); !ok || s.State != httpapi.StateReady {
		t.Fatalf("links section = %+v %v", s, ok)
	}
	// The resolver was handed the caller's own scope, the requested project and exactly the references the caller's grants allow
	// it to ask about: the profile is unavailable without profiles.read and never reached the resolver.
	links.mu.Lock()
	scopeOrg, allowsP, allowsOther, refs := links.scope.OrgID(), links.scope.AllowsProject(p), links.scope.AllowsProject(other), links.refs
	links.mu.Unlock()
	if scopeOrg != org || !allowsP || allowsOther || len(refs) != len(want)-1 {
		t.Fatalf("resolver saw org %v allows(p)=%v allows(other)=%v refs=%d, want %d", scopeOrg, allowsP, allowsOther, len(refs), len(want)-1)
	}
	for _, r := range refs {
		if r.Kind == "profile" {
			t.Fatalf("a profile reference reached the resolver without profiles.read: %+v", r)
		}
	}
	for _, r := range refs {
		if r.Project != p || r.Relation != link.RelationExplicit {
			t.Fatalf("reference outside the request: %+v", r)
		}
	}
	// An out-of-scope caller never reaches the resolver.
	before := links.count()
	if status, raw = e.view(outsider, traceBody(org, p, trace)); status != 404 {
		t.Fatalf("outsider: %d %s", status, raw)
	}
	if links.count() != before {
		t.Fatal("the resolver was reached for an out-of-scope request")
	}
}

// A resolver that cannot complete (the scope was revoked while resolving) fails the request: no
// partial or guessed targets are shown. Without a resolver the view says its links are not resolved
// and lists no target at all, never a list of unavailable ones.
func TestTraceViewLinkResolutionFailsClosedAndSaysWhenNotWired(t *testing.T) {
	trace := model.NewID()
	job := model.NewID()
	s1 := tSpan(trace, 1, 0, 0, 100)
	s1.Job = &job
	src := &fakeSpans{answer: func() (httpapi.SpanSet, error) { return httpapi.SpanSet{Spans: []model.Span{s1}}, nil }}

	broken := &fakeTargets{err: model.Fail(model.NotFound)}
	e := newTrLinksEnv(t, src, broken)
	p := model.NewID()
	org := e.org("trace links closed", p)
	reader := e.user(org, "trace-closed-reader@example.test")
	e.grant(org, reader, p, true, auth.Read)
	if status, raw := e.view(reader, traceBody(org, p, trace)); status != 404 {
		t.Fatalf("a failed resolution was answered: %d %s", status, raw)
	}

	plain := newTrLinksEnv(t, src, nil)
	p2 := model.NewID()
	org2 := plain.org("trace links unwired", p2)
	reader2 := plain.user(org2, "trace-unwired-reader@example.test")
	plain.grant(org2, reader2, p2, true, auth.Read)
	status, raw := plain.view(reader2, traceBody(org2, p2, trace))
	if status != 200 {
		t.Fatalf("view: %d %s", status, raw)
	}
	v := decodeTrace(t, raw)
	if s, ok := traceSection(v, "links"); !ok || s.State != httpapi.StateNotAvailable || s.Reason != httpapi.ReasonLinkResolverNotWired || len(v.Targets) != 0 || v.Path == nil {
		t.Fatalf("an unwired resolver: section %+v %v targets %d", s, ok, len(v.Targets))
	}
}

// One resolution batch is bounded: past it the view says it is truncated and resolves only the
// first batch.
func TestTraceViewTargetsAreBoundedAndSayWhenTruncated(t *testing.T) {
	trace := model.NewID()
	spans := make([]model.Span, 0, 70)
	for i := 1; i <= 70; i++ {
		s := tSpan(trace, uint64(i), 0, 0, 100)
		a, b := model.NewID(), model.NewID()
		s.Job, s.Replay = &a, &b
		spans = append(spans, s)
	}
	src := &fakeSpans{answer: func() (httpapi.SpanSet, error) { return httpapi.SpanSet{Spans: spans}, nil }}
	links := &fakeTargets{}
	e := newTrLinksEnv(t, src, links)
	p := model.NewID()
	org := e.org("trace links bounded", p)
	reader := e.user(org, "trace-bounded-reader@example.test")
	e.grant(org, reader, p, true, auth.Read, httpapi.ReplayRead)
	status, raw := e.view(reader, traceBody(org, p, trace))
	if status != 200 {
		t.Fatalf("view: %d %s", status, raw)
	}
	v := decodeTrace(t, raw)
	s, ok := traceSection(v, "links")
	if !ok || s.State != httpapi.StateIncomplete || s.Reason != httpapi.ReasonTargetsTruncated || len(v.Targets) != 128 || len(links.refs) != 128 {
		t.Fatalf("section %+v %v targets %d refs %d", s, ok, len(v.Targets), len(links.refs))
	}
}

// The storage source reads the error occurrences of the trace under the same scope and window and keeps
// only those that name a span of this trace.
func TestStorageSpanSourceReadsTheErrorsRecordedInTheTrace(t *testing.T) {
	trace, project := model.NewID(), model.NewID()
	a := tSpan(trace, 1, 0, 0, 10)
	sc := &fakeScanner{pages: []storage.Page{pageOf(false, &a)}}
	on, onTrace, off, elsewhere := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	span := spanID(1)
	other := model.NewID()
	errPage := storage.Page{
		IDs: []model.ID{model.NewID(), model.NewID(), model.NewID(), model.NewID()},
		Values: []model.Payload{
			{Error: &model.ErrorOccurrence{Occurrence: on, Trace: &trace, Span: &span}},
			{Error: &model.ErrorOccurrence{Occurrence: off, Trace: &trace}},                    // names no span
			{Error: &model.ErrorOccurrence{Occurrence: elsewhere, Trace: &other, Span: &span}}, // another trace
			{Error: &model.ErrorOccurrence{Occurrence: onTrace, Trace: &trace, Span: &span}},
		},
	}
	sc.errPages = []storage.Page{errPage}
	set, err := httpapi.NewStorageSpanSource(sc).TraceSpans(context.Background(), auth.Scope{}, project, trace, query.TimeRange{Start: 10, End: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Errors) != 2 || set.Errors[0] != (httpapi.ErrorRef{Span: span, Occurrence: on}) || set.Errors[1] != (httpapi.ErrorRef{Span: span, Occurrence: onTrace}) {
		t.Fatalf("errors = %+v, want the two occurrences that name a span of this trace", set.Errors)
	}
	r := sc.errs
	if r == nil || r.Signal != model.ErrorKind || r.Projects[0] != project || r.Start != 10 || r.End != 20 || len(r.Selectors) != 1 || r.Selectors[0].Name != "trace_id" || r.Selectors[0].Literal.String != trace.String() || !r.Fence.AllowPartial {
		t.Fatalf("error scan = %+v", r)
	}
	// A partial error read makes the whole trace read partial.
	sc.errPages = []storage.Page{{Partial: true}}
	if set, err = httpapi.NewStorageSpanSource(sc).TraceSpans(context.Background(), auth.Scope{}, project, trace, query.TimeRange{Start: 10, End: 20}); err != nil || !set.Partial {
		t.Fatalf("partial error read: partial %v err %v", set.Partial, err)
	}
	// No span, no error read.
	sc.pages, sc.errs = nil, nil
	if _, err = httpapi.NewStorageSpanSource(sc).TraceSpans(context.Background(), auth.Scope{}, project, trace, query.TimeRange{Start: 10, End: 20}); err != nil || sc.errs != nil {
		t.Fatalf("a trace with no span read the error records: %v", err)
	}
}

// fakeIssueTargets adds the occurrence->issue capability to the labelled C04 double.
type fakeIssueTargets struct {
	*fakeTargets
	issues map[model.ID]model.ID
	asked  [][]model.ID
}

func (f *fakeIssueTargets) IssuesOf(_ context.Context, _ auth.Scope, _ model.ID, occ []model.ID) map[model.ID]model.ID {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, append([]model.ID(nil), occ...))
	out := map[model.ID]model.ID{}
	for _, o := range occ {
		if i, ok := f.issues[o]; ok {
			out[o] = i
		}
	}
	return out
}

// An error occurrence carries the issue holding it only when it is available to the caller and an issue holds
// it; an unavailable occurrence is never asked about, so its issue cannot be learned from the trace view.
func TestTraceViewLinksAvailableErrorOccurrencesToTheirIssue(t *testing.T) {
	trace := model.NewID()
	held, unheld, hidden, issue, leaked := model.NewID(), model.NewID(), model.NewID(), model.NewID(), model.NewID()
	s1 := tSpan(trace, 1, 0, 0, 100)
	src := &fakeSpans{answer: func() (httpapi.SpanSet, error) {
		return httpapi.SpanSet{Spans: []model.Span{s1}, Errors: []httpapi.ErrorRef{{Span: spanID(1), Occurrence: held}, {Span: spanID(1), Occurrence: unheld}, {Span: spanID(1), Occurrence: hidden}}}, nil
	}}
	links := &fakeIssueTargets{fakeTargets: &fakeTargets{available: map[model.ID]bool{held: true, unheld: true}}, issues: map[model.ID]model.ID{held: issue, hidden: leaked}}
	e := newTrLinksEnv(t, src, links)
	p := model.NewID()
	org := e.org("trace issue links", p)
	reader := e.user(org, "trace-issue-reader@example.test")
	e.grant(org, reader, p, true, auth.Read)
	status, raw := e.view(reader, traceBody(org, p, trace))
	if status != 200 {
		t.Fatalf("view: %d %s", status, raw)
	}
	v := decodeTrace(t, raw)
	for _, w := range []struct {
		id   model.ID
		want *model.ID
	}{{held, &issue}, {unheld, nil}, {hidden, nil}} {
		var got *httpapi.SpanTarget
		for i := range v.Targets {
			if v.Targets[i].Kind == "error" && v.Targets[i].ID == w.id {
				got = &v.Targets[i]
			}
		}
		if got == nil || (got.Issue == nil) != (w.want == nil) || (w.want != nil && *got.Issue != *w.want) {
			t.Errorf("occurrence %v: %+v, want issue %v", w.id, got, w.want)
		}
	}
	if len(links.asked) != 1 || len(links.asked[0]) != 2 {
		t.Fatalf("issue lookup asked %v, want one call about the two available occurrences", links.asked)
	}
}
