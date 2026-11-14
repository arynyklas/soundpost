// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"github.com/arynyklas/soundpost/internal/storage"
	"github.com/arynyklas/soundpost/internal/traces"
)

// This file is the C11 trace view of the investigation UI: the spans of one
// trace read under the caller's own scope, analyzed by traces.CriticalPath into
// causal segments with observed duration BOUNDS, never one authoritative total.
//
// The scope is derived from the caller's credential before any span is read; a
// wrong organization, a project the caller does not hold and a trace with no
// visible spans are the same not-found. A span source that is not wired is an
// explicit not_available state, never an empty success. Nothing here follows a
// span link across traces: a link is reported as a reference whose target this
// scope has not resolved.

// Reason codes of the trace view.
const (
	ReasonSpanSourceNotWired = "span_source_not_wired"
	ReasonNoSpansInWindow    = "no_spans_in_window"
	ReasonSpansPartial       = "spans_partial"
)

// SpanSet is what a SpanSource returns for one trace: its spans visible to the
// scope inside the window, and whether the read was partial (missing shards).
type SpanSet struct {
	Spans   []model.Span
	Partial bool
}

// SpanSource reads the spans of exactly one trace under a scope. Implementations
// must enforce the scope themselves; the handler also verifies every returned
// span belongs to the requested trace. A source returns at most
// traces.MaxSpans+1 spans so the analysis can refuse an oversized trace with a
// typed error instead of the read holding it all.
type SpanSource interface {
	TraceSpans(ctx context.Context, scope auth.Scope, project, trace model.ID, window query.TimeRange) (SpanSet, error)
}

// SpanScanner is the committed storage read seam (*storage.Engine implements it).
type SpanScanner interface {
	Scan(ctx context.Context, scope auth.Scope, req storage.ScanRequest) (storage.RowIterator, error)
}

type storageSpans struct{ scanner SpanScanner }

// NewStorageSpanSource reads spans through the committed storage scan: signal
// span, one project, a trace_id equality selector and the request window.
func NewStorageSpanSource(scanner SpanScanner) SpanSource { return storageSpans{scanner} }

func copySpan(s model.Span) model.Span {
	if s.Parent != nil {
		p := *s.Parent
		s.Parent = &p
	}
	if s.End != nil {
		e := *s.End
		s.End = &e
	}
	s.Links = append([]model.SpanLink(nil), s.Links...)
	for _, id := range []**model.ID{&s.Job, &s.Replay, &s.Profile} {
		if *id != nil {
			v := **id
			*id = &v
		}
	}
	return s
}

func (s storageSpans) TraceSpans(ctx context.Context, scope auth.Scope, project, trace model.ID, window query.TimeRange) (SpanSet, error) {
	if s.scanner == nil {
		return SpanSet{}, model.Fail(model.Unavailable)
	}
	rows, err := s.scanner.Scan(ctx, scope, storage.ScanRequest{
		Projects: []model.ID{project}, Signal: model.SpanKind, Start: window.Start, End: window.End,
		Selectors:  []storage.Matcher{{Target: storage.MatchField, Name: "trace_id", Op: storage.MatchEqual, Literal: storage.Literal{Kind: storage.LiteralString, String: trace.String()}}},
		Projection: []storage.Field{storage.FieldID, storage.FieldTime, storage.FieldSpan},
		Fence:      storage.ReadFence{AllowPartial: true},
	})
	if err != nil {
		return SpanSet{}, err
	}
	if rows == nil {
		return SpanSet{}, model.Fail(model.Corrupt)
	}
	defer rows.Close()
	var out SpanSet
	for {
		page, err := rows.Next(ctx)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return SpanSet{}, err
		}
		out.Partial = out.Partial || page.Partial
		if len(page.Values) != page.Len() {
			return SpanSet{}, model.Fail(model.Corrupt)
		}
		for _, v := range page.Values {
			if v.Span == nil || v.Span.Trace != trace {
				continue
			}
			if len(out.Spans) > traces.MaxSpans {
				return out, nil
			}
			out.Spans = append(out.Spans, copySpan(*v.Span))
		}
	}
}

// Traces is the handler behind POST /api/v1/traces/view. The span source may be nil.
type Traces struct{ source SpanSource }

// NewTraces binds the optional span source.
func NewTraces(source SpanSource) *Traces { return &Traces{source: source} }

// TraceBody is the POST /api/v1/traces/view body. Org and Project are selectors
// authorization confirms; Window is the half-open [start,end) nanosecond range
// the trace's spans are read from.
type TraceBody struct {
	ScopeFields
	Project model.ID        `json:"project"`
	Trace   model.ID        `json:"trace"`
	Window  query.TimeRange `json:"window"`
}

// TraceView answers a trace request. Path is present only when spans were read.
type TraceView struct {
	Org      model.ID           `json:"org"`
	Project  model.ID           `json:"project"`
	Trace    model.ID           `json:"trace"`
	State    ViewState          `json:"state"`
	Reason   string             `json:"reason,omitempty"`
	Partial  bool               `json:"partial"`
	Path     *traces.PathResult `json:"path,omitempty"`
	Sections []ViewSection      `json:"sections"`
}

func traceViewOf(body TraceBody, state ViewState, reason string) TraceView {
	return TraceView{Org: body.Org, Project: body.Project, Trace: body.Trace, State: state, Reason: reason, Sections: []ViewSection{{Name: "spans", State: state, Reason: reason}}}
}

func validTrace(body TraceBody) error {
	if body.Project == (model.ID{}) || body.Trace == (model.ID{}) || body.Window.End <= body.Window.Start {
		return invalid("trace_request_invalid")
	}
	return nil
}

// View reads and analyzes one trace under the caller's own authority.
func (t *Traces) View(ctx context.Context, authority *auth.Service, credential auth.Credential, body TraceBody) (TraceView, auth.Scope, error) {
	if err := validTrace(body); err != nil {
		return TraceView{}, auth.Scope{}, err
	}
	scope, err := queryScope(ctx, authority, credential, body.ScopeFields, []model.ID{body.Project}, nil)
	if err != nil {
		return TraceView{}, auth.Scope{}, err
	}
	if !scope.AllowsProject(body.Project) {
		return TraceView{}, auth.Scope{}, model.Fail(model.NotFound)
	}
	if t == nil || t.source == nil {
		return traceViewOf(body, StateNotAvailable, ReasonSpanSourceNotWired), scope, nil
	}
	set, err := t.source.TraceSpans(ctx, scope, body.Project, body.Trace, body.Window)
	if err != nil {
		return TraceView{}, auth.Scope{}, err
	}
	for i := range set.Spans {
		if set.Spans[i].Trace != body.Trace {
			return TraceView{}, auth.Scope{}, model.Fail(model.Corrupt)
		}
	}
	if len(set.Spans) == 0 {
		// Inside an authorized scope no visible span is an honest empty state, never
		// an absence claim: the window, a missing shard or a retention boundary may
		// explain it. Out-of-scope callers were already refused above.
		if set.Partial {
			v := traceViewOf(body, StateIncomplete, ReasonSpansPartial)
			v.Partial = true
			return v, scope, nil
		}
		return traceViewOf(body, StateEmpty, ReasonNoSpansInWindow), scope, nil
	}
	path, err := traces.CriticalPath(set.Spans)
	switch {
	case errors.Is(err, traces.ErrTooManySpans), errors.Is(err, traces.ErrTooDeep):
		return TraceView{}, auth.Scope{}, model.Fail(model.TooLarge)
	case err != nil:
		return TraceView{}, auth.Scope{}, model.Fail(model.Corrupt)
	}
	view := traceViewOf(body, StateReady, "")
	view.Path, view.Partial = &path, set.Partial
	if set.Partial {
		view.State, view.Reason = StateIncomplete, ReasonSpansPartial
		view.Sections[0] = ViewSection{Name: "spans", State: StateIncomplete, Reason: ReasonSpansPartial}
	}
	return view, scope, nil
}

// RegisterTraceRoutes mounts the trace view. The route needs the CSRF binding of
// artifactCredential for a session caller and derives its scope from the
// caller's own credential; no body field names another principal's scope.
//
//	POST /api/v1/traces/view  TraceBody -> TraceView
func RegisterTraceRoutes(mux *http.ServeMux, authority *auth.Service, t *Traces) {
	mux.HandleFunc("POST /api/v1/traces/view", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body TraceBody
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		view, scope, err := t.View(r.Context(), authority, credential, body)
		if err == nil {
			err = authority.Revalidate(r.Context(), scope)
		}
		queryReply(w, view, err)
	})
}
