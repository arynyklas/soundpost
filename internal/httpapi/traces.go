// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/link"
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
	// ReasonLinkResolverNotWired: no C04 resolver is bound, so no span reference is reported as
	// resolved or as unavailable (never a guess).
	ReasonLinkResolverNotWired = "link_resolver_not_wired"
	// ReasonTargetsTruncated: more span references than one resolution batch holds; the rest are
	// neither resolved nor listed.
	ReasonTargetsTruncated = "targets_truncated"
)

// SpanSet is what a SpanSource returns for one trace: its spans visible to the
// scope inside the window, and whether the read was partial (missing shards).
type SpanSet struct {
	Spans []model.Span
	// Reported is, per span in order, when its producer reported it (the record's observation time);
	// empty when the source cannot say. Losses are the loss records of the producers that contributed
	// a span to this trace, for the signal span, over the read window.
	Reported []int64
	Losses   []traces.ProducerLoss
	Partial  bool
	// Errors are the error occurrences recorded inside a span of this trace (their trace and span
	// IDs name it), read under the same scope and window. A source that cannot say leaves it empty.
	Errors []ErrorRef
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
		Projection: []storage.Field{storage.FieldID, storage.FieldTime, storage.FieldSpan, storage.FieldObservedTime},
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
	sources := map[model.ID]bool{}
	for {
		page, err := rows.Next(ctx)
		if errors.Is(err, io.EOF) {
			if len(out.Spans) > 0 {
				if out.Losses, err = s.losses(ctx, scope, project, sources, window, &out.Partial); err != nil {
					return SpanSet{}, err
				}
				if out.Errors, err = s.errorRefs(ctx, scope, project, trace, window, &out.Partial); err != nil {
					return SpanSet{}, err
				}
			}
			return out, nil
		}
		if err != nil {
			return SpanSet{}, err
		}
		out.Partial = out.Partial || page.Partial
		if len(page.Values) != page.Len() {
			return SpanSet{}, model.Fail(model.Corrupt)
		}
		for i, v := range page.Values {
			if v.Span == nil || v.Span.Trace != trace {
				continue
			}
			if len(out.Spans) > traces.MaxSpans {
				return out, nil
			}
			out.Spans = append(out.Spans, copySpan(*v.Span))
			reported := int64(0)
			if len(page.ObservedTimes) == page.Len() {
				reported = int64(page.ObservedTimes[i])
			}
			out.Reported = append(out.Reported, reported)
			if len(page.Sources) == page.Len() {
				sources[page.Sources[i]] = true
			}
		}
	}
}

// losses reads the loss records of the signal span over the window and keeps those of a producer
// that contributed a span to this trace. A loss read that is itself partial marks the whole read so.
func (s storageSpans) losses(ctx context.Context, scope auth.Scope, project model.ID, sources map[model.ID]bool, window query.TimeRange, partial *bool) ([]traces.ProducerLoss, error) {
	rows, err := s.scanner.Scan(ctx, scope, storage.ScanRequest{
		Projects: []model.ID{project}, Signal: model.Loss, Start: window.Start, End: window.End,
		Projection: []storage.Field{storage.FieldID, storage.FieldTime, storage.FieldLoss},
		Fence:      storage.ReadFence{AllowPartial: true},
	})
	if err != nil {
		return nil, err
	}
	if rows == nil {
		return nil, model.Fail(model.Corrupt)
	}
	defer rows.Close()
	var out []traces.ProducerLoss
	for {
		page, err := rows.Next(ctx)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		*partial = *partial || page.Partial
		if len(page.Values) != page.Len() {
			return nil, model.Fail(model.Corrupt)
		}
		for _, v := range page.Values {
			l := v.Loss
			if l == nil || l.Signal != model.SpanKind || !sources[l.Source] {
				continue
			}
			out = append(out, traces.ProducerLoss{Source: l.Source, Producer: l.Producer, Start: model.Int64(l.Start), End: model.Int64(l.End), Reason: l.Reason, Count: l.Count})
			if len(out) > traces.MaxGaps*4 {
				return out, nil
			}
		}
	}
}

// maxErrorRefs bounds the error occurrences one trace view reads.
const maxErrorRefs = 256

// errorRefs reads the error occurrences of the window whose trace ID is this trace and keeps those
// that name a span (an occurrence that names none has no span to hang from). A partial read marks
// the whole read so.
func (s storageSpans) errorRefs(ctx context.Context, scope auth.Scope, project, trace model.ID, window query.TimeRange, partial *bool) ([]ErrorRef, error) {
	rows, err := s.scanner.Scan(ctx, scope, storage.ScanRequest{
		Projects: []model.ID{project}, Signal: model.ErrorKind, Start: window.Start, End: window.End,
		Selectors:  []storage.Matcher{{Target: storage.MatchField, Name: "trace_id", Op: storage.MatchEqual, Literal: storage.Literal{Kind: storage.LiteralString, String: trace.String()}}},
		Projection: []storage.Field{storage.FieldID, storage.FieldTime, storage.FieldError},
		Fence:      storage.ReadFence{AllowPartial: true},
	})
	if err != nil {
		return nil, err
	}
	if rows == nil {
		return nil, model.Fail(model.Corrupt)
	}
	defer rows.Close()
	var out []ErrorRef
	for {
		page, err := rows.Next(ctx)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		*partial = *partial || page.Partial
		if len(page.Values) != page.Len() {
			return nil, model.Fail(model.Corrupt)
		}
		for _, v := range page.Values {
			e := v.Error
			if e == nil || e.Trace == nil || *e.Trace != trace || e.Span == nil {
				continue
			}
			out = append(out, ErrorRef{Span: *e.Span, Occurrence: e.Occurrence})
			if len(out) >= maxErrorRefs {
				return out, nil
			}
		}
	}
}

// Traces is the handler behind POST /api/v1/traces/view. The span source may be nil.
type Traces struct {
	source SpanSource
	links  TargetResolver
}

// NewTraces binds the optional span source.
func NewTraces(source SpanSource) *Traces { return &Traces{source: source} }

// WithLinks binds the C04 resolver (the TargetResolver of the investigation: *link.Resolver implements it) the
// selected-span links are resolved through: every reference is checked against the caller's scope before any
// index is read.
// Without one the view says its links are not resolved at all.
func (t *Traces) WithLinks(r TargetResolver) *Traces {
	t.links = r
	return t
}

// LinksWired reports whether a link resolver is bound (the application binds one at Open).
func (t *Traces) LinksWired() bool { return t.links != nil }

// ErrorRef is one error occurrence recorded inside a span.
type ErrorRef struct {
	Span       model.SpanID
	Occurrence model.ID
}

// SpanTarget is one reference a span carries (the job, replay or profile it names, or an error
// occurrence recorded inside it) and whether this caller's scope can reach it. Unavailable is one
// value: a target that does not exist, is in another project or is not readable by this caller
// cannot be told apart.
type SpanTarget struct {
	Span      model.SpanID `json:"span_id"`
	Kind      string       `json:"kind"`
	ID        model.ID     `json:"id"`
	Relation  string       `json:"relation"`
	Available bool         `json:"available"`
}

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
	Targets  []SpanTarget       `json:"targets,omitempty"`
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
	path, err := traces.Analyze(set.Spans, traces.Evidence{Reported: set.Reported, Losses: set.Losses})
	switch {
	case errors.Is(err, traces.ErrInvalidEvidence):
		return TraceView{}, auth.Scope{}, model.Fail(model.Corrupt)
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
	permits := func(kind string) bool {
		return holdsTargetGrant(ctx, authority, credential, body.Org, body.Project, kind)
	}
	if view.Targets, err = t.resolveTargets(ctx, scope, body.Project, set, &view, permits); err != nil {
		return TraceView{}, auth.Scope{}, err
	}
	return view, scope, nil
}

// maxSpanTargets is how many references one trace view resolves (the C04 batch bound).
const maxSpanTargets = 128

// resolveTargets lists every job, replay, profile and error occurrence the spans of the trace name,
// once per span and kind, and resolves them through C04 under the caller's scope. Without a
// resolver nothing is resolved and the "links" section says so; it is never reported as
// unavailable. A resolution that cannot complete (the scope was revoked meanwhile) is the
// request's not-found, never a partial answer.
func (t *Traces) resolveTargets(ctx context.Context, scope auth.Scope, project model.ID, set SpanSet, view *TraceView, permits func(kind string) bool) ([]SpanTarget, error) {
	if t.links == nil {
		view.Sections = append(view.Sections, ViewSection{Name: "links", State: StateNotAvailable, Reason: ReasonLinkResolverNotWired})
		return nil, nil
	}
	type key struct {
		span model.SpanID
		kind string
		id   model.ID
	}
	seen := map[key]bool{}
	var targets []SpanTarget
	add := func(span model.SpanID, kind string, id model.ID) {
		k := key{span, kind, id}
		if id == (model.ID{}) || seen[k] {
			return
		}
		seen[k] = true
		targets = append(targets, SpanTarget{Span: span, Kind: kind, ID: id, Relation: link.RelationExplicit})
	}
	for i := range set.Spans {
		s := &set.Spans[i]
		for _, ref := range []struct {
			kind string
			id   *model.ID
		}{{"job", s.Job}, {"replay", s.Replay}, {"profile", s.Profile}} {
			if ref.id != nil {
				add(s.ID, ref.kind, *ref.id)
			}
		}
	}
	for _, e := range set.Errors {
		add(e.Span, "error", e.Occurrence)
	}
	section := ViewSection{Name: "links", State: StateReady}
	if len(targets) > maxSpanTargets {
		targets = targets[:maxSpanTargets]
		section = ViewSection{Name: "links", State: StateIncomplete, Reason: ReasonTargetsTruncated}
	}
	// A replay and a profile each need their own grant on top of the read scope (a replay is not readable by
	// telemetry.read alone): a target whose grant this caller does not hold is unavailable and is never looked up.
	grants := map[string]bool{}
	var refs []link.Reference
	var asked []int
	for i, tg := range targets {
		ok, known := grants[tg.Kind]
		if !known {
			ok = permits(tg.Kind)
			grants[tg.Kind] = ok
		}
		if !ok {
			continue
		}
		refs = append(refs, link.Reference{Project: project, Kind: tg.Kind, ID: tg.ID, Relation: tg.Relation})
		asked = append(asked, i)
	}
	if len(refs) > 0 {
		resolved, err := t.links.Resolve(ctx, scope, refs)
		if err != nil {
			return nil, err
		}
		if len(resolved) != len(refs) {
			return nil, model.Fail(model.Corrupt)
		}
		for j, i := range asked {
			targets[i].Available = resolved[j].Available
		}
	}
	view.Sections = append(view.Sections, section)
	return targets, nil
}

// holdsTargetGrant reports whether the caller holds the separate grant a target kind needs on the
// project: replay.read for a replay, profiles.read for a profile; a job and an error occurrence need
// nothing beyond the read scope the resolver already checks.
func holdsTargetGrant(ctx context.Context, authority *auth.Service, credential auth.Credential, org, project model.ID, kind string) bool {
	var permission auth.Permission
	switch kind {
	case "replay":
		permission = ReplayRead
	case "profile":
		permission = ProfilesRead
	default:
		return true
	}
	gate, err := authority.Authorize(ctx, credential, org, []model.ID{project}, permission)
	return err == nil && gate.AllowsProject(project)
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
