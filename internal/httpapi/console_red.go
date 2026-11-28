// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"slices"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"github.com/arynyklas/soundpost/internal/storage"
)

// This file is POST /api/v1/services/red (docs/operations/console-api.md section 6): rate, errors and duration of one
// service, computed from the owned span data of the window under the caller's own telemetry.read.
//
// The samples are the entry spans of the service (span kind server or consumer). A bucket without a sample is a gap
// (null), never 0. Quantiles are exact over the scanned spans up to a scan cap. The numbers describe the stored spans:
// when a stored span carries a sample probability below 1, the answer is incomplete (spans_sampled) because counts of a
// sampled stream are not request counts.

// Bounds of the RED computation.
const (
	// MaxREDPoints is the most points one series carries.
	MaxREDPoints = 120
	// minREDStepSeconds is the smallest default step.
	minREDStepSeconds = 10
	// defaultREDPoints is how many points the default step aims at.
	defaultREDPoints = 60
	// MaxREDSpans bounds the entry spans one answer counts; past it the answer is incomplete with reason scan_capped.
	MaxREDSpans = 200_000
	// maxREDRows bounds the span rows one answer reads (the spans of other kinds are read and skipped).
	maxREDRows  = 2_000_000
	maxREDBytes = 512 << 20
)

// Reasons of the RED answer.
const (
	ReasonNoSamples     = "no_samples"
	ReasonSpansSampled  = "spans_sampled"
	ReasonStepInvalid   = "step_invalid"
	reasonREDNoFinished = "no_finished_spans"
)

// ServiceREDBody is the POST /api/v1/services/red body.
type ServiceREDBody struct {
	Org         model.ID        `json:"org"`
	Projects    []model.ID      `json:"projects"`
	Service     model.ID        `json:"service"`
	Environment *model.ID       `json:"environment,omitempty"`
	Window      query.TimeRange `json:"window"`
	StepSeconds int64           `json:"step_seconds,omitempty"`
}

// REDPoint is one bucket of a scalar series; V is null for a bucket without samples.
type REDPoint struct {
	T model.Int64 `json:"t"`
	V *float64    `json:"v"`
}

// REDDurationPoint is one bucket of the duration series.
type REDDurationPoint struct {
	T     model.Int64 `json:"t"`
	P50Ms *float64    `json:"p50_ms"`
	P95Ms *float64    `json:"p95_ms"`
	P99Ms *float64    `json:"p99_ms"`
}

// REDRate is the request rate.
type REDRate struct {
	State     ViewState  `json:"state"`
	Reason    string     `json:"reason,omitempty"`
	PerSecond *float64   `json:"per_second"`
	Points    []REDPoint `json:"points"`
}

// REDErrors is the error ratio: errors over the spans with a finished outcome (ok or error).
type REDErrors struct {
	State  ViewState     `json:"state"`
	Reason string        `json:"reason,omitempty"`
	Ratio  *float64      `json:"ratio"`
	Count  *model.Uint64 `json:"count"`
	Points []REDPoint    `json:"points"`
}

// REDDuration is the exact duration quantiles over the finished spans scanned.
type REDDuration struct {
	State  ViewState          `json:"state"`
	Reason string             `json:"reason,omitempty"`
	P50Ms  *float64           `json:"p50_ms"`
	P95Ms  *float64           `json:"p95_ms"`
	P99Ms  *float64           `json:"p99_ms"`
	Points []REDDurationPoint `json:"points"`
}

// REDGap is one run of buckets without a sample, [Start, End) in nanoseconds.
type REDGap struct {
	Start model.Int64 `json:"start"`
	End   model.Int64 `json:"end"`
}

// ServiceREDView answers a RED request.
type ServiceREDView struct {
	Org         model.ID         `json:"org"`
	Service     model.ID         `json:"service"`
	State       ViewState        `json:"state"`
	Reason      string           `json:"reason,omitempty"`
	Window      query.TimeRange  `json:"window"`
	StepSeconds int64            `json:"step_seconds"`
	Rate        REDRate          `json:"rate"`
	Errors      REDErrors        `json:"errors"`
	Duration    REDDuration      `json:"duration"`
	Requests    *model.Uint64    `json:"requests"`
	Freshness   *query.Freshness `json:"freshness,omitempty"`
	Gaps        []REDGap         `json:"gaps"`
}

// ServiceRED is the handler behind POST /api/v1/services/red. The scanner may be nil.
type ServiceRED struct{ scanner SpanScanner }

// NewServiceRED binds the storage scan the spans are read through.
func NewServiceRED(scanner SpanScanner) *ServiceRED { return &ServiceRED{scanner: scanner} }

// RegisterServiceREDRoute mounts the RED metrics. The scope is derived from the caller's own credential.
//
//	POST /api/v1/services/red  ServiceREDBody -> ServiceREDView
func RegisterServiceREDRoute(mux *http.ServeMux, authority *auth.Service, r *ServiceRED) {
	mux.HandleFunc("POST /api/v1/services/red", gateScanRoute("service_red", listHandler(authority, func(ctx context.Context, c auth.Credential, b ServiceREDBody) (any, []auth.Scope, error) {
		return r.View(ctx, authority, c, b)
	})))
}

func validREDBody(b ServiceREDBody) error {
	if b.Org == (model.ID{}) || b.Service == (model.ID{}) || len(b.Projects) == 0 || len(b.Projects) > MaxInvestigationProjects {
		return invalid("red_request_invalid")
	}
	for i, p := range b.Projects {
		if p == (model.ID{}) || slices.Contains(b.Projects[:i], p) {
			return invalid("red_request_invalid")
		}
	}
	if b.Environment != nil && *b.Environment == (model.ID{}) {
		return invalid("red_request_invalid")
	}
	w := b.Window
	if w.Start < 0 || w.End <= w.Start || time.Duration(w.End-w.Start) > MaxConsoleListWindow {
		return invalid("window_invalid")
	}
	if b.StepSeconds < 0 {
		return invalid(ReasonStepInvalid)
	}
	return nil
}

// redStep is the bucket width in nanoseconds and the bucket count: the requested step, else the window over
// defaultREDPoints rounded up to whole seconds and not below minREDStepSeconds. More than MaxREDPoints buckets is refused.
func redStep(b ServiceREDBody) (step int64, buckets int, err error) {
	width := int64(b.Window.End - b.Window.Start)
	seconds := b.StepSeconds
	if seconds == 0 {
		perPoint := int64(time.Second) * defaultREDPoints
		seconds = max(minREDStepSeconds, (width+perPoint-1)/perPoint)
	}
	if seconds > int64(MaxConsoleListWindow/time.Second) {
		return 0, 0, invalid(ReasonStepInvalid)
	}
	step = seconds * int64(time.Second)
	n := (width + step - 1) / step
	if n > MaxREDPoints {
		return 0, 0, invalid(ReasonStepInvalid)
	}
	return step, int(n), nil
}

// redBuckets accumulates the entry spans of the window.
type redBuckets struct {
	start, step           int64
	count, outcomes, errs []uint64
	durations             [][]int64
	spans                 int
	sampled               bool
}

func newREDBuckets(start, step int64, n int) *redBuckets {
	return &redBuckets{start: start, step: step, count: make([]uint64, n), outcomes: make([]uint64, n), errs: make([]uint64, n), durations: make([][]int64, n)}
}

// add counts one entry span at its start time; the caller has checked the kind.
func (r *redBuckets) add(at int64, s *model.Span) bool {
	i := int((at - r.start) / r.step)
	if i < 0 || i >= len(r.count) {
		return false
	}
	r.spans++
	r.count[i]++
	switch s.Status {
	case "ok":
		r.outcomes[i]++
	case "error":
		r.outcomes[i]++
		r.errs[i]++
	}
	if d, ok := spanDuration(s); ok && s.Status != "incomplete" {
		r.durations[i] = append(r.durations[i], d)
	}
	if p := math.Float64frombits(uint64(s.SampleProbability)); p < 1 || math.IsNaN(p) {
		r.sampled = true
	}
	return true
}

// spanDuration is the observed duration of a finished span: the monotonic difference when both ends share the
// clock domain, else the wall difference, and unknown when the span has no end or the difference is negative.
func spanDuration(s *model.Span) (int64, bool) {
	if s.End == nil {
		return 0, false
	}
	if s.End.Domain == s.Start.Domain && s.End.Mono >= s.Start.Mono {
		return int64(s.End.Mono - s.Start.Mono), true
	}
	if d := int64(s.End.Wall - s.Start.Wall); d >= 0 {
		return d, true
	}
	return 0, false
}

// quantile is the exact nearest-rank quantile of a sorted sample.
func quantile(sorted []int64, q float64) float64 {
	rank := int(math.Ceil(q * float64(len(sorted))))
	rank = min(max(rank, 1), len(sorted))
	return float64(sorted[rank-1]) / float64(time.Millisecond)
}

// View computes the RED metrics of one service under the caller's own authority.
func (r *ServiceRED) View(ctx context.Context, authority *auth.Service, credential auth.Credential, body ServiceREDBody) (any, []auth.Scope, error) {
	if err := validREDBody(body); err != nil {
		return nil, nil, err
	}
	step, n, err := redStep(body)
	if err != nil {
		return nil, nil, err
	}
	scope, err := authority.Authorize(ctx, credential, body.Org, body.Projects, auth.Read)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range body.Projects {
		if !scope.AllowsProject(p) {
			return nil, nil, model.Fail(model.NotFound)
		}
	}
	projects, err := redProjects(ctx, authority, scope, body)
	if err != nil {
		return nil, nil, err
	}
	view := ServiceREDView{Org: body.Org, Service: body.Service, Window: body.Window, StepSeconds: step / int64(time.Second), Gaps: []REDGap{}}
	if r == nil || r.scanner == nil {
		return redUnavailable(view, ReasonListSourceNotWired), []auth.Scope{scope}, nil
	}
	b := newREDBuckets(int64(body.Window.Start), step, n)
	partial, capped, marks, err := r.scan(ctx, scope, projects, body, b)
	if err != nil {
		return nil, nil, err
	}
	completeness := query.CompletenessComplete
	if partial {
		completeness = query.CompletenessPartial
	}
	view.Freshness = &query.Freshness{Completeness: completeness, Watermarks: marks}
	return redFinish(view, b, partial, capped), []auth.Scope{scope}, nil
}

// redProjects are the requested projects where an active source policy admits the service (and, when named, the
// environment). The service or environment of no visible policy is the same not-found a missing project gives.
func redProjects(ctx context.Context, authority *auth.Service, scope auth.Scope, body ServiceREDBody) ([]model.ID, error) {
	services, err := authority.VisibleServices(ctx, scope)
	if err != nil {
		return nil, err
	}
	var out []model.ID
	for _, s := range services {
		if s.ID != body.Service || !slices.Contains(body.Projects, s.Project) {
			continue
		}
		if body.Environment != nil && !slices.Contains(s.Environments, *body.Environment) {
			continue
		}
		out = append(out, s.Project)
	}
	if len(out) == 0 {
		return nil, model.Fail(model.NotFound)
	}
	return out, nil
}

func redUnavailable(view ServiceREDView, reason string) ServiceREDView {
	view.State, view.Reason = StateNotAvailable, reason
	view.Rate = REDRate{State: StateNotAvailable, Reason: reason, Points: []REDPoint{}}
	view.Errors = REDErrors{State: StateNotAvailable, Reason: reason, Points: []REDPoint{}}
	view.Duration = REDDuration{State: StateNotAvailable, Reason: reason, Points: []REDDurationPoint{}}
	return view
}

// scan folds the entry spans of the service into the buckets.
func (r *ServiceRED) scan(ctx context.Context, scope auth.Scope, projects []model.ID, body ServiceREDBody, b *redBuckets) (partial, capped bool, marks []model.Cursor, err error) {
	selectors := []storage.Matcher{{Target: storage.MatchField, Name: "service_id", Op: storage.MatchEqual, Literal: storage.Literal{Kind: storage.LiteralString, String: body.Service.String()}}}
	if body.Environment != nil {
		selectors = append(selectors, storage.Matcher{Target: storage.MatchField, Name: "environment_id", Op: storage.MatchEqual, Literal: storage.Literal{Kind: storage.LiteralString, String: body.Environment.String()}})
	}
	rows, err := gateScanner(ctx, r.scanner).Scan(ctx, scope, storage.ScanRequest{
		Projects: projects, Signal: model.SpanKind, Start: body.Window.Start, End: body.Window.End, Selectors: selectors,
		Projection: []storage.Field{storage.FieldID, storage.FieldTime, storage.FieldSpan},
		Fence:      storage.ReadFence{AllowPartial: true},
	})
	if err != nil {
		return false, false, nil, err
	}
	if rows == nil {
		return false, false, nil, model.Fail(model.Corrupt)
	}
	defer rows.Close()
	marks = rows.Watermarks()
	scanned, bytes := 0, uint64(0)
	for {
		page, err := rows.Next(ctx)
		if errors.Is(err, io.EOF) {
			return partial, capped, marks, nil
		}
		if err != nil {
			return false, false, nil, err
		}
		partial = partial || page.Partial
		if len(page.Values) != page.Len() || len(page.Times) != page.Len() {
			return false, false, nil, model.Fail(model.Corrupt)
		}
		if bytes += page.Bytes; bytes > maxREDBytes {
			return partial, true, marks, nil
		}
		for i, v := range page.Values {
			s := v.Span
			if s == nil {
				return false, false, nil, model.Fail(model.Corrupt)
			}
			if scanned++; scanned > maxREDRows {
				return partial, true, marks, nil
			}
			if s.Kind != "server" && s.Kind != "consumer" {
				continue
			}
			if b.spans >= MaxREDSpans {
				return partial, true, marks, nil
			}
			b.add(int64(page.Times[i]), s)
		}
	}
}

// redFinish turns the buckets into the answer.
func redFinish(view ServiceREDView, b *redBuckets, partial, capped bool) ServiceREDView {
	n := len(b.count)
	var total, outcomes, errs uint64
	var all []int64
	view.Rate.Points, view.Errors.Points, view.Duration.Points = make([]REDPoint, n), make([]REDPoint, n), make([]REDDurationPoint, n)
	gapFrom := -1
	closeGap := func(to int) {
		if gapFrom >= 0 {
			view.Gaps = append(view.Gaps, REDGap{Start: model.Int64(b.bucketStart(gapFrom)), End: model.Int64(b.bucketStart(to))})
			gapFrom = -1
		}
	}
	for i := range n {
		t := model.Int64(b.bucketStart(i))
		seconds := float64(b.bucketStart(i+1)-b.bucketStart(i)) / float64(time.Second)
		view.Rate.Points[i], view.Errors.Points[i], view.Duration.Points[i] = REDPoint{T: t}, REDPoint{T: t}, REDDurationPoint{T: t}
		if b.count[i] == 0 {
			if gapFrom < 0 {
				gapFrom = i
			}
			continue
		}
		closeGap(i)
		total += b.count[i]
		outcomes += b.outcomes[i]
		errs += b.errs[i]
		view.Rate.Points[i].V = new(float64(b.count[i]) / seconds)
		if b.outcomes[i] > 0 {
			view.Errors.Points[i].V = new(float64(b.errs[i]) / float64(b.outcomes[i]))
		}
		if d := b.durations[i]; len(d) > 0 {
			slices.Sort(d)
			view.Duration.Points[i].P50Ms, view.Duration.Points[i].P95Ms, view.Duration.Points[i].P99Ms = new(quantile(d, 0.5)), new(quantile(d, 0.95)), new(quantile(d, 0.99))
			all = append(all, d...)
		}
	}
	closeGap(n)
	reason := ""
	switch {
	case capped:
		reason = ReasonListScanCapped
	case partial:
		reason = ReasonShardsMissing
	case b.sampled:
		reason = ReasonSpansSampled
	}
	view.State, view.Reason = StateReady, reason
	if reason != "" {
		view.State = StateIncomplete
	}
	if total == 0 {
		if reason == "" {
			view.State, view.Reason = StateEmpty, ReasonNoSamples
		}
		view.Rate.State, view.Rate.Reason = view.State, view.Reason
		view.Errors.State, view.Errors.Reason = view.State, view.Reason
		view.Duration.State, view.Duration.Reason = view.State, view.Reason
		return view
	}
	view.Requests = new(model.Uint64(total))
	window := float64(view.Window.End-view.Window.Start) / float64(time.Second)
	view.Rate.PerSecond = new(float64(total) / window)
	view.Rate.State, view.Rate.Reason = view.State, reason
	view.Errors.Count = new(model.Uint64(errs))
	view.Errors.State, view.Errors.Reason = view.State, reason
	if outcomes > 0 {
		view.Errors.Ratio = new(float64(errs) / float64(outcomes))
	} else {
		view.Errors.Count = nil
		view.Errors.State, view.Errors.Reason = StateEmpty, ReasonNoSamples
	}
	view.Duration.State, view.Duration.Reason = view.State, reason
	if len(all) > 0 {
		slices.Sort(all)
		view.Duration.P50Ms, view.Duration.P95Ms, view.Duration.P99Ms = new(quantile(all, 0.5)), new(quantile(all, 0.95)), new(quantile(all, 0.99))
	} else {
		view.Duration.State, view.Duration.Reason = StateEmpty, reasonREDNoFinished
	}
	return view
}

// bucketStart is the start time of bucket i, clamped to the end of the window for i == len.
func (r *redBuckets) bucketStart(i int) int64 { return r.start + int64(i)*r.step }
