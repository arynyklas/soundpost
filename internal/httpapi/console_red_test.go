// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// redRig is one organization, one project and one span source, with a reader holding telemetry.read.
type redRig struct {
	*windowRig
	ids   sharedIDs
	start time.Time // a whole minute inside the last hour
}

func newREDRig(t *testing.T) *redRig {
	t.Helper()
	pol := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Operations: []string{"operation"}, RetentionDays: map[model.Kind]uint32{model.SpanKind: 7}, MaxBytes: 8 << 20, MaxSeries: 100}
	r := &redRig{start: time.Now().Add(-40 * time.Minute).Truncate(time.Minute)}
	r.windowRig = &windowRig{clEnv: newClEnv(t, 0), project: model.NewID()}
	r.org = r.isoEnv.org("red org", r.project)
	r.ids = sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	pol.Kinds = []model.Kind{model.SpanKind}
	r.src = r.onboard(r.org, r.project, model.NewID(), r.ids, pol, auth.SourcePolicyConfig{ProjectID: r.project, Enabled: true})
	r.reader = r.user(r.org, "red-reader@example.test")
	r.grant(r.org, r.reader, r.project, true, auth.Read)
	return r
}

type spanSpec struct {
	at          time.Time
	kind        string
	status      string
	duration    time.Duration
	unfinished  bool
	probability float64
}

func (r *redRig) span(s spanSpec) {
	r.t.Helper()
	if s.probability == 0 {
		s.probability = 1
	}
	var id model.SpanID
	raw := model.NewID()
	copy(id[:], raw[:8])
	domain := model.ClockDomain{Host: model.ID{1}, Boot: model.ID{2}, Runtime: model.ID{3}}
	start := model.TraceClock{Wall: model.UnixNano(s.at.UnixNano()), Mono: 1_000_000_000, Domain: domain}
	span := model.Span{Trace: model.NewID(), ID: id, Kind: s.kind, Operation: "operation", Start: start, Status: s.status, SampleProbability: model.FloatBits(math.Float64bits(s.probability)), SampleDecision: "keep"}
	if !s.unfinished {
		end := start
		end.Wall += model.UnixNano(s.duration)
		end.Mono += model.MonoNano(s.duration)
		span.End = &end
	}
	r.ingest(r.src, model.Record{ID: model.NewID(), Kind: model.SpanKind, ObservedAt: start.Wall, Resource: r.resource(r.src), Payload: model.Payload{Span: &span}})
}

func (r *redRig) red(who person, org model.ID, projects []model.ID, service model.ID, extra clBody) (int, []byte) {
	r.t.Helper()
	ids := make([]string, len(projects))
	for i, p := range projects {
		ids[i] = p.String()
	}
	body := clBody{"org": org.String(), "projects": ids, "service": service.String(),
		"window": map[string]any{"start": strconv.FormatInt(r.start.UnixNano(), 10), "end": strconv.FormatInt(r.start.Add(10*time.Minute).UnixNano(), 10)}, "step_seconds": 60}
	for k, v := range extra {
		body[k] = v
	}
	return r.post(who, "/api/v1/services/red", body)
}

func decodeRED(t *testing.T, status int, raw []byte) httpapi.ServiceREDView {
	t.Helper()
	if status != 200 {
		t.Fatalf("status %d: %s", status, raw)
	}
	var v httpapi.ServiceREDView
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("not a RED answer: %v\n%s", err, raw)
	}
	return v
}

func near(a *float64, want float64) bool { return a != nil && math.Abs(*a-want) < 1e-9 }

func TestServiceREDFromRealStoredSpans(t *testing.T) {
	r := newREDRig(t)
	ms := time.Millisecond
	at := func(minute int, sec int) time.Time {
		return r.start.Add(time.Duration(minute)*time.Minute + time.Duration(sec)*time.Second)
	}
	// minute 0: four ok server spans and one unfinished; minute 1: an error and a consumer; minute 3: spans that are not
	// entry spans; minute 5: one slow server span.
	for i, d := range []time.Duration{10 * ms, 20 * ms, 30 * ms, 40 * ms} {
		r.span(spanSpec{at: at(0, i), kind: "server", status: "ok", duration: d})
	}
	r.span(spanSpec{at: at(0, 10), kind: "server", status: "incomplete", unfinished: true})
	r.span(spanSpec{at: at(1, 0), kind: "server", status: "error", duration: 100 * ms})
	r.span(spanSpec{at: at(1, 1), kind: "consumer", status: "ok", duration: 50 * ms})
	r.span(spanSpec{at: at(3, 0), kind: "internal", status: "ok", duration: 5 * ms})
	r.span(spanSpec{at: at(3, 1), kind: "client", status: "error", duration: 5 * ms})
	r.span(spanSpec{at: at(5, 0), kind: "server", status: "ok", duration: 200 * ms})

	status, raw := r.red(r.reader, r.org, []model.ID{r.project}, r.ids.Service, nil)
	v := decodeRED(t, status, raw)
	if v.State != httpapi.StateReady || v.Reason != "" || v.StepSeconds != 60 || v.Service != r.ids.Service || v.Requests == nil || *v.Requests != 8 || v.Freshness == nil || v.Freshness.Completeness != "complete" {
		t.Fatalf("answer: %s", raw)
	}
	if !near(v.Rate.PerSecond, 8.0/600) || v.Rate.State != httpapi.StateReady || len(v.Rate.Points) != 10 {
		t.Fatalf("rate: %s", raw)
	}
	if v.Errors.Count == nil || *v.Errors.Count != 1 || !near(v.Errors.Ratio, 1.0/7) || len(v.Errors.Points) != 10 {
		t.Fatalf("errors are counted over the spans with a finished outcome: %s", raw)
	}
	if !near(v.Duration.P50Ms, 40) || !near(v.Duration.P95Ms, 200) || !near(v.Duration.P99Ms, 200) || len(v.Duration.Points) != 10 {
		t.Fatalf("exact quantiles over [10 20 30 40 50 100 200] ms: %s", raw)
	}
	if p := v.Rate.Points[0]; p.V == nil || !near(p.V, 5.0/60) {
		t.Fatalf("bucket 0 rate (the unfinished span is a request): %+v", p)
	}
	if d := v.Duration.Points[0]; !near(d.P50Ms, 20) || !near(d.P95Ms, 40) {
		t.Fatalf("bucket 0 quantiles: %+v", d)
	}
	if p := v.Errors.Points[1]; !near(p.V, 0.5) {
		t.Fatalf("bucket 1 error ratio: %+v", p)
	}
	for _, i := range []int{2, 3, 4, 6, 7, 8, 9} {
		if v.Rate.Points[i].V != nil || v.Errors.Points[i].V != nil || v.Duration.Points[i].P50Ms != nil {
			t.Fatalf("bucket %d has no sample: it is null, never 0: %s", i, raw)
		}
	}
	if !strings.Contains(string(raw), `"v":null`) || !strings.Contains(string(raw), `"p50_ms":null`) {
		t.Fatalf("gaps are null on the wire: %s", raw)
	}
	wantGaps := []httpapi.REDGap{
		{Start: model.Int64(at(2, 0).UnixNano()), End: model.Int64(at(5, 0).UnixNano())},
		{Start: model.Int64(at(6, 0).UnixNano()), End: model.Int64(at(10, 0).UnixNano())},
	}
	if len(v.Gaps) != 2 || v.Gaps[0] != wantGaps[0] || v.Gaps[1] != wantGaps[1] {
		t.Fatalf("gaps %+v, want %+v", v.Gaps, wantGaps)
	}

	// the environment narrows; the default step and the point bound
	env := r.ids.Environment
	_, raw = r.red(r.reader, r.org, []model.ID{r.project}, r.ids.Service, clBody{"environment": env.String()})
	if v = decodeRED(t, 200, raw); v.Requests == nil || *v.Requests != 8 {
		t.Fatalf("environment of the source: %s", raw)
	}
	_, raw = r.red(r.reader, r.org, []model.ID{r.project}, r.ids.Service, clBody{"step_seconds": nil})
	if v = decodeRED(t, 200, raw); v.StepSeconds != 10 || len(v.Rate.Points) != 60 {
		t.Fatalf("default step is window/60, at least 10 s: %d s, %d points", v.StepSeconds, len(v.Rate.Points))
	}
	for name, step := range map[string]int{"below the point bound": 1, "negative": -5} {
		if status, raw = r.red(r.reader, r.org, []model.ID{r.project}, r.ids.Service, clBody{"step_seconds": step}); status != 400 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}
	_, raw = r.red(r.reader, r.org, []model.ID{r.project}, r.ids.Service, clBody{"step_seconds": 5, "window": map[string]any{"start": strconv.FormatInt(r.start.UnixNano(), 10), "end": strconv.FormatInt(r.start.Add(20*time.Second).UnixNano(), 10)}})
	if v = decodeRED(t, 200, raw); len(v.Rate.Points) != 4 {
		t.Fatalf("120 points at most, a short window a few: %s", raw)
	}
}

func TestServiceREDEmptyWindowIsNoSamplesNeverZero(t *testing.T) {
	r := newREDRig(t)
	status, raw := r.red(r.reader, r.org, []model.ID{r.project}, r.ids.Service, nil)
	v := decodeRED(t, status, raw)
	if v.State != httpapi.StateEmpty || v.Reason != httpapi.ReasonNoSamples || v.Requests != nil || v.Rate.PerSecond != nil || v.Errors.Ratio != nil || v.Errors.Count != nil || v.Duration.P50Ms != nil {
		t.Fatalf("a service with no spans in the window: %s", raw)
	}
	if len(v.Gaps) != 1 || v.Gaps[0].Start != model.Int64(r.start.UnixNano()) || v.Gaps[0].End != model.Int64(r.start.Add(10*time.Minute).UnixNano()) {
		t.Fatalf("the whole window is one gap: %+v", v.Gaps)
	}
	if v.Rate.State != httpapi.StateEmpty || v.Errors.State != httpapi.StateEmpty || v.Duration.State != httpapi.StateEmpty || strings.Contains(string(raw), `"per_second":0`) || strings.Contains(string(raw), `"ratio":0`) {
		t.Fatalf("sections: %s", raw)
	}
}

func TestServiceREDSampledSpansAreIncomplete(t *testing.T) {
	r := newREDRig(t)
	r.span(spanSpec{at: r.start.Add(time.Second), kind: "server", status: "ok", duration: time.Millisecond, probability: 0.5})
	status, raw := r.red(r.reader, r.org, []model.ID{r.project}, r.ids.Service, nil)
	v := decodeRED(t, status, raw)
	if v.State != httpapi.StateIncomplete || v.Reason != httpapi.ReasonSpansSampled || v.Rate.State != httpapi.StateIncomplete || v.Requests == nil || *v.Requests != 1 {
		t.Fatalf("counts of a sampled stream are not request counts: %s", raw)
	}
}

func TestServiceREDScopeIsTheCallersOwn(t *testing.T) {
	r := newREDRig(t)
	r.span(spanSpec{at: r.start.Add(time.Second), kind: "server", status: "ok", duration: time.Millisecond})
	one := []model.ID{r.project}
	fp := model.NewID()
	fo := r.isoEnv.org("red foreign org", fp)
	foreign := r.user(fo, "red-foreign@example.test")
	r.grant(fo, foreign, fp, true, auth.Read)
	stranger := r.user(r.org, "red-stranger@example.test")
	ungranted := model.NewID()
	r.cmd(r.org, "create_project", auth.AdminPayload{ID: ungranted, Name: "other"})

	var want string
	deny := func(name string, who person, org model.ID, projects []model.ID, service model.ID, extra clBody) {
		t.Helper()
		status, raw := r.red(who, org, projects, service, extra)
		if status != 404 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if got := denial(t, status, raw); want == "" {
			want = got
		} else if got != want {
			t.Fatalf("%s is distinguishable: %s vs %s", name, got, want)
		}
	}
	deny("a service nobody admits", r.reader, r.org, one, model.NewID(), nil)
	deny("an environment no policy lists", r.reader, r.org, one, r.ids.Service, clBody{"environment": model.NewID().String()})
	deny("member without a grant", stranger, r.org, one, r.ids.Service, nil)
	deny("another organization's reader", foreign, r.org, one, r.ids.Service, nil)
	deny("own org, foreign project", foreign, fo, one, r.ids.Service, nil)
	deny("a project without a grant in the set", r.reader, r.org, []model.ID{r.project, ungranted}, r.ids.Service, nil)
	deny("a project that does not exist", r.reader, r.org, []model.ID{model.NewID()}, r.ids.Service, nil)
	// the service of this project asked through a project that does not carry it
	other := model.NewID()
	r.cmd(r.org, "create_project", auth.AdminPayload{ID: other, Name: "carries nothing"})
	r.grant(r.org, r.reader, other, true, auth.Read)
	deny("a visible project that does not carry the service", r.reader, r.org, []model.ID{other}, r.ids.Service, nil)

	many := make([]model.ID, 17)
	for i := range many {
		many[i] = model.NewID()
	}
	for name, c := range map[string]struct {
		projects []model.ID
		service  model.ID
		extra    clBody
	}{
		"17 projects": {many, r.ids.Service, nil},
		"no projects": {nil, r.ids.Service, nil},
		"no service":  {one, model.ID{}, nil},
		"unknown key": {one, r.ids.Service, clBody{"scope": "admin"}},
		"huge window": {one, r.ids.Service, clBody{"window": map[string]any{"start": "1", "end": strconv.FormatInt(int64(40*24*time.Hour), 10)}}},
	} {
		body := clBody{"org": r.org.String(), "projects": []string{}, "service": c.service.String(), "window": map[string]any{"start": "1", "end": "2"}}
		for _, p := range c.projects {
			body["projects"] = append(body["projects"].([]string), p.String())
		}
		for k, v := range c.extra {
			body[k] = v
		}
		if c.service == (model.ID{}) {
			body["service"] = ""
		}
		if status, raw := r.post(r.reader, "/api/v1/services/red", body); status != 400 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}

	r.grant(r.org, r.reader, r.project, false, auth.Read)
	deny("revoked reader", r.reader, r.org, one, r.ids.Service, nil)
}

// capScanner serves generated server spans: the RED scan cap and the partial-shard answer are exercised with more spans than
// a test should store. The service visibility and the scope are the real ones.
type capScanner struct {
	spans   int
	partial bool
	start   model.UnixNano
}

type capRows struct {
	left    int
	partial bool
	start   model.UnixNano
}

func (c *capRows) Next(context.Context) (storage.Page, error) {
	if c.left == 0 {
		return storage.Page{}, io.EOF
	}
	n := min(c.left, 1000)
	c.left -= n
	p := storage.Page{Partial: c.partial}
	clock := model.TraceClock{Wall: c.start, Mono: 10, Domain: model.ClockDomain{Host: model.ID{1}, Boot: model.ID{2}, Runtime: model.ID{3}}}
	end := clock
	end.Mono += 1_000_000
	for range n {
		p.IDs = append(p.IDs, model.ID{9})
		p.Times = append(p.Times, c.start)
		p.Values = append(p.Values, model.Payload{Span: &model.Span{Kind: "server", Status: "ok", Start: clock, End: &end, SampleProbability: model.FloatBits(math.Float64bits(1))}})
	}
	return p, nil
}
func (c *capRows) Watermarks() []model.Cursor { return nil }
func (c *capRows) Close() error               { return nil }

func (s capScanner) Scan(context.Context, auth.Scope, storage.ScanRequest) (storage.RowIterator, error) {
	return &capRows{left: s.spans, partial: s.partial, start: s.start}, nil
}

func TestServiceREDScanCapAndPartialShardsAreIncomplete(t *testing.T) {
	r := newREDRig(t)
	for name, c := range map[string]struct {
		scanner capScanner
		reason  string
		freshly string
	}{
		"scan cap":      {capScanner{spans: httpapi.MaxREDSpans + 1500, start: model.UnixNano(r.start.UnixNano())}, httpapi.ReasonListScanCapped, "complete"},
		"partial shard": {capScanner{spans: 5, partial: true, start: model.UnixNano(r.start.UnixNano())}, httpapi.ReasonShardsMissing, "partial"},
	} {
		srv := httptest.NewTLSServer(httpapi.NewServer("", r.app.Auth, nil, func(mux *http.ServeMux) {
			httpapi.RegisterServiceREDRoute(mux, r.app.Auth, httpapi.NewServiceRED(c.scanner))
		}).Handler)
		t.Cleanup(srv.Close)
		body := clBody{"org": r.org.String(), "projects": []string{r.project.String()}, "service": r.ids.Service.String(),
			"window": map[string]any{"start": strconv.FormatInt(r.start.UnixNano(), 10), "end": strconv.FormatInt(r.start.Add(10*time.Minute).UnixNano(), 10)}}
		status, raw := (&evEnv{isoEnv: r.isoEnv, srv: srv}).post(r.reader, "/api/v1/services/red", body, nil)
		v := decodeRED(t, status, raw)
		if v.State != httpapi.StateIncomplete || v.Reason != c.reason || v.Rate.State != httpapi.StateIncomplete || v.Requests == nil || v.Freshness == nil || v.Freshness.Completeness != c.freshly {
			t.Fatalf("%s: %s", name, raw)
		}
		if name == "scan cap" && *v.Requests != httpapi.MaxREDSpans {
			t.Fatalf("the answer counts exactly the scanned spans: %d", *v.Requests)
		}
		if !near(v.Duration.P50Ms, 1) {
			t.Fatalf("%s duration: %s", name, raw)
		}
	}
}

func TestServiceREDWithoutScannerIsNotAvailable(t *testing.T) {
	r := newREDRig(t)
	srv := httptest.NewTLSServer(httpapi.NewServer("", r.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterServiceREDRoute(mux, r.app.Auth, httpapi.NewServiceRED(nil))
	}).Handler)
	t.Cleanup(srv.Close)
	body := clBody{"org": r.org.String(), "projects": []string{r.project.String()}, "service": r.ids.Service.String(), "window": map[string]any{"start": "1", "end": "2"}}
	status, raw := (&evEnv{isoEnv: r.isoEnv, srv: srv}).post(r.reader, "/api/v1/services/red", body, nil)
	if v := decodeRED(t, status, raw); v.State != httpapi.StateNotAvailable || v.Reason != httpapi.ReasonListSourceNotWired || v.Requests != nil {
		t.Fatalf("%s", raw)
	}
}
