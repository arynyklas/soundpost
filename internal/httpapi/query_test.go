// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"soundpost/internal/query"
	"soundpost/internal/query/profile"
	"strings"
	"testing"
	"time"
)

const (
	queryProm  = "promql-prometheus-3.1.0"
	queryLogql = "logql-loki-3.5.2"
	sampleTime = int64(10_000_000_000) // whole milliseconds, 10s
)

// queryEnv is the real stack behind the owned C06 routes: real control store and
// auth, real C03 ingestion over HTTPS, real C05 storage, the owned engine and
// the owned routes. Nothing here forwards to an upstream engine.
type queryEnv struct {
	*isoEnv
	engine   *query.Engine
	server   *httptest.Server
	client   *http.Client
	promSet  string
	logSet   string
	registry profile.Registry
}

func featureSetOf(t *testing.T, id string) string {
	t.Helper()
	raw, err := os.ReadFile("../../profiles/query/" + id + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		FeatureSets []struct {
			ID string `json:"id"`
		} `json:"feature_sets"`
	}
	if json.Unmarshal(raw, &p) != nil || len(p.FeatureSets) == 0 {
		t.Fatal("no feature set")
	}
	return p.FeatureSets[0].ID
}

func newQueryEnv(t *testing.T, limits query.Limits) *queryEnv {
	t.Helper()
	e := &queryEnv{isoEnv: newIsoEnv(t)}
	var err error
	if e.registry, err = profile.Load(os.DirFS("../../profiles/query")); err != nil {
		t.Fatal(err)
	}
	e.promSet, e.logSet = featureSetOf(t, queryProm), featureSetOf(t, queryLogql)
	if e.engine, err = query.New(e.gate, e.app.Auth, e.registry, limits, query.WithDeleteGenerations(e.deletes), query.WithTickets(e.cache), query.WithResultCache(e.cache)); err != nil {
		t.Fatal(err)
	}
	e.server = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterQueryRoutes(mux, e.app.Auth, e.engine)
	}).Handler)
	t.Cleanup(e.server.Close)
	e.client = e.server.Client()
	return e
}
func queryLimits() query.Limits {
	l := query.DefaultLimits()
	l.RevalidateInterval = 25 * time.Millisecond
	return l
}

// metricSource onboards a structured metric source whose policy allows the
// labels the tests admit.
func (e *queryEnv) metricSource(org, project model.ID, ids sharedIDs) sourceFixture {
	e.t.Helper()
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, RetentionDays: map[model.Kind]uint32{model.Metric: 7}, MaxBytes: 1 << 20, MaxSeries: 100, Labels: map[string][]string{"job": {"api"}, "version": {"1.2"}}}
	return e.onboard(org, project, model.NewID(), ids, policy, auth.SourcePolicyConfig{ProjectID: project, Enabled: true})
}

func (e *queryEnv) post(who person, path string, body any) (int, []byte, http.Header) {
	e.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		e.t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", e.server.URL+path, bytes.NewReader(raw))
	if who.Session.Token != "" {
		req.Header.Set("Cookie", "__Host-soundpost="+who.Session.Token)
		req.Header.Set("X-CSRF-Token", who.Session.CSRF)
	}
	req.Header.Set("Origin", e.server.URL)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out, resp.Header
}

// metricPoint admits one float sample (and optionally an exemplar trace) over
// the real ingestion route.
func (e *queryEnv) metricPoint(s sourceFixture, name string, labels model.Labels, at int64, v float64, exemplar *model.ID) {
	e.t.Helper()
	bits := model.FloatBits(math.Float64bits(v))
	e.ingest(s, model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(at), Resource: e.resource(s), Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: labels, SampleKind: "float", Value: &bits, Unit: "1", Type: "gauge", ExemplarTrace: exemplar}}})
}

type queryBody map[string]any

func (e *queryEnv) request(org model.ID, projects []model.ID, expr string, at int64) queryBody {
	ps := make([]string, len(projects))
	for i, p := range projects {
		ps[i] = p.String()
	}
	return queryBody{"org": org.String(), "language": query.LanguagePromQL, "profile": queryProm, "feature_set": e.promSet, "expression": expr,
		"evaluation": queryBody{"instant": true, "time": decimal(at), "start": "0", "end": "0", "step": "0"}, "projects": ps, "budget": queryBody{"timeout_ns": "0", "memory_bytes": "0", "max_returned": "0"}, "allow_partial": false}
}
func decimal(v int64) string {
	raw, _ := json.Marshal(model.Int64(v))
	return strings.Trim(string(raw), `"`)
}
func decodeResult(t *testing.T, raw []byte) query.Result {
	t.Helper()
	var r query.Result
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("result does not decode: %v\n%s", err, raw)
	}
	return r
}
func faultBody(t *testing.T, raw []byte) (code, detail string) {
	t.Helper()
	var f struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(raw, &f); err != nil || f.Code == "" {
		t.Fatalf("not a typed failure: %s", raw)
	}
	return f.Code, f.Detail
}

func TestOwnedQueryOverHTTPRealStorage(t *testing.T) {
	e := newQueryEnv(t, queryLimits())
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	p1, p2 := model.NewID(), model.NewID()
	org := e.org("query org", p1, p2)
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, p1, true, auth.Read)
	e.grant(org, alice, p2, true, auth.Read)
	s1 := e.metricSource(org, p1, ids)
	s2 := e.metricSource(org, p2, ids)
	api := model.Labels{{Name: "job", Value: "api"}}
	trace := model.NewID()
	e.metricPoint(s1, "up", api, sampleTime, 1, &trace)
	e.metricPoint(s2, "up", api, sampleTime, 2, nil)
	e.metricPoint(s1, "build_info", model.Labels{{Name: "version", Value: "1.2"}}, sampleTime, 1, nil)
	e.metricPoint(s1, "other_total", api, sampleTime, 5, nil)
	both := []model.ID{p1, p2}

	// Discovery -> paged labels -> exemplars -> format -> query: the full flow, as
	// the investigation UI drives it, every step a POST to an owned route.
	disc := func(body queryBody) (int, query.DiscoveryResult) {
		status, raw, _ := e.post(alice, "/api/v1/discover", body)
		var r query.DiscoveryResult
		if status == 200 {
			if err := json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
		}
		return status, r
	}
	window := queryBody{"start": decimal(sampleTime - 1000), "end": decimal(sampleTime + 1000)}
	status, names := disc(queryBody{"org": org.String(), "projects": []string{p1.String(), p2.String()}, "signal": "metric", "kind": "metric_names", "matchers": []queryBody{}, "time": window, "limit": 100})
	if status != 200 || strings.Join(names.Items, ",") != "build_info,other_total,up" || names.More || names.Freshness.Completeness != "complete" || len(names.Freshness.Watermarks) == 0 {
		t.Fatalf("metric names: %d %+v", status, names)
	}
	var gathered []string
	cursor := ""
	for page := 0; ; page++ {
		body := queryBody{"org": org.String(), "projects": []string{p1.String()}, "signal": "metric", "kind": "label_names", "matchers": []queryBody{}, "time": window, "limit": 1}
		if cursor != "" {
			body["cursor"] = cursor
		}
		status, res := disc(body)
		if status != 200 || page > 5 {
			t.Fatalf("label_names page %d: %d", page, status)
		}
		gathered = append(gathered, res.Items...)
		if res.More != (res.NextCursor != "") {
			t.Fatalf("truthful pagination: %+v", res)
		}
		if !res.More {
			break
		}
		cursor = res.NextCursor
	}
	if strings.Join(gathered, ",") != "__name__,job,version" {
		t.Fatalf("paged label names %v", gathered)
	}
	status, raw, _ := e.post(alice, "/api/v1/exemplars", queryBody{"org": org.String(), "projects": []string{p1.String(), p2.String()}, "profile": queryProm, "feature_set": e.promSet, "expression": "up", "window": window, "limit": 10})
	var ex query.ExemplarResult
	if err := json.Unmarshal(raw, &ex); err != nil || status != 200 || len(ex.Exemplars) != 1 || ex.Exemplars[0].Trace != trace || ex.Exemplars[0].Project != p1 {
		t.Fatalf("exemplars: %d %s", status, raw)
	}
	status, raw, _ = e.post(alice, "/api/v1/query/format", queryBody{"org": org.String(), "projects": []string{p1.String()}, "language": query.LanguagePromQL, "profile": queryProm, "feature_set": e.promSet, "expression": "sum   (up )"})
	var formatted query.FormatResult
	if err := json.Unmarshal(raw, &formatted); err != nil || status != 200 || formatted.Formatted != "sum(up)" {
		t.Fatalf("format: %d %s", status, raw)
	}

	status, raw, header := e.post(alice, "/api/v1/query", e.request(org, both, formatted.Formatted, sampleTime+1_000_000))
	if status != 200 || header.Get("Cache-Control") != "no-store" || !strings.HasPrefix(header.Get("Content-Type"), "application/json") {
		t.Fatalf("query: %d %s", status, raw)
	}
	res := decodeResult(t, raw)
	got := map[model.ID]uint64{}
	if len(res.Projects) != 2 {
		t.Fatalf("%s", raw)
	}
	for _, pr := range res.Projects {
		if pr.Completeness != "complete" || len(pr.Watermarks) == 0 || pr.Stats.ScansStarted == 0 || pr.Stats.RowsRead == 0 || pr.Value.Type != query.ValueVector || len(pr.Value.Vector) != 1 || len(pr.Value.Vector[0].Labels) != 0 {
			t.Fatalf("project %s: %+v", pr.ProjectID, pr)
		}
		got[pr.ProjectID] = uint64(*pr.Value.Vector[0].Sample.Float)
	}
	if got[p1] != math.Float64bits(1) || got[p2] != math.Float64bits(2) {
		t.Fatalf("colliding series were merged across projects: %v", got)
	}
	if !bytes.Contains(raw, []byte(`"float":"3ff0000000000000"`)) || !bytes.Contains(raw, []byte(`"float":"4000000000000000"`)) {
		t.Fatalf("float bits must be exact hex strings: %s", raw)
	}

	// A range evaluation streams a typed matrix per project.
	ranged := e.request(org, both, "up", 0)
	ranged["evaluation"] = queryBody{"instant": false, "time": "0", "start": decimal(sampleTime), "end": decimal(sampleTime + 2_000_000_000), "step": decimal(1_000_000_000)}
	status, raw, _ = e.post(alice, "/api/v1/query", ranged)
	if status != 200 {
		t.Fatalf("range query: %d %s", status, raw)
	}
	for _, pr := range decodeResult(t, raw).Projects {
		if pr.Value.Type != query.ValueMatrix || len(pr.Value.Matrix) != 1 || len(pr.Value.Matrix[0].Samples) != 3 {
			t.Fatalf("project %s: %+v", pr.ProjectID, pr.Value)
		}
	}

	// Own routes only: POST-only, no upstream-shaped route exists.
	for _, path := range []string{"/api/v1/query", "/api/v1/discover", "/api/v1/exemplars", "/api/v1/query/format"} {
		resp, err := e.client.Get(e.server.URL + path + "?query=up")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s must not be a query surface: %d", path, resp.StatusCode)
		}
	}
	for _, path := range []string{"/api/v1/query_range", "/api/v1/labels", "/loki/api/v1/query", "/api/v1/series"} {
		status, _, _ := e.post(alice, path, queryBody{})
		if status != http.StatusNotFound {
			t.Fatalf("%s: no upstream-compatible route may exist (%d)", path, status)
		}
	}
	if status, _, _ := e.post(person{}, "/api/v1/query", e.request(org, both, "up", sampleTime)); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", status)
	}

	// Typed failures keep their meaning instead of an upstream HTTP text.
	status, raw, _ = e.post(alice, "/api/v1/query", e.request(org, both, "sum(", sampleTime))
	var language struct {
		Code, LanguageCode, Category, Detail string
		SourceRange                          *struct{ StartByte, EndByte int } `json:"source_range"`
	}
	_ = json.Unmarshal(raw, &language)
	if status != 400 || language.Code != "language" || language.Category == "" || language.SourceRange == nil || strings.Contains(language.Detail, "sum(") {
		t.Fatalf("language error: %d %s", status, raw)
	}
	tight := e.request(org, both, "up", sampleTime+1_000_000)
	tight["budget"] = queryBody{"timeout_ns": "0", "memory_bytes": "0", "max_returned": "1"}
	status, raw, _ = e.post(alice, "/api/v1/query", tight)
	if c, _ := faultBody(t, raw); status != http.StatusTooManyRequests || c != "quota" {
		t.Fatalf("a returned-count budget is a 429 quota, not a trimmed answer: %d %s", status, raw)
	}
	unknown := e.request(org, both, "up", sampleTime)
	unknown["unexpected"] = 1
	if status, _, _ = e.post(alice, "/api/v1/query", unknown); status != 400 {
		t.Fatalf("a closed body: %d", status)
	}

	// A foreign project, another org's project and a guessed ID are one answer.
	stranger := e.user(org, "stranger@example.test")
	e.grant(org, stranger, p1, true, auth.Read)
	var first string
	for name, target := range map[string][]model.ID{"sibling": {p2}, "guess": {model.NewID()}, "both": both} {
		status, raw, _ := e.post(stranger, "/api/v1/query", e.request(org, target, "up", sampleTime))
		c, d := faultBody(t, raw)
		if status != 404 || c != "not_found" {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if first == "" {
			first = d
		} else if d != first {
			t.Fatalf("%s: denial differs", name)
		}
	}
	if u := e.engine.Usage(); u.ActiveQueries != 0 || u.MemoryUsed != 0 || u.OpenIterators != 0 || u.LeakedBytes != 0 || u.OverReleasedBytes != 0 {
		t.Fatalf("resources leaked: %+v", u)
	}
}

func TestRevocationAndDeletionBeforeRelease(t *testing.T) {
	e := newQueryEnv(t, queryLimits())
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	p := model.NewID()
	org := e.org("revoke org", p)
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, p, true, auth.Read)
	s := e.metricSource(org, p, ids)
	e.metricPoint(s, "up", model.Labels{{Name: "job", Value: "api"}}, sampleTime, 1, nil)

	type reply struct {
		status int
		raw    []byte
	}
	blocked := func() (chan reply, chan struct{}) {
		gate := e.gate.arm()
		out := make(chan reply, 1)
		go func() {
			status, raw, _ := e.post(alice, "/api/v1/query", e.request(org, []model.ID{p}, "up", sampleTime+1_000_000))
			out <- reply{status, raw}
		}()
		time.Sleep(100 * time.Millisecond) // the request reaches the held scan
		return out, gate
	}
	// Revoked while the scan is held: the guard stops the work and no value leaves.
	done, gate := blocked()
	e.grant(org, alice, p, false, auth.Read)
	select {
	case r := <-done:
		if c, _ := faultBody(t, r.raw); r.status != 404 || c != "not_found" || bytes.Contains(r.raw, []byte("projects")) {
			t.Fatalf("revoked query: %d %s", r.status, r.raw)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a revoked query kept running")
	}
	close(gate)

	// Deleted while computing: a deletion generation bump is a 409 with no value.
	e.grant(org, alice, p, true, auth.Read)
	done, gate = blocked()
	e.deletes.bump.Add(1)
	select {
	case r := <-done:
		if c, _ := faultBody(t, r.raw); r.status != 409 || c != "stale" || bytes.Contains(r.raw, []byte("projects")) {
			t.Fatalf("deleted-from query: %d %s", r.status, r.raw)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a query over deleted data kept running")
	}
	close(gate)
	e.gate.mu.Lock()
	e.gate.gate = nil
	e.gate.mu.Unlock()
	if u := e.engine.Usage(); u.ActiveQueries != 0 || u.MemoryUsed != 0 || u.OpenIterators != 0 || u.LeakedBytes != 0 {
		t.Fatalf("resources leaked: %+v", u)
	}
}

func (e *queryEnv) logQuery(who person, org, project model.ID, source *model.ID, expr string) (int, []byte) {
	body := queryBody{"org": org.String(), "language": query.LanguageLogQL, "profile": queryLogql, "feature_set": e.logSet, "expression": expr,
		"evaluation": queryBody{"instant": false, "time": "0", "start": "0", "end": "1000", "step": "1"}, "projects": []string{project.String()}, "budget": queryBody{"timeout_ns": "0", "memory_bytes": "0", "max_returned": "0"}, "allow_partial": false}
	if source != nil {
		body["permission"], body["source"] = "raw.read", source.String()
	}
	status, raw, _ := e.post(who, "/api/v1/query", body)
	return status, raw
}

func TestEffectiveSourceReaderCacheIsolation(t *testing.T) {
	e := newQueryEnv(t, queryLimits())
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	p := model.NewID()
	org := e.org("sources org", p)
	a := e.user(org, "a@example.test")
	b := e.user(org, "b@example.test")
	for _, who := range []person{a, b} {
		e.grant(org, who, p, true, auth.Read, auth.RawRead)
	}
	structured := e.metricSource(org, p, ids)
	e.metricPoint(structured, "up", model.Labels{{Name: "job", Value: "api"}}, sampleTime, 1, nil)

	// Restricted raw sources X (reader A) and Y (reader B).
	mk := func(reader person, app, text string) sourceFixture {
		source := model.NewID()
		cfg := auth.SourcePolicyConfig{ProjectID: p, Restricted: true, Readers: []model.ID{reader.ID}, Enabled: true}
		policy := e.rawPolicy(e.actor.ID)
		policy.Labels = map[string][]string{"app": {app}}
		s := e.onboard(org, p, source, ids, policy, cfg)
		ts := model.UnixNano(5)
		var msg model.Scalar
		if err := json.Unmarshal([]byte(`"`+text+`"`), &msg); err != nil {
			t.Fatal(err)
		}
		e.ingest(s, model.Record{ID: model.NewID(), Kind: model.Log, ObservedAt: 5, Resource: e.resource(s), Payload: model.Payload{Log: &model.LogRecord{Timestamp: &ts, Severity: "error", TemplateID: "raw", TemplateRevision: 1, Fields: map[string]model.Scalar{"msg": msg}, Line: text, StreamLabels: model.Labels{{Name: "app", Value: app}}, Metadata: map[string]model.Scalar{}, SourceClass: "restricted_raw"}}})
		return s
	}
	x, y := mk(a, "x", "secret-x"), mk(b, "y", "secret-y")

	status, raw := e.logQuery(a, org, p, &x.ID, `{app="x"}`)
	if status != 200 || !bytes.Contains(raw, []byte("secret-x")) || bytes.Contains(raw, []byte("secret-y")) {
		t.Fatalf("A reads X: %d %s", status, raw)
	}
	if status, raw = e.logQuery(b, org, p, &y.ID, `{app="y"}`); status != 200 || !bytes.Contains(raw, []byte("secret-y")) {
		t.Fatalf("B reads Y: %d %s", status, raw)
	}
	if status, raw = e.logQuery(b, org, p, &y.ID, `{app="x"}`); status != 200 || bytes.Contains(raw, []byte("secret")) || len(decodeResult(t, raw).Projects[0].Value.Streams) != 0 {
		t.Fatalf("B's Y scope can never select X's rows: %d %s", status, raw)
	}
	var denial string
	for name, c := range map[string]struct {
		who    person
		source model.ID
	}{"B reading X": {b, x.ID}, "A reading Y": {a, y.ID}, "A reading a guessed source": {a, model.NewID()}} {
		status, raw := e.logQuery(c.who, org, p, &c.source, `{app="x"}`)
		code, detail := faultBody(t, raw)
		if status != 404 || code != "not_found" || bytes.Contains(raw, []byte("secret")) {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if denial == "" {
			denial = detail
		} else if detail != denial {
			t.Fatalf("%s: a restricted source must be indistinguishable from a guessed one", name)
		}
	}
	// Telemetry.read never reaches restricted raw rows.
	if status, raw = e.logQuery(a, org, p, nil, `{app="x"}`); status != 200 || bytes.Contains(raw, []byte("secret")) {
		t.Fatalf("a telemetry.read scope read a restricted source: %d %s", status, raw)
	}

	// Discovery on the restricted source, with a cursor minted by A.
	discover := func(who person, source model.ID, kind, field, cursor string, limit int) (int, query.DiscoveryResult, []byte) {
		body := queryBody{"org": org.String(), "permission": "raw.read", "source": source.String(), "projects": []string{p.String()}, "signal": "log", "kind": kind, "matchers": []queryBody{}, "time": queryBody{"start": "0", "end": "1000"}, "limit": limit}
		if field != "" {
			body["field"] = field
		}
		if cursor != "" {
			body["cursor"] = cursor
		}
		status, raw, _ := e.post(who, "/api/v1/discover", body)
		var r query.DiscoveryResult
		if status == 200 {
			_ = json.Unmarshal(raw, &r)
		}
		return status, r, raw
	}
	status, page, raw := discover(a, x.ID, "label_names", "", "", 1)
	if status != 200 || strings.Join(page.Items, ",") != "app" || page.More {
		t.Fatalf("A discovers X: %d %s", status, raw)
	}
	status, vals, raw := discover(a, x.ID, "label_values", "app", "", 1)
	if status != 200 || strings.Join(vals.Items, ",") != "x" {
		t.Fatalf("A's values of X: %d %s", status, raw)
	}
	if status, _, raw = discover(b, x.ID, "label_values", "app", "", 1); status != 404 || bytes.Contains(raw, []byte(`"x"`)) {
		t.Fatalf("B discovering X: %d %s", status, raw)
	}
	if status, vals, raw = discover(b, y.ID, "label_values", "app", "", 5); status != 200 || strings.Join(vals.Items, ",") != "y" {
		t.Fatalf("B's own values: %d %s", status, raw)
	}

	// The structured query cache is keyed by effective visibility: A's warm entry is
	// not B's, though both hold the same broad grants.
	structuredQuery := func(who person) query.ProjectResult {
		status, raw, _ := e.post(who, "/api/v1/query", e.request(org, []model.ID{p}, "up", sampleTime+1_000_000))
		if status != 200 {
			t.Fatalf("%d %s", status, raw)
		}
		return decodeResult(t, raw).Projects[0]
	}
	structuredQuery(a)
	if !structuredQuery(a).Stats.Cached {
		t.Fatal("A's entry did not warm")
	}
	if structuredQuery(b).Stats.Cached {
		t.Fatal("B was served A's cache entry")
	}
	if !structuredQuery(b).Stats.Cached {
		t.Fatal("B's own entry did not warm")
	}
	if u := e.engine.Usage(); u.ActiveQueries != 0 || u.MemoryUsed != 0 || u.OpenIterators != 0 || u.LeakedBytes != 0 {
		t.Fatalf("resources leaked: %+v", u)
	}
}

// A stored line is the immutable safe rendering from the template revision that
// admitted it. Registering a new template revision later never rewrites it.
func TestHistoricalSafeLineImmutable(t *testing.T) {
	e := newQueryEnv(t, queryLimits())
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	p := model.NewID()
	org := e.org("history org", p)
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, p, true, auth.Read)
	field := func() []model.TemplateField {
		var v1, v2 model.Scalar
		_ = json.Unmarshal([]byte(`"alice"`), &v1)
		_ = json.Unmarshal([]byte(`"bob"`), &v2)
		return []model.TemplateField{{Name: "name", Type: "string", MaxBytes: 16, Sensitivity: "metadata", Values: []model.Scalar{v1, v2}}}
	}
	template := func(revision model.Revision, line string) model.LogTemplate {
		return model.LogTemplate{ID: "signin", Revision: revision, Line: line, Severity: "info", Fields: field()}
	}
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Log}, Templates: []model.LogTemplate{template(1, "user {name} signed in")}, RetentionDays: map[model.Kind]uint32{model.Log: 7}, MaxBytes: 1 << 20, MaxSeries: 100, Labels: map[string][]string{"app": {"web"}}}
	s := e.onboard(org, p, model.NewID(), ids, policy, auth.SourcePolicyConfig{ProjectID: p, Enabled: true})
	admit := func(revision model.Revision, at int64, name string) {
		var v model.Scalar
		_ = json.Unmarshal([]byte(`"`+name+`"`), &v)
		ts := model.UnixNano(at)
		batch := model.Batch{Version: 1, Project: s.Project, Source: s.ID, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: revision, Records: []model.Record{{ID: model.NewID(), Kind: model.Log, ObservedAt: ts, Resource: e.resource(s), Payload: model.Payload{Log: &model.LogRecord{Timestamp: &ts, TemplateID: "signin", TemplateRevision: revision, Fields: map[string]model.Scalar{"name": v}, StreamLabels: model.Labels{{Name: "app", Value: "web"}}, Metadata: map[string]model.Scalar{}}}}}}
		var err error
		if batch.RouteSlot, err = model.OwnerSlot(s.Org, s.Project, s.ID, batch.Producer, batch.Records[0]); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(batch)
		req, _ := http.NewRequest("POST", e.isoEnv.server.URL+"/ingest/v1/batches", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+s.Credential)
		req.Header.Set("Content-Type", "application/json")
		resp, err := e.isoEnv.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("admit revision %d: %d %s", revision, resp.StatusCode, body)
		}
	}
	lines := func() []string {
		status, raw := e.logQuery(alice, org, p, nil, `{app="web"}`)
		if status != 200 {
			t.Fatalf("%d %s", status, raw)
		}
		var out []string
		for _, st := range decodeResult(t, raw).Projects[0].Value.Streams {
			for _, entry := range st.Entries {
				out = append(out, entry.Line)
			}
		}
		return out
	}
	admit(1, 100, "alice")
	if got := lines(); strings.Join(got, "|") != "user alice signed in" {
		t.Fatalf("admission renders the line from the registered template: %v", got)
	}
	changed := policy
	changed.Revision = 2
	changed.Resources = model.ResourceRegistry{Services: []model.ID{ids.Service}, Environments: []model.ID{ids.Environment}, Builds: []model.ID{ids.Build}, Instances: []string{"opaque-instance"}}
	changed.Templates = []model.LogTemplate{template(1, "user {name} signed in"), template(2, "account {name} authenticated")}
	if _, err := e.app.Auth.ChangeSourcePolicy(e.ctx, e.actor.Cred, auth.SourcePolicyChange{CommandID: model.NewID(), Source: s.ID, ExpectedRevision: 1, Policy: changed, Reason: "history regression"}); err != nil {
		t.Fatal(err)
	}
	drain, cancel := context.WithTimeout(e.ctx, 30*time.Second)
	defer cancel()
	if err := e.app.Auth.DrainSourceFences(drain); err != nil {
		t.Fatal(err)
	}
	admit(2, 200, "bob")
	got := lines()
	if strings.Join(got, "|") != "account bob authenticated|user alice signed in" {
		t.Fatalf("an already stored line must not change when a new template revision is registered: %v", got)
	}
}

func TestQueryCancellationOverHTTPReleasesEverything(t *testing.T) {
	e := newQueryEnv(t, queryLimits())
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	p := model.NewID()
	org := e.org("cancel org", p)
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, p, true, auth.Read)
	s := e.metricSource(org, p, ids)
	e.metricPoint(s, "up", model.Labels{{Name: "job", Value: "api"}}, sampleTime, 1, nil)

	gate := e.gate.arm()
	ctx, cancel := context.WithCancel(e.ctx)
	raw, _ := json.Marshal(e.request(org, []model.ID{p}, "up", sampleTime+1_000_000))
	req, _ := http.NewRequestWithContext(ctx, "POST", e.server.URL+"/api/v1/query", bytes.NewReader(raw))
	req.Header.Set("Cookie", "__Host-soundpost="+alice.Session.Token)
	req.Header.Set("X-CSRF-Token", alice.Session.CSRF)
	req.Header.Set("Origin", e.server.URL)
	req.Header.Set("Content-Type", "application/json")
	errc := make(chan error, 1)
	go func() {
		resp, err := e.client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		errc <- err
	}()
	for deadline := time.Now().Add(5 * time.Second); e.engine.Usage().ActiveQueries == 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the query never started")
		}
	}
	cancel() // the client goes away while the scan is held
	<-errc
	deadline := time.Now().Add(10 * time.Second)
	for {
		u := e.engine.Usage()
		if u.ActiveQueries == 0 && u.MemoryUsed == 0 && u.OpenIterators == 0 {
			if u.LeakedBytes != 0 || u.OverReleasedBytes != 0 {
				t.Fatalf("%+v", u)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a cancelled request kept resources: %+v", u)
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(gate)
}
