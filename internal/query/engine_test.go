// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/value"
	"soundpost/internal/storage"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fx is a real control store and auth service (the authority every scope,
// revalidation, cache key and cursor comes from) with an injectable clock.
type fx struct {
	t       *testing.T
	ctx     context.Context
	store   *control.Store
	svc     *auth.Service
	now     atomic.Int64
	actor   auth.Credential
	session auth.Session
	deletes *bumpDeletes
}

type bumpDeletes struct {
	base auth.DeleteGenerations
	bump atomic.Uint64
	hits atomic.Int64
}

func (d *bumpDeletes) DeleteGeneration(ctx context.Context, org model.ID, projects []model.ID) (uint64, error) {
	d.hits.Add(1)
	n, err := d.base.DeleteGeneration(ctx, org, projects)
	return n + d.bump.Load(), err
}

func newFx(t *testing.T) *fx {
	t.Helper()
	f := &fx{t: t, ctx: context.Background()}
	f.now.Store(time.Now().UnixNano())
	dir := t.TempDir()
	var err error
	if f.store, err = control.Open(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	if f.svc, err = auth.NewService(auth.AuthDependencies{Control: f.store, Now: func() time.Time { return time.Unix(0, f.now.Load()) }}); err != nil {
		t.Fatal(err)
	}
	enable, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	if err = f.store.EnableSingle(enable, filepath.Join(dir, "raft-control")); err != nil {
		t.Fatal(err)
	}
	boot, _ := f.store.BootstrapToken()
	if f.session, err = f.svc.Bootstrap(f.ctx, boot, "query-owner@example.test", "query owner password 2026"); err != nil {
		t.Fatal(err)
	}
	if f.actor, err = f.svc.Authenticate(f.ctx, f.session.Token); err != nil {
		t.Fatal(err)
	}
	f.deletes = &bumpDeletes{base: f.svc.SourceLifecycleGenerations()}
	return f
}
func (f *fx) advance(d time.Duration) { f.now.Add(int64(d)) }
func (f *fx) cmd(org model.ID, kind string, p auth.AdminPayload) {
	f.t.Helper()
	var revision model.Revision
	_ = f.store.View(f.ctx, func(st control.State) error { revision = st.Revision; return nil })
	p.Reason = "query regression"
	raw, _ := json.Marshal(p)
	if _, err := f.svc.AdminCommand(f.ctx, f.actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
		f.t.Fatal(kind, err)
	}
}

// newOrg creates an organization with n projects.
func (f *fx) newOrg(name string, n int) (model.ID, []model.ID) {
	f.t.Helper()
	org := model.NewID()
	f.cmd(org, "create_org", auth.AdminPayload{Name: name})
	projects := make([]model.ID, n)
	for i := range projects {
		projects[i] = model.NewID()
		f.cmd(org, "create_project", auth.AdminPayload{ID: projects[i], Name: "p" + strconv.Itoa(i)})
	}
	return org, projects
}

type person struct {
	id   model.ID
	cred auth.Credential
}

// user creates an org member with the given permissions on each listed project.
func (f *fx) user(org model.ID, email string, projects []model.ID, permissions ...auth.Permission) person {
	f.t.Helper()
	id := model.NewID()
	f.cmd(org, "create_user", auth.AdminPayload{ID: id, Email: email, Password: "query reader password"})
	f.cmd(org, "membership", auth.AdminPayload{UserID: id, Enabled: true})
	ps := make([]string, len(permissions))
	for i, p := range permissions {
		ps[i] = string(p)
	}
	for _, project := range projects {
		f.cmd(org, "grant", auth.AdminPayload{UserID: id, ProjectID: project, Enabled: true, Permissions: ps})
	}
	login, err := f.svc.Login(f.ctx, email, "query reader password", "")
	if err != nil {
		f.t.Fatal(err)
	}
	c, err := f.svc.Authenticate(f.ctx, login.Token)
	if err != nil {
		f.t.Fatal(err)
	}
	return person{id: id, cred: c}
}
func (f *fx) revoke(org model.ID, who person, project model.ID, permissions ...auth.Permission) {
	ps := make([]string, len(permissions))
	for i, p := range permissions {
		ps[i] = string(p)
	}
	f.cmd(org, "grant", auth.AdminPayload{UserID: who.id, ProjectID: project, Enabled: false, Permissions: ps})
}
func (f *fx) scope(who person, org model.ID, projects ...model.ID) auth.Scope {
	f.t.Helper()
	s, err := f.svc.Authorize(f.ctx, who.cred, org, projects, auth.Read)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

// restricted registers a restricted-raw source readable only by the readers.
func (f *fx) restricted(org, project model.ID, readers ...model.ID) model.ID {
	f.t.Helper()
	source := model.NewID()
	cfg, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: project, Restricted: true, Readers: readers, Enabled: true})
	f.cmd(org, "source_policy", auth.AdminPayload{ID: source, Config: cfg})
	return source
}
func (f *fx) rawScope(who person, org, project, source model.ID) (auth.Scope, error) {
	return f.svc.AuthorizeRestrictedSource(f.ctx, who.cred, org, project, source)
}

func testRegistry(t *testing.T) profile.Registry {
	t.Helper()
	r, err := profile.Load(os.DirFS("../../profiles/query"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const (
	prom310   = "promql-prometheus-3.1.0"
	prom3135  = "promql-prometheus-3.13.5"
	logql352  = "logql-loki-3.5.2"
	testEpoch = int64(1_000_000_000_000) // far in the past, so responses are settled and cacheable
)

// featureSet returns the first registered feature set id of a profile.
func featureSet(t *testing.T, id string) string {
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
		t.Fatal("profile has no feature set")
	}
	return p.FeatureSets[0].ID
}

// countingRegistry counts profile resolutions.
type countingRegistry struct {
	inner Registry
	n     atomic.Int64
}

func (r *countingRegistry) Resolve(id, set string) (profile.Profile, error) {
	r.n.Add(1)
	return r.inner.Resolve(id, set)
}

// countingCache counts lookups of the real C02 cache.
type countingCache struct {
	*auth.Cache
	lookups atomic.Int64
	stores  atomic.Int64
}

func (c *countingCache) Lookup(ctx context.Context, scope auth.Scope, profile, query, params string) (auth.CacheResult, error) {
	c.lookups.Add(1)
	return c.Cache.Lookup(ctx, scope, profile, query, params)
}
func (c *countingCache) Store(ctx context.Context, scope auth.Scope, fill auth.CacheFill, value []byte, negative bool) error {
	c.stores.Add(1)
	return c.Cache.Store(ctx, scope, fill, value, negative)
}

type env struct {
	*fx
	store    *tstore
	registry *countingRegistry
	cache    *countingCache
	engine   *Engine
}

func (f *fx) engineWith(store *tstore, limits Limits, withCache bool) *env {
	f.t.Helper()
	e := &env{fx: f, store: store, registry: &countingRegistry{inner: testRegistry(f.t)}}
	options := []Option{WithDeleteGenerations(f.deletes), WithClock(func() time.Time { return time.Unix(0, f.now.Load()) })}
	if withCache {
		c, err := auth.NewCache(f.svc, f.deletes, 256, time.Minute)
		if err != nil {
			f.t.Fatal(err)
		}
		e.cache = &countingCache{Cache: c}
		options = append(options, WithResultCache(e.cache), WithTickets(e.cache))
	}
	var err error
	if e.engine, err = New(store, f.svc, e.registry, limits, options...); err != nil {
		f.t.Fatal(err)
	}
	return e
}
func testLimits() Limits {
	l := DefaultLimits()
	l.RevalidateInterval = 20 * time.Millisecond
	l.MaxQueueWait = 2 * time.Second
	return l
}

// trow is one stored row of the scripted C05 store.
type trow struct {
	project, source model.ID
	restricted      bool
	kind            model.Kind
	at              model.UnixNano
	id              model.ID
	payload         model.Payload
}

// tstore is a scripted storage.Scan implementation that enforces the same scope
// rules as the real engine (project membership, structured versus
// restricted-raw namespaces and the named source selector), so isolation
// outcomes come from the scope, never from the fixture. Hooks let a test hold a
// scan open, fail it, mark a page partial and count iterator lifetimes.
type tstore struct {
	mu       sync.Mutex
	rows     []trow
	pageSize int
	marks    []model.Cursor

	scans, opens, closes, closeCalls atomic.Int64
	partialPage                      int
	scanGate                         chan struct{}
	nextHook                         func(ctx context.Context, n int) error
	scanErr                          func(project model.ID) error
	requests                         []storage.ScanRequest
}

func newStore() *tstore { return &tstore{pageSize: 3} }
func (s *tstore) add(rows ...trow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range rows {
		if rows[i].id == (model.ID{}) {
			rows[i].id = model.NewID()
		}
		if rows[i].source == (model.ID{}) {
			rows[i].source = model.NewID()
		}
	}
	s.rows = append(s.rows, rows...)
}
func (s *tstore) Scan(ctx context.Context, scope auth.Scope, req storage.ScanRequest) (storage.RowIterator, error) {
	s.scans.Add(1)
	s.mu.Lock()
	s.requests = append(s.requests, req)
	gate := s.scanGate
	s.mu.Unlock()
	for _, p := range req.Projects {
		if !scope.AllowsProject(p) {
			return nil, model.Fail(model.NotFound)
		}
	}
	var wantSource model.ID
	if scope.Permission() == auth.RawRead {
		for _, m := range req.Selectors {
			if m.Name == "source_id" && m.Op == storage.MatchEqual {
				id, err := model.ParseID(m.Literal.String)
				if err == nil && scope.AllowsSource(id) {
					wantSource = id
				}
			}
		}
		if wantSource == (model.ID{}) {
			return nil, model.Fail(model.Forbidden)
		}
	}
	if s.scanErr != nil {
		for _, p := range req.Projects {
			if err := s.scanErr(p); err != nil {
				return nil, err
			}
		}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	var pages []storage.Page
	var cur storage.Page
	flush := func() {
		if cur.Len() > 0 {
			pages = append(pages, cur)
			cur = storage.Page{}
		}
	}
	s.mu.Lock()
	rows := append([]trow(nil), s.rows...)
	s.mu.Unlock()
	for _, r := range rows {
		if r.kind != req.Signal || r.at < req.Start || r.at >= req.End {
			continue
		}
		in := false
		for _, p := range req.Projects {
			in = in || p == r.project
		}
		if !in {
			continue
		}
		if r.restricted != (scope.Permission() == auth.RawRead) {
			continue
		}
		if r.restricted && r.source != wantSource {
			continue
		}
		cur.IDs = append(cur.IDs, r.id)
		cur.Times = append(cur.Times, r.at)
		cur.ObservedTimes = append(cur.ObservedTimes, r.at)
		cur.Resources = append(cur.Resources, model.Resource{Labels: model.Labels{}})
		cur.Values = append(cur.Values, r.payload)
		cur.Origins = append(cur.Origins, model.Cursor{})
		cur.Projects = append(cur.Projects, r.project)
		cur.Sources = append(cur.Sources, r.source)
		cur.Loss = append(cur.Loss, 0)
		cur.Bytes += 100
		if cur.Len() >= s.pageSize {
			flush()
		}
	}
	flush()
	s.opens.Add(1)
	return &titer{s: s, pages: pages}, nil
}

type titer struct {
	s      *tstore
	pages  []storage.Page
	n      int
	closed bool
}

func (i *titer) Next(ctx context.Context) (storage.Page, error) {
	if i.closed {
		return storage.Page{}, io.ErrClosedPipe
	}
	if err := ctx.Err(); err != nil {
		return storage.Page{}, err
	}
	if i.s.nextHook != nil {
		if err := i.s.nextHook(ctx, i.n); err != nil {
			return storage.Page{}, err
		}
	}
	if i.n >= len(i.pages) {
		return storage.Page{}, io.EOF
	}
	p := i.pages[i.n]
	i.n++
	if i.s.partialPage == i.n {
		p.Partial = true
	}
	return p, nil
}
func (i *titer) Watermarks() []model.Cursor { return i.s.marks }
func (i *titer) Close() error {
	i.s.closeCalls.Add(1)
	if !i.closed {
		i.closed = true
		i.s.closes.Add(1)
	}
	return nil
}

func bitsOf(f float64) model.FloatBits { return model.FloatBits(math.Float64bits(f)) }

func metricRow(project model.ID, name string, labels model.Labels, at int64, v float64) trow {
	b := bitsOf(v)
	return metricBitsRow(project, name, labels, at, b)
}
func metricBitsRow(project model.ID, name string, labels model.Labels, at int64, b model.FloatBits) trow {
	if labels == nil {
		labels = model.Labels{}
	}
	return trow{project: project, kind: model.Metric, at: model.UnixNano(at), payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: labels, SampleKind: "float", Value: &b, Unit: "1", Type: "gauge"}}}
}
func exemplarRow(project model.ID, name string, labels model.Labels, at int64, v float64, trace model.ID) trow {
	r := metricRow(project, name, labels, at, v)
	r.payload.Metric.ExemplarTrace = &trace
	return r
}
func histogramRow(project model.ID, name string, at int64) trow {
	h := &model.NativeHistogram{Integer: &model.IntegerHistogram{Flavor: "counter", ResetHint: "unknown", Count: 9007199254740993, PositiveSpans: []model.HistogramSpan{{Length: 1}}, PositiveBuckets: []model.DeltaBucket{7}}}
	return trow{project: project, kind: model.Metric, at: model.UnixNano(at), payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "histogram", Histogram: h, Unit: "1", Type: "histogram"}}}
}
func scalarText(t *testing.T, text string) model.Scalar {
	t.Helper()
	var s model.Scalar
	if err := json.Unmarshal([]byte(strconv.Quote(text)), &s); err != nil {
		t.Fatal(err)
	}
	return s
}
func logRow(t *testing.T, project model.ID, at int64, line string, labels model.Labels) trow {
	t.Helper()
	ts := model.UnixNano(at)
	return trow{project: project, kind: model.Log, at: ts, payload: model.Payload{Log: &model.LogRecord{Timestamp: &ts, Severity: "info", TemplateID: "t1", TemplateRevision: 1, Fields: map[string]model.Scalar{"msg": scalarText(t, line)}, Line: line, StreamLabels: labels, Metadata: map[string]model.Scalar{}, SourceClass: "structured"}}}
}
func rawLogRow(t *testing.T, project, source model.ID, at int64, line string, labels model.Labels) trow {
	r := logRow(t, project, at, line, labels)
	r.restricted = true
	r.source = source
	r.payload.Log.SourceClass = "restricted_raw"
	return r
}

func promReq(expr string, at int64, projects ...model.ID) Request {
	return Request{Language: LanguagePromQL, Profile: prom310, FeatureSet: baseFeatureSet, Expression: expr, Evaluation: Evaluation{Instant: true, Time: model.UnixNano(at)}, Projects: projects}
}
func logReq(expr string, start, end int64, projects ...model.ID) Request {
	return Request{Language: LanguageLogQL, Profile: logql352, FeatureSet: logFeatureSet, Expression: expr, Evaluation: Evaluation{Start: model.UnixNano(start), End: model.UnixNano(end), Step: 1}, Projects: projects}
}

var baseFeatureSet, logFeatureSet string

func TestMain(m *testing.M) {
	read := func(id string) string {
		raw, err := os.ReadFile("../../profiles/query/" + id + ".json")
		if err != nil {
			panic(err)
		}
		var p struct {
			FeatureSets []struct {
				ID string `json:"id"`
			} `json:"feature_sets"`
		}
		if json.Unmarshal(raw, &p) != nil || len(p.FeatureSets) == 0 {
			panic("no feature sets in " + id)
		}
		return p.FeatureSets[0].ID
	}
	baseFeatureSet = read(prom310)
	logFeatureSet = read(logql352)
	os.Exit(m.Run())
}

// code extracts the typed fault code of an error ("" if untyped).
func code(err error) model.Code { return faultCode(err) }

func requireCode(t *testing.T, err error, want model.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got success", want)
	}
	var f *model.Fault
	if !errors.As(err, &f) || f.Code != want {
		t.Fatalf("expected fault %s, got %v", want, err)
	}
}

func sortedIDs(ids ...model.ID) []model.ID {
	out := append([]model.ID(nil), ids...)
	sort.Slice(out, func(i, j int) bool { return idLess(out[i], out[j]) })
	return out
}

func sampleBits(t *testing.T, s Sample) uint64 {
	t.Helper()
	if s.Float == nil {
		t.Fatal("sample is not a float")
	}
	return uint64(*s.Float)
}

// idle asserts the engine holds no memory, iterator, queue or slot.
func (e *env) idle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var u Usage
	for time.Now().Before(deadline) {
		u = e.engine.Usage()
		if u.ActiveQueries == 0 && u.QueuedQueries == 0 && u.MemoryUsed == 0 && u.OpenIterators == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if u.ActiveQueries != 0 || u.QueuedQueries != 0 || u.MemoryUsed != 0 || u.OpenIterators != 0 || u.LeakedBytes != 0 || u.OverReleasedBytes != 0 {
		t.Fatalf("engine did not return to idle without leaks: %+v", u)
	}
	if opens, closes, calls := e.store.opens.Load(), e.store.closes.Load(), e.store.closeCalls.Load(); opens != closes || calls != opens {
		t.Fatalf("every iterator must be closed exactly once: opened %d, closed %d, Close calls %d", opens, closes, calls)
	}
}

func TestOwnedQueryEnvelope(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("envelope", 1)
	alice := f.user(org, "alice@example.test", ps, auth.Read)
	scope := f.scope(alice, org, ps...)
	st := newStore()
	groupA, groupB := model.ID{9}, model.ID{3}
	st.marks = []model.Cursor{{Group: groupA, Index: 7}, {Group: groupB, Index: 5}}
	nan := model.FloatBits(0x7ff8000000000001)
	st.add(
		metricRow(ps[0], "up", model.Labels{{Name: "job", Value: "api"}}, testEpoch, 1),
		metricBitsRow(ps[0], "ordinary_nan", nil, testEpoch, nan),
		metricBitsRow(ps[0], "gone", nil, testEpoch, 0x7ff0000000000002),
		metricRow(ps[0], "gone", nil, testEpoch-int64(time.Second), 4),
		histogramRow(ps[0], "latency", testEpoch),
		logRow(t, ps[0], testEpoch+1, "first", model.Labels{{Name: "app", Value: "web"}}),
		logRow(t, ps[0], testEpoch+2, "second", model.Labels{{Name: "app", Value: "web"}}),
	)
	e := f.engineWith(st, testLimits(), false)

	scalar, err := e.engine.Execute(f.ctx, scope, promReq("1 + 2", testEpoch, ps...))
	if err != nil {
		t.Fatal(err)
	}
	pr := scalar.Projects[0]
	if len(scalar.Projects) != 1 || pr.ProjectID != ps[0] || pr.Value.Type != ValueScalar || sampleBits(t, pr.Value.Scalar) != math.Float64bits(3) || pr.Completeness != CompletenessComplete {
		t.Fatalf("scalar envelope: %+v", pr)
	}
	if pr.Stats.ScansStarted != 0 || len(pr.Watermarks) != 0 || len(pr.Diagnostics) != 0 || pr.Stats.SamplesReturned != 1 {
		t.Fatalf("a scalar must not claim scans or read cuts: %+v", pr.Stats)
	}

	text, err := e.engine.Execute(f.ctx, scope, promReq(`"hello"`, testEpoch, ps...))
	if err != nil || text.Projects[0].Value.Type != ValueString || text.Projects[0].Value.String != "hello" {
		t.Fatalf("string result: %+v %v", text, err)
	}

	vec, err := e.engine.Execute(f.ctx, scope, promReq(`{__name__=~"up|ordinary_nan|gone"}`, testEpoch+1, ps...))
	if err != nil {
		t.Fatal(err)
	}
	v := vec.Projects[0].Value
	if v.Type != ValueVector {
		t.Fatalf("vector type %s", v.Type)
	}
	seen := map[string]uint64{}
	for _, el := range v.Vector {
		seen[el.Labels[0].Value] = sampleBits(t, el.Sample)
	}
	if len(v.Vector) != 2 || seen["up"] != math.Float64bits(1) || seen["ordinary_nan"] != uint64(nan) {
		t.Fatalf("an ordinary NaN must keep its exact bits and a stale marker must not be a user sample: %+v", seen)
	}
	marks := vec.Projects[0].Watermarks
	if len(marks) != 2 || !idLess(marks[0].Group, marks[1].Group) || marks[0].Group != groupB {
		t.Fatalf("watermarks must be ordered by group: %+v", marks)
	}
	if vec.Projects[0].Stats.ScansStarted == 0 || vec.Projects[0].Stats.RowsRead == 0 || vec.Projects[0].Stats.PagesRead == 0 || vec.Projects[0].Stats.BytesRead == 0 || vec.Projects[0].Stats.PeakMemoryBytes == 0 {
		t.Fatalf("stats are measured, not zero: %+v", vec.Projects[0].Stats)
	}

	hist, err := e.engine.Execute(f.ctx, scope, promReq("latency", testEpoch+1, ps...))
	if err != nil {
		t.Fatal(err)
	}
	h := hist.Projects[0].Value.Vector[0].Sample.Histogram
	if h == nil || h.Float == nil || h.Integer != nil || hist.Projects[0].Value.Vector[0].Sample.Float != nil || uint64(h.Float.Count) != math.Float64bits(float64(9007199254740993)) {
		t.Fatalf("a native histogram selector is the pinned exact float-histogram conversion and never a float sample: %+v", hist.Projects[0].Value.Vector)
	}

	logs, err := e.engine.Execute(f.ctx, scope, logReq(`{app="web"}`, testEpoch, testEpoch+10, ps...))
	if err != nil {
		t.Fatal(err)
	}
	lv := logs.Projects[0].Value
	if lv.Type != ValueStreams || len(lv.Streams) != 1 || len(lv.Streams[0].Entries) != 2 {
		t.Fatalf("log streams: %+v", lv)
	}
	first, second := lv.Streams[0].Entries[0], lv.Streams[0].Entries[1]
	if first.Time != model.UnixNano(testEpoch+2) || second.Time != model.UnixNano(testEpoch+1) || first.Index != 0 || second.Index != 1 || first.Line != "second" {
		t.Fatalf("nanosecond order lost: %+v", lv.Streams[0].Entries)
	}
	raw, err := json.Marshal(logs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"time":"`+strconv.FormatInt(testEpoch+2, 10)+`"`) {
		t.Fatalf("log times must be canonical nanosecond strings: %s", raw)
	}
	var round Result
	if err = json.Unmarshal(raw, &round); err != nil || round.Projects[0].Value.Streams[0].Entries[0].Time != first.Time {
		t.Fatalf("typed result must round trip: %v", err)
	}
	e.idle(t)
}

func TestProjectPartitionedEvaluation(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("partition", 2)
	alice := f.user(org, "alice@example.test", ps, auth.Read)
	scope := f.scope(alice, org, ps...)
	st := newStore()
	same := model.Labels{{Name: "job", Value: "api"}}
	st.add(metricRow(ps[0], "up", same, testEpoch, 1), metricRow(ps[1], "up", same, testEpoch, 2))
	e := f.engineWith(st, testLimits(), false)
	res, err := e.engine.Execute(f.ctx, scope, promReq("sum(up)", testEpoch+1, ps[1], ps[0]))
	if err != nil {
		t.Fatal(err)
	}
	want := sortedIDs(ps...)
	if len(res.Projects) != 2 || res.Projects[0].ProjectID != want[0] || res.Projects[1].ProjectID != want[1] {
		t.Fatalf("one result per project ordered by ID: %+v", res.Projects)
	}
	got := map[model.ID]float64{}
	for _, pr := range res.Projects {
		if len(pr.Value.Vector) != 1 || len(pr.Value.Vector[0].Labels) != 0 {
			t.Fatalf("sum(up) keeps language labels (none) and never gains a project label: %+v", pr.Value.Vector)
		}
		got[pr.ProjectID] = math.Float64frombits(sampleBits(t, pr.Value.Vector[0].Sample))
	}
	if got[ps[0]] != 1 || got[ps[1]] != 2 {
		t.Fatalf("multi-project request merged colliding language series: %v", got)
	}
	raw, err := e.engine.Execute(f.ctx, scope, promReq(`up`, testEpoch+1, ps...))
	if err != nil {
		t.Fatal(err)
	}
	for _, pr := range raw.Projects {
		if len(pr.Value.Vector) != 1 || len(pr.Value.Vector[0].Labels) != 2 {
			t.Fatalf("colliding series must each stay in their project with unchanged labels: %+v", pr.Value.Vector)
		}
	}
	e.idle(t)
}

func TestHistoricalSafeLineImmutable(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("historical", 1)
	alice := f.user(org, "alice@example.test", ps, auth.Read)
	scope := f.scope(alice, org, ps...)
	st := newStore()
	// The admitted line was rendered from template revision 1; the typed field now
	// says something else, as it would if the template were later edited. A stored
	// line is immutable: the engine never re-renders it from fields or templates.
	row := logRow(t, ps[0], testEpoch+1, "revision one: user signed in", model.Labels{{Name: "app", Value: "web"}})
	row.payload.Log.Fields = map[string]model.Scalar{"msg": scalarText(t, "revision two renders this differently")}
	row.payload.Log.TemplateRevision = 1
	st.add(row)
	e := f.engineWith(st, testLimits(), false)
	res, err := e.engine.Execute(f.ctx, scope, logReq(`{app="web"}`, testEpoch, testEpoch+10, ps...))
	if err != nil {
		t.Fatal(err)
	}
	entries := res.Projects[0].Value.Streams[0].Entries
	if len(entries) != 1 || entries[0].Line != "revision one: user signed in" {
		t.Fatalf("historical safe line changed: %+v", entries)
	}
	e.idle(t)
}

func TestScopeBeforeLookupAndCache(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("cache", 2)
	alice := f.user(org, "alice@example.test", ps[:1], auth.Read)
	bob := f.user(org, "bob@example.test", ps[:1], auth.Read, auth.RawRead)
	st := newStore()
	st.add(metricRow(ps[0], "up", model.Labels{{Name: "job", Value: "api"}}, testEpoch, 1), metricRow(ps[1], "up", model.Labels{{Name: "job", Value: "api"}}, testEpoch, 9))
	e := f.engineWith(st, testLimits(), true)
	scope := f.scope(alice, org, ps[0])

	// A project the scope does not name is rejected before a profile, cache,
	// deletion generation or the index is touched, and is byte-for-byte the same
	// answer as a project that does not exist.
	_, errForeign := e.engine.Execute(f.ctx, scope, promReq("up", testEpoch+1, ps[1]))
	_, errMissing := e.engine.Execute(f.ctx, scope, promReq("up", testEpoch+1, model.NewID()))
	requireCode(t, errForeign, model.NotFound)
	requireCode(t, errMissing, model.NotFound)
	var a, b *model.Fault
	if !errors.As(errForeign, &a) || !errors.As(errMissing, &b) || a.SafeDetail != b.SafeDetail || a.Code != b.Code {
		t.Fatalf("foreign and nonexistent projects must be indistinguishable: %v / %v", errForeign, errMissing)
	}
	if st.scans.Load() != 0 || e.registry.n.Load() != 0 || e.cache.lookups.Load() != 0 || f.deletes.hits.Load() != 0 {
		t.Fatalf("forbidden project reached an index/profile/cache/deletion read: scans=%d profile=%d cache=%d deletes=%d", st.scans.Load(), e.registry.n.Load(), e.cache.lookups.Load(), f.deletes.hits.Load())
	}

	base := promReq("up", testEpoch+1, ps[0])
	run := func(s auth.Scope, r Request) (ProjectResult, int64) {
		t.Helper()
		before := st.scans.Load()
		res, err := e.engine.Execute(f.ctx, s, r)
		if err != nil {
			t.Fatal(err)
		}
		return res.Projects[0], st.scans.Load() - before
	}
	first, scans := run(scope, base)
	if scans == 0 || first.Stats.Cached || len(first.Value.Vector) != 1 {
		t.Fatalf("first run must compute: scans=%d %+v", scans, first)
	}
	hit, scans := run(scope, base)
	if scans != 0 || !hit.Stats.Cached || len(hit.Value.Vector) != 1 || sampleBits(t, hit.Value.Vector[0].Sample) != math.Float64bits(1) {
		t.Fatalf("identical request by the identical visibility must hit: scans=%d %+v", scans, hit.Stats)
	}

	miss := func(name string, s auth.Scope, r Request) {
		t.Helper()
		pr, scans := run(s, r)
		if scans == 0 || pr.Stats.Cached {
			t.Fatalf("%s must not reuse another entry (scans=%d cached=%v)", name, scans, pr.Stats.Cached)
		}
	}
	later := base
	later.Evaluation.Time++
	miss("another evaluation time", scope, later)
	other := base
	other.Profile, other.FeatureSet = prom3135, featureSet(t, prom3135)
	miss("another profile", scope, other)
	otherExpr := promReq("up + 0", testEpoch+1, ps[0])
	miss("another query", scope, otherExpr)
	miss("another effective visibility with equal telemetry.read", f.scope(bob, org, ps[0]), base)

	f.deletes.bump.Add(1)
	miss("another delete generation", scope, base)
	hit, scans = run(scope, base)
	if scans != 0 || !hit.Stats.Cached {
		t.Fatalf("the entry stored under the new generation must hit: scans=%d", scans)
	}

	// A policy change moves the epoch: the old scope is dead and the fresh scope
	// has its own entry.
	f.cmd(org, "create_project", auth.AdminPayload{ID: model.NewID(), Name: "extra"})
	if _, err := e.engine.Execute(f.ctx, scope, base); err == nil {
		t.Fatal("a scope from an older policy epoch must be refused")
	}
	miss("another policy epoch", f.scope(alice, org, ps[0]), base)
	e.idle(t)
}

// blockedScan runs fn while the store holds its scan open.
func holdScan(t *testing.T, st *tstore, e *Engine, scope auth.Scope, req Request) (<-chan error, chan struct{}) {
	t.Helper()
	gate := make(chan struct{})
	st.mu.Lock()
	st.scanGate = gate
	st.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		res, err := e.Execute(context.Background(), scope, req)
		if err == nil && len(res.Projects) != 0 {
			err = errors.New("released")
		}
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for st.scans.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("scan never started")
		}
		time.Sleep(time.Millisecond)
	}
	return done, gate
}

func TestRevocationAndDeletionBeforeRelease(t *testing.T) {
	newCase := func(t *testing.T, interval time.Duration) (*fx, *env, person, auth.Scope, model.ID, model.ID) {
		f := newFx(t)
		org, ps := f.newOrg("revocation", 1)
		alice := f.user(org, "alice@example.test", ps, auth.Read)
		scope := f.scope(alice, org, ps...)
		st := newStore()
		st.add(metricRow(ps[0], "up", nil, testEpoch, 1))
		l := testLimits()
		l.RevalidateInterval = interval
		return f, f.engineWith(st, l, false), alice, scope, org, ps[0]
	}
	t.Run("revoked while computing, caught by the final check", func(t *testing.T) {
		f, e, alice, scope, org, project := newCase(t, 5*time.Second)
		done, gate := holdScan(t, e.store, e.engine, scope, promReq("up", testEpoch+1, project))
		f.revoke(org, alice, project, auth.Read)
		close(gate)
		err := <-done
		requireCode(t, err, model.NotFound)
		e.idle(t)
	})
	t.Run("revoked while a scan is blocked, caught by the guard", func(t *testing.T) {
		f, e, alice, scope, org, project := newCase(t, 20*time.Millisecond)
		done, _ := holdScan(t, e.store, e.engine, scope, promReq("up", testEpoch+1, project))
		f.revoke(org, alice, project, auth.Read)
		select {
		case err := <-done:
			requireCode(t, err, model.NotFound)
		case <-time.After(5 * time.Second):
			t.Fatal("a revoked query kept computing behind its blocked scan")
		}
		e.idle(t)
	})
	t.Run("deleted while computing, caught by the final check", func(t *testing.T) {
		f, e, _, scope, _, project := newCase(t, 5*time.Second)
		done, gate := holdScan(t, e.store, e.engine, scope, promReq("up", testEpoch+1, project))
		f.deletes.bump.Add(1)
		close(gate)
		requireCode(t, <-done, model.Stale)
		e.idle(t)
	})
	t.Run("deleted while a scan is blocked, caught by the guard", func(t *testing.T) {
		f, e, _, scope, _, project := newCase(t, 20*time.Millisecond)
		done, _ := holdScan(t, e.store, e.engine, scope, promReq("up", testEpoch+1, project))
		f.deletes.bump.Add(1)
		select {
		case err := <-done:
			requireCode(t, err, model.Stale)
		case <-time.After(5 * time.Second):
			t.Fatal("a query over deleted data kept computing")
		}
		e.idle(t)
	})
}

func TestRangeMatrixAndLogMetricValues(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("matrix", 1)
	alice := f.user(org, "alice@example.test", ps, auth.Read)
	scope := f.scope(alice, org, ps...)
	st := newStore()
	sec := int64(time.Second)
	for i := range 4 {
		if i == 2 {
			st.add(metricBitsRow(ps[0], "up", model.Labels{{Name: "job", Value: "api"}}, testEpoch+int64(i)*sec, 0x7ff0000000000002))
			continue
		}
		st.add(metricRow(ps[0], "up", model.Labels{{Name: "job", Value: "api"}}, testEpoch+int64(i)*sec, float64(i+1)))
	}
	for i := range 3 {
		st.add(logRow(t, ps[0], testEpoch+int64(i)*sec, "line", model.Labels{{Name: "app", Value: "web"}}))
	}
	e := f.engineWith(st, testLimits(), false)
	req := promReq("up", 0, ps...)
	req.Evaluation = Evaluation{Start: model.UnixNano(testEpoch), End: model.UnixNano(testEpoch + 3*sec), Step: model.Int64(sec)}
	res, err := e.engine.Execute(f.ctx, scope, req)
	if err != nil {
		t.Fatal(err)
	}
	v := res.Projects[0].Value
	if v.Type != ValueMatrix || len(v.Matrix) != 1 || res.Projects[0].Stats.SeriesReturned != 1 {
		t.Fatalf("%+v", v)
	}
	var got []float64
	var times []model.UnixNano
	for _, s := range v.Matrix[0].Samples {
		got = append(got, math.Float64frombits(sampleBits(t, s)))
		times = append(times, s.Time)
	}
	if fmt.Sprint(got) != "[1 2 4]" || len(times) != 3 || times[2] != model.UnixNano(testEpoch+3*sec) {
		t.Fatalf("a stale marker is the absence of a sample, never a NaN or a zero point: %v %v", got, times)
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var round Result
	if err = json.Unmarshal(raw, &round); err != nil || len(round.Projects[0].Value.Matrix[0].Samples) != 3 {
		t.Fatalf("matrix must round trip: %v", err)
	}

	metric := logReq(`count_over_time({app="web"}[10s])`, 0, 0, ps...)
	metric.Evaluation = Evaluation{Instant: true, Time: model.UnixNano(testEpoch + 5*sec)}
	lres, err := e.engine.Execute(f.ctx, scope, metric)
	if err != nil {
		t.Fatal(err)
	}
	lv := lres.Projects[0].Value
	if lv.Type != ValueVector || len(lv.Vector) != 1 || math.Float64frombits(sampleBits(t, lv.Vector[0].Sample)) != 3 {
		t.Fatalf("a LogQL metric query is a typed vector: %+v", lv)
	}
	e.idle(t)
}

func TestWireValueDropsStaleMarkersAndKeepsNaNBits(t *testing.T) {
	nan := model.FloatBits(0x7ff8000000000001)
	staleHistogram := &model.NativeHistogram{Float: &model.FloatHistogram{Flavor: "gauge", ResetHint: "unknown", Sum: value.StaleBits}}
	ls := model.Labels{{Name: "a", Value: "b"}}
	vector, counts, err := wireValue(value.Result{Type: "vector", Vector: []value.Series{
		{Labels: ls, Samples: []value.Sample{{Time: 5, Float: value.StaleBits}}},
		{Labels: ls, Samples: []value.Sample{{Time: 5, Float: nan}}},
		{Labels: ls, Samples: []value.Sample{{Time: 5, Histogram: staleHistogram}}},
	}})
	if err != nil || len(vector.Vector) != 1 || counts.samples != 1 || uint64(*vector.Vector[0].Sample.Float) != uint64(nan) {
		t.Fatalf("a stale marker (float or histogram) is absence, an ordinary NaN is a value: %+v %v", vector, err)
	}
	matrix, counts, err := wireValue(value.Result{Type: "matrix", Matrix: []value.Series{
		{Labels: ls, Samples: []value.Sample{{Time: 1, Float: bitsOf(1)}, {Time: 2, Float: value.StaleBits}, {Time: 3, Float: nan}}},
		{Labels: model.Labels{{Name: "gone", Value: "1"}}, Samples: []value.Sample{{Time: 1, Float: value.StaleBits}}},
	}})
	if err != nil || len(matrix.Matrix) != 1 || len(matrix.Matrix[0].Samples) != 2 || counts.series != 1 || counts.samples != 2 || uint64(*matrix.Matrix[0].Samples[1].Float) != uint64(nan) {
		t.Fatalf("%+v %v", matrix, err)
	}
	if _, _, err = wireValue(value.Result{Type: "scalar-ish"}); code(err) != model.Corrupt {
		t.Fatalf("an unknown engine result type is a typed corruption, not an empty answer: %v", err)
	}
	if _, _, err = wireValue(value.Result{Type: "vector", Vector: []value.Series{{Samples: nil}}}); code(err) != model.Corrupt {
		t.Fatalf("%v", err)
	}
}

type countingRows struct{ closes, nexts int }

func (c *countingRows) Next(context.Context) (storage.Page, error) {
	c.nexts++
	return storage.Page{}, io.EOF
}
func (c *countingRows) Watermarks() []model.Cursor { return nil }
func (c *countingRows) Close() error               { c.closes++; return nil }

// A scanner iterator is closed exactly once however many times a consumer calls
// Close, and the engine's open-iterator count returns to zero.
func TestTrackedIteratorClosesExactlyOnce(t *testing.T) {
	inner := &countingRows{}
	var open atomic.Int64
	rows := &trackedRows{inner: inner, open: &open, stats: &scanStats{}}
	open.Add(1)
	for range 3 {
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if inner.closes != 1 || open.Load() != 0 {
		t.Fatalf("closes %d, open %d", inner.closes, open.Load())
	}
}
