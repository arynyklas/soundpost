// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package smoke executes the declarative smoke case files against a REAL
// in-process node: a real appcore (control Raft group, auth, C03 admission, C05
// storage), real HTTPS ingest and the owned C06 routes. It lives beside the
// conformance harness, never in a production path, and contains no oracle.
package smoke

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/storage"
	"github.com/arynyklas/soundpost/profiles"
)

// failure aborts a smoke step; Run recovers it into an error.
type failure struct{ err error }

func check(err error) {
	if err != nil {
		panic(failure{err})
	}
}
func checkf(ok bool, format string, a ...any) {
	if !ok {
		panic(failure{fmt.Errorf(format, a...)})
	}
}

// recoverFailure turns a smoke failure panic into an error; other panics propagate.
func recoverFailure(err *error) {
	switch r := recover().(type) {
	case nil:
	case failure:
		*err = r.err
	default:
		panic(r)
	}
}

type Person struct {
	ID      model.ID
	Email   string
	Session auth.Session
	Cred    auth.Credential
}

type Source struct {
	Name       string
	ID         model.ID
	Project    string
	Credential string
	Resource   model.Resource
	Cred       auth.SourceCredential
}

// gate is the scan seam with two switches: it can hold a scan open until
// released (revocation/cancellation during compute) and make data unavailable
// (a missing shard). It also counts open iterators so teardown can be checked.
type gate struct {
	inner query.Scanner
	mu    sync.Mutex
	hold  chan struct{}
	down  bool
	open  int
	held  int
}

func (g *gate) arm() chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.hold = make(chan struct{})
	return g.hold
}
func (g *gate) disarm() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.hold = nil
}
func (g *gate) setDown(v bool) { g.mu.Lock(); g.down = v; g.mu.Unlock() }
func (g *gate) openCount() int { g.mu.Lock(); defer g.mu.Unlock(); return g.open }
func (g *gate) heldCount() int { g.mu.Lock(); defer g.mu.Unlock(); return g.held }

func (g *gate) Scan(ctx context.Context, scope auth.Scope, req storage.ScanRequest) (storage.RowIterator, error) {
	g.mu.Lock()
	hold, down := g.hold, g.down
	g.mu.Unlock()
	if down {
		return nil, model.Fail(model.Unavailable)
	}
	if hold != nil {
		g.mu.Lock()
		g.held++
		g.mu.Unlock()
		select {
		case <-hold:
		case <-ctx.Done():
			g.mu.Lock()
			g.held--
			g.mu.Unlock()
			return nil, ctx.Err()
		}
		g.mu.Lock()
		g.held--
		g.mu.Unlock()
	}
	it, err := g.inner.Scan(ctx, scope, req)
	if err != nil {
		return nil, err
	}
	g.mu.Lock()
	g.open++
	g.mu.Unlock()
	return &countedRows{RowIterator: it, g: g}, nil
}

type countedRows struct {
	storage.RowIterator
	g    *gate
	once sync.Once
}

func (c *countedRows) Close() error {
	c.once.Do(func() { c.g.mu.Lock(); c.g.open--; c.g.mu.Unlock() })
	return c.RowIterator.Close()
}

type Env struct {
	ctx         context.Context
	dir         string
	app         *appcore.App
	owner       Person
	org         model.ID
	Projects    map[string]model.ID
	People      map[string]*Person
	Sources     map[string]*Source
	Names       map[string]model.ID // symbolic IDs in case files ("trace-a")
	gate        *gate
	engine      *query.Engine
	server      *httptest.Server
	client      *http.Client
	registry    profile.Registry
	Features    map[string]string
	Limits      query.Limits
	tick        int64
	ownerMember bool
}

func (e *Env) App() *appcore.App { return e.app }
func (e *Env) Org() model.ID     { return e.org }
func (e *Env) Gate() *gate       { return e.gate }
func (e *Env) Engine() *query.Engine {
	return e.engine
}

// NewEnv opens a fresh node in dir. Close it with Close.
func NewEnv(ctx context.Context, dir string) (*Env, error) {
	e := &Env{ctx: ctx, dir: dir, Projects: map[string]model.ID{}, People: map[string]*Person{}, Sources: map[string]*Source{}, Names: map[string]model.ID{}, Features: map[string]string{}}
	e.Limits = query.DefaultLimits()
	e.Limits.RevalidateInterval = 25 * time.Millisecond
	files, err := profiles.Query()
	if err != nil {
		return nil, err
	}
	if e.registry, err = profile.Load(files); err != nil {
		return nil, err
	}
	for _, id := range []string{"promql-prometheus-3.1.0", "promql-prometheus-3.13.5", "logql-loki-3.5.2"} {
		raw, err := fs.ReadFile(files, id+".json")
		if err != nil {
			return nil, err
		}
		var p struct {
			FeatureSets []struct {
				ID string `json:"id"`
			} `json:"feature_sets"`
		}
		if json.Unmarshal(raw, &p) != nil || len(p.FeatureSets) == 0 {
			return nil, fmt.Errorf("no feature set for %s", id)
		}
		e.Features[id] = p.FeatureSets[0].ID
	}
	if err = e.open(); err != nil {
		return nil, err
	}
	boot, err := e.app.Control.BootstrapToken()
	if err != nil {
		return nil, err
	}
	session, err := e.app.Auth.Bootstrap(ctx, boot, "smoke-owner@example.test", "soundpost smoke owner password 2026")
	if err != nil {
		return nil, err
	}
	cred, err := e.app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		return nil, err
	}
	e.owner = Person{ID: session.User, Session: session, Cred: cred}
	e.org = model.NewID()
	if err = e.command(e.org, "create_org", auth.AdminPayload{Name: "smoke"}); err != nil {
		return nil, err
	}
	return e, nil
}

// open (re)opens the node on e.dir and starts the owned routes. The query
// engine is built over the gate so a scan can be held, failed or counted.
func (e *Env) open() error {
	app, err := appcore.Open(e.dir)
	if err != nil {
		return err
	}
	e.app = app
	if err = app.Control.BindRuleEvaluation(); err != nil {
		var f *model.Fault
		if !errors.As(err, &f) || f.Code != model.Conflict {
			return err
		}
	}
	e.gate = &gate{inner: app.Storage}
	if e.engine, err = query.New(e.gate, app.Auth, e.registry, e.Limits, query.WithDeleteGenerations(app.Retention), query.WithTickets(app.Cache), query.WithResultCache(app.Cache)); err != nil {
		return err
	}
	e.server = httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterIngestRoutes(mux, app.Auth, app.Ingest)
		httpapi.RegisterQueryRoutes(mux, app.Auth, e.engine)
		httpapi.RegisterLiveRoutes(mux, app.Auth, app.Live)
	}).Handler)
	e.client = e.server.Client()
	return nil
}

// Restart is a whole-node restart on the same directory: every session,
// source credential and stored sample must survive it.
func (e *Env) Restart() error {
	e.server.Close()
	if err := e.app.Close(); err != nil {
		return err
	}
	e.app = nil
	if err := e.open(); err != nil {
		return err
	}
	cred, err := e.app.Auth.Authenticate(e.ctx, e.owner.Session.Token)
	if err != nil {
		return fmt.Errorf("owner session did not survive the restart: %w", err)
	}
	e.owner.Cred = cred
	for _, p := range e.People {
		if p.Cred, err = e.app.Auth.Authenticate(e.ctx, p.Session.Token); err != nil {
			return fmt.Errorf("session of %s did not survive the restart: %w", p.Email, err)
		}
	}
	for _, s := range e.Sources {
		if s.Cred, err = e.app.Auth.AuthenticateSource(e.ctx, s.Credential, "", false); err != nil {
			return fmt.Errorf("source credential %s did not survive the restart: %w", s.Name, err)
		}
	}
	return nil
}

func (e *Env) Close() {
	if e.server != nil {
		e.server.Close()
	}
	if e.app != nil {
		_ = e.app.Close()
	}
}

func (e *Env) command(org model.ID, kind string, p auth.AdminPayload) error {
	var revision model.Revision
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		return err
	}
	p.Reason = "query smoke"
	raw, _ := json.Marshal(p)
	_, err := e.app.Auth.AdminCommand(e.ctx, e.owner.Cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw})
	if err != nil {
		return fmt.Errorf("%s: %w", kind, err)
	}
	return nil
}

func (e *Env) AddProject(name string) {
	id := model.NewID()
	check(e.command(e.org, "create_project", auth.AdminPayload{ID: id, Name: name}))
	e.Projects[name] = id
	// The bootstrap owner reads raw scans to reconcile manifests; it is never a
	// principal of a case file.
	if !e.ownerMember {
		check(e.command(e.org, "membership", auth.AdminPayload{UserID: e.owner.ID, Enabled: true}))
		e.ownerMember = true
	}
	check(e.command(e.org, "grant", auth.AdminPayload{UserID: e.owner.ID, ProjectID: id, Enabled: true, Permissions: []string{string(auth.Read)}}))
}

// AddPerson creates a member and logs in over the real session path.
func (e *Env) AddPerson(name string) *Person {
	id := model.NewID()
	email := name + "@example.test"
	check(e.command(e.org, "create_user", auth.AdminPayload{ID: id, Email: email, Password: "soundpost smoke reader password"}))
	check(e.command(e.org, "membership", auth.AdminPayload{UserID: id, Enabled: true}))
	login, err := e.app.Auth.Login(e.ctx, email, "soundpost smoke reader password", "")
	check(err)
	cred, err := e.app.Auth.Authenticate(e.ctx, login.Token)
	check(err)
	p := &Person{ID: id, Email: email, Session: login, Cred: cred}
	e.People[name] = p
	return p
}

// SecondSession logs the same principal in again: a distinct session with
// identical grants.
func (e *Env) SecondSession(name string) *Person {
	p := e.People[name]
	checkf(p != nil, "unknown principal %s", name)
	login, err := e.app.Auth.Login(e.ctx, p.Email, "soundpost smoke reader password", "")
	check(err)
	cred, err := e.app.Auth.Authenticate(e.ctx, login.Token)
	check(err)
	return &Person{ID: p.ID, Email: p.Email, Session: login, Cred: cred}
}

// Grant enables or revokes a project permission. The call returns after the
// control commit; the engine revalidates against it.
func (e *Env) Grant(person, project string, enabled bool, permissions ...string) {
	p, ok := e.People[person]
	checkf(ok, "unknown principal %s", person)
	proj, ok := e.Projects[project]
	checkf(ok, "unknown project %s", project)
	check(e.command(e.org, "grant", auth.AdminPayload{UserID: p.ID, ProjectID: proj, Enabled: enabled, Permissions: permissions}))
}

// SourceSpec describes one metric or log source to onboard.
type SourceSpec struct {
	Name    string
	Project string
	Kinds   []model.Kind
	Labels  map[string][]string
	Logs    *model.LogTemplate
}

func (e *Env) AddSource(spec SourceSpec) *Source {
	id := model.NewID()
	project := e.Projects[spec.Project]
	checkf(project != (model.ID{}), "unknown project %s", spec.Project)
	r := model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "smoke-" + spec.Name, Labels: model.Labels{}}
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: spec.Kinds,
		Resources:     model.ResourceRegistry{Services: []model.ID{r.Service}, Environments: []model.ID{r.Environment}, Builds: []model.ID{r.Build}, Instances: []string{r.Instance}},
		Labels:        spec.Labels,
		RetentionDays: map[model.Kind]uint32{}, MaxBytes: 64 << 20, MaxSeries: 1000}
	for _, k := range spec.Kinds {
		policy.RetentionDays[k] = 7
	}
	if spec.Logs != nil {
		policy.Templates = []model.LogTemplate{*spec.Logs}
	}
	cfg, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: project, Enabled: true})
	check(e.command(e.org, "source_policy", auth.AdminPayload{ID: id, Config: cfg}))
	issued, err := e.app.Auth.OnboardSource(e.ctx, e.owner.Cred, auth.SourceOnboarding{CommandID: model.NewID(), Org: e.org, Project: project, Source: id, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "query smoke"})
	check(err)
	cred, err := e.app.Auth.AuthenticateSource(e.ctx, issued.Credential, "", false)
	check(err)
	s := &Source{Name: spec.Name, ID: id, Project: spec.Project, Credential: issued.Credential, Resource: r, Cred: cred}
	e.Sources[spec.Name] = s
	return s
}

// Name maps a symbolic ID from a case file ("trace-a") to a stable model ID.
func (e *Env) Name(symbol string) model.ID {
	if id, ok := e.Names[symbol]; ok {
		return id
	}
	id := model.NewID()
	e.Names[symbol] = id
	return id
}

// Ingest admits one batch over the real HTTPS route and returns the receipt cursor.
func (e *Env) Ingest(s *Source, records ...model.Record) model.Receipt {
	project := e.Projects[s.Project]
	batch := model.Batch{Version: 1, Project: project, Source: s.ID, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: records}
	var err error
	batch.RouteSlot, err = model.OwnerSlot(e.org, project, s.ID, batch.Producer, records[0])
	check(err)
	raw, _ := json.Marshal(batch)
	req, _ := http.NewRequest("POST", e.server.URL+"/ingest/v1/batches", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+s.Credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	check(err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	checkf(resp.StatusCode == 200, "ingest status %d: %s", resp.StatusCode, trim(body))
	var receipt model.Receipt
	check(json.Unmarshal(body, &receipt))
	checkf(receipt.BatchID == batch.ID, "receipt names a different batch")
	return receipt
}

// MetricRecord builds one float metric record at time ns with exact value bits.
func (e *Env) MetricRecord(s *Source, name string, labels map[string]string, timeNS int64, bits uint64, exemplar *model.ID) model.Record {
	value := model.FloatBits(bits)
	ls := model.Labels{}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		ls = append(ls, model.Label{Name: k, Value: labels[k]})
	}
	kind := "float"
	if bits == 0x7ff0000000000002 {
		kind = "stale" // the model requires the stale marker to carry its own tag
	}
	return model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(timeNS), Resource: s.Resource,
		Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: ls, SampleKind: kind, Value: &value, Unit: "1", Type: "gauge", ExemplarTrace: exemplar}}}
}

func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// Post issues a real HTTPS POST as a logged-in person (session cookie + CSRF).
func (e *Env) Post(who *Person, path string, body any) (int, []byte) {
	raw, err := json.Marshal(body)
	check(err)
	return e.PostRaw(who, path, raw, nil)
}

func (e *Env) PostRaw(who *Person, path string, raw []byte, ctx context.Context) (int, []byte) {
	if ctx == nil {
		ctx = e.ctx
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", e.server.URL+path, bytes.NewReader(raw))
	if who != nil && who.Session.Token != "" {
		req.Header.Set("Cookie", "__Host-soundpost="+who.Session.Token)
		req.Header.Set("X-CSRF-Token", who.Session.CSRF)
	}
	req.Header.Set("Origin", e.server.URL)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return 0, []byte(err.Error())
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// Do issues an arbitrary request (used for the forbidden-route checks).
func (e *Env) Do(method, path string) int {
	req, _ := http.NewRequest(method, e.server.URL+path, nil)
	req.Header.Set("Origin", e.server.URL)
	resp, err := e.client.Do(req)
	check(err)
	resp.Body.Close()
	return resp.StatusCode
}

func decimal(v int64) string { return strconv.FormatInt(v, 10) }

// QueryBody builds a flattened C06 query body.
func (e *Env) QueryBody(language, profileID, expression string, timeNS int64, projects ...string) map[string]any {
	ps := make([]string, len(projects))
	for i, p := range projects {
		id, ok := e.Projects[p]
		checkf(ok, "unknown project %s", p)
		ps[i] = id.String()
	}
	return map[string]any{"org": e.org.String(), "language": language, "profile": profileID, "feature_set": e.Features[profileID], "expression": expression,
		"evaluation": map[string]any{"instant": true, "time": decimal(timeNS), "start": "0", "end": "0", "step": "0"}, "projects": ps,
		"budget": map[string]any{"timeout_ns": "0", "memory_bytes": "0", "max_returned": "0"}, "allow_partial": false}
}

// FloatBitsOf returns the exact bit pattern of a float for expectations.
func FloatBitsOf(f float64) uint64 { return math.Float64bits(f) }
