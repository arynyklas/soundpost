// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/exports"
	"soundpost/internal/httpapi"
	"soundpost/internal/link"
	"soundpost/internal/model"
	"soundpost/internal/storage"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type person struct {
	ID      model.ID
	Session auth.Session
	Cred    auth.Credential
}
type sourceFixture struct {
	ID, Org, Project         model.ID
	Credential               string
	Service, Environment, Bd model.ID
}
type isoDeletes struct {
	base auth.DeleteGenerations
	bump atomic.Uint64
}

func (d *isoDeletes) DeleteGeneration(ctx context.Context, org model.ID, projects []model.ID) (uint64, error) {
	n, err := d.base.DeleteGeneration(ctx, org, projects)
	return n + d.bump.Load(), err
}

// gatedScanner delays the real engine scan so a test can change authority while
// an export is genuinely pending.
type gatedScanner struct {
	inner exports.Scanner
	mu    sync.Mutex
	gate  chan struct{}
}

func (g *gatedScanner) arm() chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gate = make(chan struct{})
	return g.gate
}
func (g *gatedScanner) Scan(ctx context.Context, scope auth.Scope, req storage.ScanRequest) (storage.RowIterator, error) {
	g.mu.Lock()
	gate := g.gate
	g.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return g.inner.Scan(ctx, scope, req)
}

type countingRecords struct {
	inner link.Records
	scans atomic.Int64
}

func (c *countingRecords) Scan(ctx context.Context, scope auth.Scope, req storage.ScanRequest) (storage.RowIterator, error) {
	c.scans.Add(1)
	return c.inner.Scan(ctx, scope, req)
}

type isoEnv struct {
	t        *testing.T
	ctx      context.Context
	app      *appcore.App
	server   *httptest.Server
	client   *http.Client
	actor    person
	cache    *auth.Cache
	deletes  *isoDeletes
	gate     *gatedScanner
	exports  *exports.Service
	records  *countingRecords
	resolver *link.Resolver
	tick     atomic.Int64
}

func newIsoEnv(t *testing.T) *isoEnv {
	t.Helper()
	ctx := context.Background()
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &isoEnv{t: t, ctx: ctx, app: app}
	t.Cleanup(func() { app.Close() })
	boot, err := app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := app.Auth.Bootstrap(ctx, boot, "isolation-owner@example.test", "isolation owner password 2026")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	e.actor = person{ID: session.User, Session: session, Cred: cred}
	e.deletes = &isoDeletes{base: app.Auth.SourceLifecycleGenerations()}
	if e.cache, err = auth.NewCache(app.Auth, e.deletes, 256, time.Minute); err != nil {
		t.Fatal(err)
	}
	e.gate = &gatedScanner{inner: app.Storage}
	if e.exports, err = exports.New(app.Auth, e.cache, e.deletes, e.gate); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.exports.Close)
	e.records = &countingRecords{inner: app.Storage}
	if e.resolver, err = link.New(app.Auth, e.records, nil); err != nil {
		t.Fatal(err)
	}
	e.server = httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, func(mux *http.ServeMux) {
		// App.Register also serves capabilities/exports from the app's own cache
		// and scanner; this test substitutes gated/counting doubles for those two,
		// so it registers only the routes it does not override.
		httpapi.RegisterIngestRoutes(mux, app.Auth, app.Ingest)
		app.RegisterArtifactRoutes(mux)
		httpapi.RegisterCapabilityRoutes(mux, app.Auth)
		httpapi.RegisterExportRoutes(mux, app.Auth, e.exports)
	}).Handler)
	t.Cleanup(e.server.Close)
	e.client = e.server.Client()
	return e
}
func (e *isoEnv) cmd(org model.ID, kind string, p auth.AdminPayload) {
	e.t.Helper()
	var revision model.Revision
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		e.t.Fatal(err)
	}
	p.Reason = "isolation regression"
	raw, _ := json.Marshal(p)
	if _, err := e.app.Auth.AdminCommand(e.ctx, e.actor.Cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
		e.t.Fatal(kind, err)
	}
}
func (e *isoEnv) org(name string, projects ...model.ID) model.ID {
	org := model.NewID()
	e.cmd(org, "create_org", auth.AdminPayload{Name: name})
	for _, p := range projects {
		e.cmd(org, "create_project", auth.AdminPayload{ID: p, Name: "project"})
	}
	return org
}

// user creates a member and logs in over the real session path.
func (e *isoEnv) user(org model.ID, email string) person {
	e.t.Helper()
	id := model.NewID()
	e.cmd(org, "create_user", auth.AdminPayload{ID: id, Email: email, Password: "isolation reader password"})
	e.cmd(org, "membership", auth.AdminPayload{UserID: id, Enabled: true})
	login, err := e.app.Auth.Login(e.ctx, email, "isolation reader password", "")
	if err != nil {
		e.t.Fatal(err)
	}
	cred, err := e.app.Auth.Authenticate(e.ctx, login.Token)
	if err != nil {
		e.t.Fatal(err)
	}
	return person{ID: id, Session: login, Cred: cred}
}
func (e *isoEnv) grant(org model.ID, who person, project model.ID, enabled bool, permissions ...auth.Permission) {
	ps := make([]string, len(permissions))
	for i, p := range permissions {
		ps[i] = string(p)
	}
	e.cmd(org, "grant", auth.AdminPayload{UserID: who.ID, ProjectID: project, Enabled: enabled, Permissions: ps})
}
func (e *isoEnv) team(org model.ID, who person, project model.ID, permissions ...string) {
	raw, _ := json.Marshal(model.ControlTeam{Members: []model.ID{who.ID}, Projects: []model.ID{project}, Permissions: permissions, Enabled: true})
	e.cmd(org, "team", auth.AdminPayload{ID: model.NewID(), Config: raw})
}
func (e *isoEnv) resource(s sourceFixture) model.Resource {
	return model.Resource{Service: s.Service, Environment: s.Environment, Build: s.Bd, Instance: "opaque-instance", Labels: model.Labels{}}
}

// sharedIDs lets two orgs seed byte-identical resource identities.
type sharedIDs struct{ Service, Environment, Build model.ID }

func (e *isoEnv) source(org, project model.ID, ids sharedIDs, kinds []model.Kind) sourceFixture {
	e.t.Helper()
	source := model.NewID()
	cfg := auth.SourcePolicyConfig{ProjectID: project, Enabled: true}
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: kinds, Resources: model.ResourceRegistry{Services: []model.ID{ids.Service}, Environments: []model.ID{ids.Environment}, Builds: []model.ID{ids.Build}, Instances: []string{"opaque-instance"}}, RetentionDays: map[model.Kind]uint32{}, MaxBytes: 1 << 20, MaxSeries: 100}
	for _, k := range kinds {
		policy.RetentionDays[k] = 7
	}
	return e.onboard(org, project, source, ids, policy, cfg)
}
func (e *isoEnv) onboard(org, project, source model.ID, ids sharedIDs, policy model.SourcePolicy, cfg auth.SourcePolicyConfig) sourceFixture {
	e.t.Helper()
	policy.Resources = model.ResourceRegistry{Services: []model.ID{ids.Service}, Environments: []model.ID{ids.Environment}, Builds: []model.ID{ids.Build}, Instances: []string{"opaque-instance"}}
	rawCfg, _ := json.Marshal(cfg)
	e.cmd(org, "source_policy", auth.AdminPayload{ID: source, Config: rawCfg})
	issued, err := e.app.Auth.OnboardSource(e.ctx, e.actor.Cred, auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "isolation regression"})
	if err != nil {
		e.t.Fatal(err)
	}
	return sourceFixture{ID: source, Org: org, Project: project, Credential: issued.Credential, Service: ids.Service, Environment: ids.Environment, Bd: ids.Build}
}
func (e *isoEnv) ingest(s sourceFixture, record model.Record) {
	e.t.Helper()
	batch := model.Batch{Version: 1, Project: s.Project, Source: s.ID, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{record}}
	var err error
	if batch.RouteSlot, err = model.OwnerSlot(s.Org, s.Project, s.ID, batch.Producer, record); err != nil {
		e.t.Fatal(err)
	}
	raw, _ := json.Marshal(batch)
	req, _ := http.NewRequest("POST", e.server.URL+"/ingest/v1/batches", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+s.Credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		e.t.Fatalf("ingest status %d %s", resp.StatusCode, body)
	}
}
func (e *isoEnv) metric(s sourceFixture, name string) {
	value := model.FloatBits(math.Float64bits(1))
	e.ingest(s, model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(e.tick.Add(1)), Resource: e.resource(s), Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &value, Unit: "1", Type: "counter"}}})
}
func (e *isoEnv) occurrence(s sourceFixture, occurrence model.ID) {
	e.ingest(s, model.Record{ID: model.NewID(), Kind: model.ErrorKind, ObservedAt: 1, Resource: e.resource(s), Payload: model.Payload{Error: &model.ErrorOccurrence{Occurrence: occurrence, Class: "TypeError", Mechanism: "manual", Build: s.Bd, Handled: true, Frames: []model.Frame{}}}})
}
func (e *isoEnv) rawLog(s sourceFixture, text string) {
	var msg model.Scalar
	if err := json.Unmarshal([]byte(`"`+text+`"`), &msg); err != nil {
		e.t.Fatal(err)
	}
	ts := model.UnixNano(5)
	e.ingest(s, model.Record{ID: model.NewID(), Kind: model.Log, ObservedAt: 5, Resource: e.resource(s), Payload: model.Payload{Log: &model.LogRecord{Timestamp: &ts, Severity: "error", TemplateID: "raw", TemplateRevision: 1, Fields: map[string]model.Scalar{"msg": msg}, Line: text, StreamLabels: model.Labels{}, Metadata: map[string]model.Scalar{}, SourceClass: "restricted_raw"}}})
}
func (e *isoEnv) rawPolicy(owner model.ID) model.SourcePolicy {
	return model.SourcePolicy{Revision: 1, Enabled: true, Class: "restricted_raw", Kinds: []model.Kind{model.Log}, Templates: []model.LogTemplate{{ID: "raw", Revision: 1, Line: "{msg}", Severity: "error", Fields: []model.TemplateField{{Name: "msg", Type: "string", MaxBytes: 64, Sensitivity: "restricted_raw"}}}}, RetentionDays: map[model.Kind]uint32{model.Log: 7}, MaxBytes: 1 << 20, MaxSeries: 100, Expires: model.UnixNano(time.Now().Add(30 * time.Minute).UnixNano()), RawOwner: &owner, RawRationale: "isolation regression", RawMaxBytes: 128}
}

// http performs a real HTTPS request as a logged-in person.
func (e *isoEnv) call(who person, method, path string, body any) (int, []byte, http.Header) {
	e.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, merr := json.Marshal(body)
		if merr != nil {
			e.t.Fatal(merr)
		}
		reader = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, e.server.URL+path, reader)
	req.Header.Set("Cookie", "__Host-soundpost="+who.Session.Token)
	req.Header.Set("Origin", e.server.URL)
	req.Header.Set("X-CSRF-Token", who.Session.CSRF)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, resp.Header
}

// denial reduces a response to what a client may compare: status and the
// public fault code/detail (the request ID is per request by design).
func denial(t *testing.T, status int, raw []byte) string {
	t.Helper()
	var f model.Fault
	if err := json.Unmarshal(raw, &f); err != nil || f.Code == "" {
		t.Fatalf("status %d is not a safe fault: %s", status, raw)
	}
	return http.StatusText(status) + "/" + string(f.Code) + "/" + f.SafeDetail
}
func (e *isoEnv) scope(who person, org model.ID, project model.ID, p auth.Permission) (auth.Scope, error) {
	return e.app.Auth.Authorize(e.ctx, who.Cred, org, []model.ID{project}, p)
}
func faultCode(err error) model.Code {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code
	}
	return ""
}

// cachedCount is a real query path: scope, then cache, then an engine scan.
func (e *isoEnv) cachedCount(scope auth.Scope, project model.ID, name string) (count int, hit, negative bool, err error) {
	res, err := e.cache.Lookup(e.ctx, scope, "scan_count", "metric:"+name, "0..max")
	if err != nil {
		return 0, false, false, err
	}
	if res.Hit {
		if res.Negative {
			return 0, true, true, nil
		}
		var n int
		if json.Unmarshal(res.Value, &n) != nil {
			return 0, true, false, errors.New("corrupt cache value")
		}
		return n, true, false, nil
	}
	rows, err := e.app.Storage.Scan(e.ctx, scope, storage.ScanRequest{Projects: []model.ID{project}, Signal: model.Metric, Start: math.MinInt64, End: math.MaxInt64})
	if err != nil {
		return 0, false, false, err
	}
	defer rows.Close()
	for {
		page, err := rows.Next(e.ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, false, false, err
		}
		for i := range page.Len() {
			if page.Values[i].Metric != nil && page.Values[i].Metric.Name == name {
				count++
			}
		}
	}
	if count == 0 {
		return 0, false, true, e.cache.Store(e.ctx, scope, res.Fill, nil, true)
	}
	raw, _ := json.Marshal(count)
	return count, false, false, e.cache.Store(e.ctx, scope, res.Fill, raw, false)
}

func (e *isoEnv) exportCreate(who person, body exports.Request, org model.ID, permission string, source, elevation model.ID) (int, []byte) {
	status, raw, _ := e.call(who, "POST", "/api/v1/exports", httpapi.ExportRequest{Operation: "create", Org: org, Project: body.Project, Permission: permission, Source: httpapi.OptionalID(source), Elevation: httpapi.OptionalID(elevation), Signal: body.Signal, Start: body.Start, End: body.End})
	return status, raw
}
func (e *isoEnv) exportStatus(who person, org, project model.ID, permission string, source, id model.ID) (int, []byte) {
	status, raw, _ := e.call(who, "POST", "/api/v1/exports", httpapi.ExportRequest{Operation: "status", Org: org, Project: project, Permission: permission, Source: httpapi.OptionalID(source), ID: httpapi.OptionalID(id)})
	return status, raw
}
func (e *isoEnv) exportDownload(who person, org, project model.ID, permission string, source, id model.ID, ticket string) (int, []byte) {
	status, raw, _ := e.call(who, "POST", "/api/v1/exports", httpapi.ExportRequest{Operation: "download", Org: org, Project: project, Permission: permission, Source: httpapi.OptionalID(source), ID: httpapi.OptionalID(id), Ticket: ticket})
	return status, raw
}
func (e *isoEnv) waitExport(who person, org, project model.ID, permission string, source, id model.ID) exports.Operation {
	e.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		status, raw := e.exportStatus(who, org, project, permission, source, id)
		if status != 200 {
			e.t.Fatalf("status poll %d %s", status, raw)
		}
		var op exports.Operation
		if err := json.Unmarshal(raw, &op); err != nil {
			e.t.Fatal(err)
		}
		if op.Phase != "running" {
			return op
		}
		time.Sleep(25 * time.Millisecond)
	}
	e.t.Fatal("export did not finish")
	return exports.Operation{}
}
func (e *isoEnv) mustGrant(status int, raw []byte) exports.Grant {
	t := e.t
	t.Helper()
	if status != http.StatusAccepted {
		t.Fatalf("export create status %d %s", status, raw)
	}
	var g exports.Grant
	if err := json.Unmarshal(raw, &g); err != nil || g.Ticket == "" {
		t.Fatal("bad grant", err)
	}
	return g
}

func TestCrossOrgGuessedIDNegativeCacheAndLink(t *testing.T) {
	e := newIsoEnv(t)
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	p1, p2, pb := model.NewID(), model.NewID(), model.NewID()
	orgA := e.org("org A", p1, p2)
	orgB := e.org("org B", pb)
	alice := e.user(orgA, "alice@example.test") // P1 by direct grant
	bob := e.user(orgA, "bob@example.test")     // P2 only by project team
	carol := e.user(orgA, "carol@example.test") // member, no grants
	dave := e.user(orgB, "dave@example.test")
	e.grant(orgA, alice, p1, true, auth.Read)
	e.team(orgA, bob, p2, string(auth.Read))
	e.grant(orgB, dave, pb, true, auth.Read)
	kinds := []model.Kind{model.Metric, model.ErrorKind}
	sa1 := e.source(orgA, p1, ids, kinds)
	sa2 := e.source(orgA, p2, ids, kinds)
	sb := e.source(orgB, pb, ids, kinds)
	// Identical names and identical error identity in all three namespaces;
	// distinct counts so a leak of either existence or count is observable.
	shared := model.NewID()
	for _, s := range []struct {
		src sourceFixture
		n   int
	}{{sa1, 2}, {sa2, 3}, {sb, 4}} {
		for range s.n {
			e.metric(s.src, "request_total")
		}
		e.occurrence(s.src, shared)
	}
	aliceScope, err := e.scope(alice, orgA, p1, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	// Warm positive and negative caches for alice.
	for pass := range 2 {
		n, hit, _, err := e.cachedCount(aliceScope, p1, "request_total")
		if err != nil || n != 2 || hit != (pass == 1) {
			t.Fatalf("alice positive pass %d: n=%d hit=%v err=%v", pass, n, hit, err)
		}
		_, hit, neg, err := e.cachedCount(aliceScope, p1, "never_ingested")
		if err != nil || !neg || hit != (pass == 1) {
			t.Fatalf("alice negative pass %d: hit=%v neg=%v err=%v", pass, hit, neg, err)
		}
	}
	bobScope, err := e.scope(bob, orgA, p2, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	// Same org, same epoch, same query text: bob never reaches alice's warm
	// positive or negative entries and sees only his own project's count.
	n, hit, _, err := e.cachedCount(bobScope, p2, "request_total")
	if err != nil || hit || n != 3 {
		t.Fatalf("bob shared alice's cache entry or count: n=%d hit=%v err=%v", n, hit, err)
	}
	if _, hit, _, err = e.cachedCount(bobScope, p2, "never_ingested"); err != nil || hit {
		t.Fatal("bob consumed alice's warm negative entry", hit, err)
	}
	// Every unauthorized scope request is the same NotFound as a pure guess,
	// before any cache or index is consulted.
	guess := [2]model.ID{model.NewID(), model.NewID()}
	cases := []struct {
		name    string
		who     person
		org, pj model.ID
	}{
		{"foreign org existing project", dave, orgA, p1},
		{"own org foreign project", dave, orgB, p1},
		{"foreign org own project id", alice, orgB, pb},
		{"same org other project (grant)", alice, orgA, p2},
		{"same org other project (team)", bob, orgA, p1},
		{"member without grant", carol, orgA, p1},
		{"guessed org and project", dave, guess[0], guess[1]},
	}
	var want string
	for _, c := range cases {
		_, err := e.scope(c.who, c.org, c.pj, auth.Read)
		if faultCode(err) != model.NotFound {
			t.Fatalf("%s: scope error %v", c.name, err)
		}
		status, raw, _ := e.call(c.who, "GET", "/api/v1/capabilities?org="+c.org.String()+"&project="+c.pj.String(), nil)
		got := denial(t, status, raw)
		if want == "" {
			want = got
		}
		if got != want || status != 404 {
			t.Fatalf("%s: capabilities denial %q differs from %q", c.name, got, want)
		}
		status, raw = e.exportCreate(c.who, exports.Request{Project: c.pj, Signal: model.Metric, End: 10}, c.org, "", model.ID{}, model.ID{})
		if got = denial(t, status, raw); got != want {
			t.Fatalf("%s: export denial %q differs from %q", c.name, got, want)
		}
		status, raw = e.exportStatus(c.who, c.org, c.pj, "", model.ID{}, model.NewID())
		if got = denial(t, status, raw); got != want {
			t.Fatalf("%s: export status denial %q differs from %q", c.name, got, want)
		}
	}
	// Authorized callers see only their own project's real sources.
	var caps struct{ Sources []auth.VisibleSource }
	status, raw, _ := e.call(alice, "GET", "/api/v1/capabilities?org="+orgA.String()+"&project="+p1.String(), nil)
	if status != 200 || json.Unmarshal(raw, &caps) != nil || len(caps.Sources) != 1 || caps.Sources[0].ID != sa1.ID || bytes.Contains(raw, []byte(sa2.ID.String())) || bytes.Contains(raw, []byte(sb.ID.String())) {
		t.Fatalf("capabilities leaked or lost: %d %s", status, raw)
	}
	// A real export reflects only alice's two rows.
	g := e.mustGrant(e.exportCreate(alice, exports.Request{Project: p1, Signal: model.Metric, End: model.Int64(math.MaxInt64)}, orgA, "", model.ID{}, model.ID{}))
	if op := e.waitExport(alice, orgA, p1, "", model.ID{}, g.Operation.ID); op.Phase != "complete" {
		t.Fatalf("alice export phase %q reason %q", op.Phase, op.SafeReason)
	}
	status, body := e.exportDownload(alice, orgA, p1, "", model.ID{}, g.Operation.ID, g.Ticket)
	if status != 200 || strings.Count(string(body), "request_total") != 2 {
		t.Fatalf("alice export download %d rows=%d", status, strings.Count(string(body), "request_total"))
	}
	// Alice's export id and ticket are useless to anyone else, even a
	// same-org reader with the identical query shape (bob), warm or not.
	bobExport := e.mustGrant(e.exportCreate(bob, exports.Request{Project: p2, Signal: model.Metric, End: model.Int64(math.MaxInt64)}, orgA, "", model.ID{}, model.ID{}))
	e.waitExport(bob, orgA, p2, "", model.ID{}, bobExport.Operation.ID)
	status, raw = e.exportStatus(bob, orgA, p2, "", model.ID{}, g.Operation.ID)
	missing := denial(t, status, raw)
	status, raw = e.exportDownload(bob, orgA, p2, "", model.ID{}, g.Operation.ID, g.Ticket)
	if denial(t, status, raw) != missing {
		t.Fatal("foreign export download distinguishable from a missing export")
	}
	status, raw = e.exportDownload(bob, orgA, p2, "", model.ID{}, bobExport.Operation.ID, g.Ticket)
	if denial(t, status, raw) != missing {
		t.Fatal("alice's ticket opened bob's export")
	}
	// Link: same trace/occurrence ID exists in all three namespaces.
	explicit := func(project model.ID, id model.ID) link.Reference {
		return link.Reference{Project: project, Kind: "error", ID: id, Relation: link.RelationExplicit}
	}
	refs := []link.Reference{explicit(p1, shared), explicit(p2, shared), explicit(pb, shared), explicit(p1, model.NewID()), explicit(guess[1], shared)}
	e.records.scans.Store(0)
	out, err := e.resolver.Resolve(e.ctx, aliceScope, refs)
	if err != nil {
		t.Fatal(err)
	}
	if !out[0].Available || out[0].Reference == nil || out[0].Reference.ID != shared {
		t.Fatal("authorized link did not resolve")
	}
	for i := 1; i < len(out); i++ {
		if out[i] != (link.ResolvedReference{}) {
			t.Fatalf("link %d distinguishable from unavailable: %+v", i, out[i])
		}
	}
	// Only the two authorized-project references (one existing, one missing)
	// reached an index; wrong-scope and foreign targets never did.
	if got := e.records.scans.Load(); got != 2 {
		t.Fatalf("unauthorized link targets reached the index: %d scans", got)
	}
	// Warm the link path for dave, then retry alice's foreign refs: still unavailable.
	daveScope, err := e.scope(dave, orgB, pb, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := e.resolver.Resolve(e.ctx, daveScope, []link.Reference{explicit(pb, shared), explicit(p1, shared)}); err != nil || !res[0].Available || res[1] != (link.ResolvedReference{}) {
		t.Fatal("dave link results", err)
	}
	if res, err := e.resolver.Resolve(e.ctx, aliceScope, []link.Reference{explicit(pb, shared)}); err != nil || res[0] != (link.ResolvedReference{}) {
		t.Fatal("alice resolved a foreign org's target after dave warmed it", err)
	}
	// Dave's cache entry for the same query text never serves alice, and the
	// count for org B is not reachable by alice's scope in any way.
	if n, hit, _, err := e.cachedCount(daveScope, pb, "request_total"); err != nil || hit || n != 4 {
		t.Fatalf("dave count n=%d hit=%v err=%v", n, hit, err)
	}
	if n, hit, _, err := e.cachedCount(aliceScope, p1, "request_total"); err != nil || !hit || n != 2 {
		t.Fatalf("alice warm entry changed: n=%d hit=%v err=%v", n, hit, err)
	}
	// Revoking alice's grant kills her warm entries before any lookup.
	e.grant(orgA, alice, p1, false)
	if _, _, _, err = e.cachedCount(aliceScope, p1, "request_total"); faultCode(err) != model.NotFound {
		t.Fatalf("stale scope reached warm cache: %v", err)
	}
	if _, err = e.resolver.Resolve(e.ctx, aliceScope, refs[:1]); faultCode(err) != model.NotFound {
		t.Fatalf("stale scope resolved links: %v", err)
	}
}

func TestNamedSourceVisibilityCannotShareWarmCacheOrCursor(t *testing.T) {
	e := newIsoEnv(t)
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	project := model.NewID()
	org := e.org("named sources", project)
	r1 := e.user(org, "reader-one@example.test")
	r2 := e.user(org, "reader-two@example.test")
	for _, r := range []person{r1, r2} {
		e.grant(org, r, project, true, auth.RawRead)
	}
	// Sources need their own named readers in the control policy.
	src := func(reader person) sourceFixture {
		id := model.NewID()
		return e.onboard(org, project, id, ids, e.rawPolicy(e.actor.ID), auth.SourcePolicyConfig{ProjectID: project, Restricted: true, Readers: []model.ID{reader.ID}, Enabled: true})
	}
	one, two := src(r1), src(r2)
	e.rawLog(one, "canary-one")
	e.rawLog(two, "canary-two")
	scope := func(who person, source sourceFixture) (auth.Scope, error) {
		return e.app.Auth.AuthorizeRestrictedSource(e.ctx, who.Cred, org, project, source.ID)
	}
	s1scope, err := scope(r1, one)
	if err != nil {
		t.Fatal(err)
	}
	s2scope, err := scope(r2, two)
	if err != nil {
		t.Fatal(err)
	}
	if s1scope.PolicyEpoch() != s2scope.PolicyEpoch() || !equalProjects(s1scope.ProjectIDs(), s2scope.ProjectIDs()) || s1scope.Permission() != s2scope.Permission() {
		t.Fatal("fixture must compare identical org epoch, projects and action")
	}
	if s1scope.VisibilityFingerprint() == s2scope.VisibilityFingerprint() {
		t.Fatal("disjoint named-source readers share an authorization fingerprint")
	}
	if _, err = scope(r2, one); faultCode(err) != model.NotFound {
		t.Fatalf("reader two authorized reader one's source: %v", err)
	}
	// Even one principal's two selected sources never share a fingerprint.
	both := e.onboard(org, project, model.NewID(), ids, e.rawPolicy(e.actor.ID), auth.SourcePolicyConfig{ProjectID: project, Restricted: true, Readers: []model.ID{r1.ID}, Enabled: true})
	if bothScope, err := scope(r1, both); err != nil {
		t.Fatal(err)
	} else if bothScope.VisibilityFingerprint() == mustScope(t, scope, r1, one).VisibilityFingerprint() {
		t.Fatal("two selected sources of one reader share a fingerprint")
	}
	// Re-derive after the extra onboarding bumped the epoch.
	if s1scope, err = scope(r1, one); err != nil {
		t.Fatal(err)
	}
	if s2scope, err = scope(r2, two); err != nil {
		t.Fatal(err)
	}
	// Broad raw.read scopes name no source: identical org, epoch, project list
	// and action, so ONLY the visibility fingerprint separates the readers.
	broad1, err := e.scope(r1, org, project, auth.RawRead)
	if err != nil {
		t.Fatal(err)
	}
	broad2, err := e.scope(r2, org, project, auth.RawRead)
	if err != nil {
		t.Fatal(err)
	}
	if broad1.VisibilityFingerprint() == broad2.VisibilityFingerprint() {
		t.Fatal("equal broad raw.read with disjoint named-source grants share a fingerprint")
	}
	warm, err := e.cache.Lookup(e.ctx, broad1, "raw_logs", "broad", "all")
	if err != nil || warm.Hit {
		t.Fatal(err)
	}
	if err = e.cache.Store(e.ctx, broad1, warm.Fill, []byte("reader-one-private"), false); err != nil {
		t.Fatal(err)
	}
	if res, err := e.cache.Lookup(e.ctx, broad1, "raw_logs", "broad", "all"); err != nil || !res.Hit {
		t.Fatal("broad warm entry not reusable by its owner", err)
	}
	if res, err := e.cache.Lookup(e.ctx, broad2, "raw_logs", "broad", "all"); err != nil || res.Hit {
		t.Fatal("broad scope with disjoint named-source grants shared a warm entry", err)
	}
	broadCursor, err := e.cache.IssueTicket(e.ctx, broad1, "cursor", project, []byte("next"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = e.cache.OpenTicket(e.ctx, broad2, "cursor", broadCursor); faultCode(err) != model.NotFound {
		t.Fatalf("cursor resumed by a reader with disjoint named-source grants: %v", err)
	}
	scanRaw := func(sc auth.Scope, source sourceFixture) ([]string, error) {
		rows, err := e.app.Storage.Scan(e.ctx, sc, storage.ScanRequest{Projects: []model.ID{project}, Signal: model.Log, Start: math.MinInt64, End: math.MaxInt64, Selectors: []storage.Matcher{{Target: storage.MatchField, Name: "source_id", Op: storage.MatchEqual, Literal: storage.Literal{Kind: storage.LiteralString, String: source.ID.String()}}}})
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var lines []string
		for {
			page, err := rows.Next(e.ctx)
			if errors.Is(err, io.EOF) {
				return lines, nil
			}
			if err != nil {
				return nil, err
			}
			for i := range page.Len() {
				lines = append(lines, page.Values[i].Log.Line)
			}
		}
	}
	// Warm query cache + pagination cursor for reader one.
	query := func(sc auth.Scope, source sourceFixture) (lines []string, hit bool, err error) {
		res, err := e.cache.Lookup(e.ctx, sc, "raw_logs", "source:"+source.ID.String(), "all")
		if err != nil {
			return nil, false, err
		}
		if res.Hit {
			var out []string
			return out, true, json.Unmarshal(res.Value, &out)
		}
		lines, err = scanRaw(sc, source)
		if err != nil {
			return nil, false, err
		}
		raw, _ := json.Marshal(lines)
		return lines, false, e.cache.Store(e.ctx, sc, res.Fill, raw, false)
	}
	for pass := range 2 {
		lines, hit, err := query(s1scope, one)
		if err != nil || len(lines) != 1 && !hit || hit != (pass == 1) {
			t.Fatalf("reader one warm query pass %d lines=%v hit=%v err=%v", pass, lines, hit, err)
		}
	}
	// Reader two: identical profile/query/params text for reader one's source
	// misses (not a hit), and the scan itself is refused.
	if res, err := e.cache.Lookup(e.ctx, s2scope, "raw_logs", "source:"+one.ID.String(), "all"); err != nil || res.Hit {
		t.Fatal("reader two reached reader one's warm cache entry", err)
	}
	if _, err := scanRaw(s2scope, one); err == nil {
		t.Fatal("reader two scanned reader one's source")
	}
	// Negative cache: reader two warms "nothing here" for its own scope; it can
	// never be served to reader one.
	if res, err := e.cache.Lookup(e.ctx, s2scope, "raw_logs", "probe", "all"); err != nil || res.Hit {
		t.Fatal(err)
	} else if err = e.cache.Store(e.ctx, s2scope, res.Fill, nil, true); err != nil {
		t.Fatal(err)
	}
	if res, err := e.cache.Lookup(e.ctx, s1scope, "raw_logs", "probe", "all"); err != nil || res.Hit {
		t.Fatal("reader one received reader two's warm negative entry", err)
	}
	// Pagination cursor + live replay position tickets.
	cursor, err := e.cache.IssueTicket(e.ctx, s1scope, "cursor", one.ID, []byte(`{"offset":1}`), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if subject, state, err := e.cache.OpenTicket(e.ctx, s1scope, "cursor", cursor); err != nil || subject != one.ID || string(state) != `{"offset":1}` {
		t.Fatal("owner cursor rejected", err)
	}
	if _, _, err := e.cache.OpenTicket(e.ctx, s2scope, "cursor", cursor); faultCode(err) != model.NotFound {
		t.Fatalf("reader two resumed reader one's cursor: %v", err)
	}
	if _, _, err := e.cache.OpenTicket(e.ctx, s1scope, "live", cursor); faultCode(err) != model.NotFound {
		t.Fatalf("cursor accepted as a live replay position: %v", err)
	}
	live1, err := e.app.Storage.Subscribe(e.ctx, s1scope, storage.SubscribeRequest{Projects: []model.ID{project}, Signal: model.Log, Selectors: []storage.Matcher{{Target: storage.MatchField, Name: "source_id", Op: storage.MatchEqual, Literal: storage.Literal{Kind: storage.LiteralString, String: one.ID.String()}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer live1.Close()
	if _, err = e.app.Storage.Subscribe(e.ctx, s2scope, storage.SubscribeRequest{Projects: []model.ID{project}, Signal: model.Log, Selectors: []storage.Matcher{{Target: storage.MatchField, Name: "source_id", Op: storage.MatchEqual, Literal: storage.Literal{Kind: storage.LiteralString, String: one.ID.String()}}}}); err == nil {
		t.Fatal("reader two subscribed to reader one's live stream")
	}
	liveTicket, err := e.cache.IssueTicket(e.ctx, s1scope, "live", one.ID, []byte("position"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.cache.OpenTicket(e.ctx, s2scope, "live", liveTicket); faultCode(err) != model.NotFound {
		t.Fatalf("reader two resumed reader one's live replay: %v", err)
	}
	// Both sources receive a new row; reader one's live feed shows only its own.
	e.rawLog(two, "canary-two-live")
	e.rawLog(one, "canary-one-live")
	seen := ""
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(seen, "canary-one-live") && time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(e.ctx, 2*time.Second)
		change, err := live1.Next(ctx)
		cancel()
		if err != nil {
			continue
		}
		for i := range change.Page.Len() {
			if change.Page.Values[i].Log != nil {
				seen += change.Page.Values[i].Log.Line + "\n"
			}
		}
	}
	if !strings.Contains(seen, "canary-one-live") || strings.Contains(seen, "canary-two") {
		t.Fatalf("live replay leaked or lost rows: %q", seen)
	}
	// Discovery: each reader's capabilities list exactly its own source.
	capabilities := func(who person, permission string) string {
		status, raw, _ := e.call(who, "GET", "/api/v1/capabilities?org="+org.String()+"&project="+project.String()+"&permission="+permission, nil)
		if status != 200 {
			t.Fatalf("capabilities %d %s", status, raw)
		}
		return string(raw)
	}
	c1, c2 := capabilities(r1, "raw.read"), capabilities(r2, "raw.read")
	if !strings.Contains(c1, one.ID.String()) || strings.Contains(c1, two.ID.String()) || !strings.Contains(c2, two.ID.String()) || strings.Contains(c2, one.ID.String()) {
		t.Fatalf("capability discovery shared named sources: %s | %s", c1, c2)
	}
	// Export: each reader's export contains only its own source's canaries,
	// and neither reader can open the other's operation or ticket.
	export := func(who person, source sourceFixture) (exports.Grant, string) {
		g := e.mustGrant(e.exportCreate(who, exports.Request{Project: project, Signal: model.Log, End: model.Int64(math.MaxInt64)}, org, "raw.read", source.ID, model.ID{}))
		if op := e.waitExport(who, org, project, "raw.read", source.ID, g.Operation.ID); op.Phase != "complete" {
			t.Fatalf("raw export phase %q %q", op.Phase, op.SafeReason)
		}
		status, body := e.exportDownload(who, org, project, "raw.read", source.ID, g.Operation.ID, g.Ticket)
		if status != 200 {
			t.Fatalf("raw export download %d", status)
		}
		return g, string(body)
	}
	g1, body1 := export(r1, one)
	g2, body2 := export(r2, two)
	if !strings.Contains(body1, "canary-one") || strings.Contains(body1, "canary-two") || !strings.Contains(body2, "canary-two") || strings.Contains(body2, "canary-one") {
		t.Fatal("export crossed named-source grants")
	}
	for _, c := range []struct {
		who person
		src sourceFixture
		g   exports.Grant
	}{{r2, two, g1}, {r1, one, g2}} {
		status, raw := e.exportDownload(c.who, org, project, "raw.read", c.src.ID, c.g.Operation.ID, c.g.Ticket)
		if status != 404 || bytes.Contains(raw, []byte("canary")) {
			t.Fatalf("foreign export released: %d %s", status, raw)
		}
	}
	// A reader asking for the other's source gets the guessed-ID denial.
	status, raw := e.exportCreate(r2, exports.Request{Project: project, Signal: model.Log, End: 10}, org, "raw.read", one.ID, model.ID{})
	status2, raw2 := e.exportCreate(r2, exports.Request{Project: project, Signal: model.Log, End: 10}, org, "raw.read", model.NewID(), model.ID{})
	if denial(t, status, raw) != denial(t, status2, raw2) {
		t.Fatal("foreign named source distinguishable from a guessed one")
	}
}
func equalProjects(a, b []model.ID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func mustScope(t *testing.T, f func(person, sourceFixture) (auth.Scope, error), who person, s sourceFixture) auth.Scope {
	t.Helper()
	sc, err := f(who, s)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func TestExportRevokedBeforeDownload(t *testing.T) {
	e := newIsoEnv(t)
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	project := model.NewID()
	org := e.org("exports", project)
	alice := e.user(org, "export-reader@example.test")
	e.grant(org, alice, project, true, auth.Read)
	src := e.source(org, project, ids, []model.Kind{model.Metric})
	e.metric(src, "export_canary_total")
	e.metric(src, "export_canary_total")
	req := exports.Request{Project: project, Signal: model.Metric, End: model.Int64(math.MaxInt64)}
	run := func() exports.Grant {
		g := e.mustGrant(e.exportCreate(alice, req, org, "", model.ID{}, model.ID{}))
		if op := e.waitExport(alice, org, project, "", model.ID{}, g.Operation.ID); op.Phase != "complete" || op.Chunks == 0 {
			t.Fatalf("export phase %q chunks %d", op.Phase, op.Chunks)
		}
		return g
	}
	// Control: an untouched completed export downloads.
	g := run()
	if status, body := e.exportDownload(alice, org, project, "", model.ID{}, g.Operation.ID, g.Ticket); status != 200 || !bytes.Contains(body, []byte("export_canary_total")) {
		t.Fatalf("baseline download failed: %d", status)
	}
	// 1. Grant revoked after completion: download fails, zero bytes.
	g = run()
	e.grant(org, alice, project, false)
	status, body := e.exportDownload(alice, org, project, "", model.ID{}, g.Operation.ID, g.Ticket)
	if status != 404 || bytes.Contains(body, []byte("export_canary_total")) {
		t.Fatalf("revoked export downloaded: %d %s", status, body)
	}
	// 2. Deletion generation advances after completion (no grant change).
	e.grant(org, alice, project, true, auth.Read)
	g = run()
	e.deletes.bump.Add(1)
	status, body = e.exportDownload(alice, org, project, "", model.ID{}, g.Operation.ID, g.Ticket)
	if status != 404 || bytes.Contains(body, []byte("export_canary_total")) {
		t.Fatalf("deleted export downloaded: %d %s", status, body)
	}
	if status, _ = e.exportStatus(alice, org, project, "", model.ID{}, g.Operation.ID); status != 404 {
		t.Fatal("deleted export status still visible")
	}
	// 3. Session revoked (logout) after completion: even a valid ticket fails.
	g = run()
	if err := e.app.Auth.Logout(e.ctx, alice.Session.Token); err != nil {
		t.Fatal(err)
	}
	status, body = e.exportDownload(alice, org, project, "", model.ID{}, g.Operation.ID, g.Ticket)
	if status == 200 || bytes.Contains(body, []byte("export_canary_total")) {
		t.Fatalf("logged-out principal downloaded: %d", status)
	}
}

// auditFailStore is a real durable control store whose commit of a chosen
// audit fails, which models a failed fsync of exactly the elevated-read audit.
type auditFailStore struct {
	*control.Store
	chunks atomic.Int64
	failAt atomic.Int64 // fail every export.chunk audit numbered >= failAt; 0 = never
}

func (s *auditFailStore) Update(ctx context.Context, fn func(*model.ControlState) error) error {
	return s.Store.Update(ctx, func(st *model.ControlState) error {
		before := len(st.Audits)
		if err := fn(st); err != nil {
			return err
		}
		if len(st.Audits) > before && st.Audits[len(st.Audits)-1].Action == "export.chunk" {
			if n := s.chunks.Add(1); s.failAt.Load() != 0 && n >= s.failAt.Load() {
				return errors.New("injected durable audit commit failure")
			}
		}
		return nil
	})
}

type staticScanner struct{ pages int }
type staticRows struct {
	pages, sent int
}

func (s staticScanner) Scan(context.Context, auth.Scope, storage.ScanRequest) (storage.RowIterator, error) {
	return &staticRows{pages: s.pages}, nil
}
func (r *staticRows) Next(context.Context) (storage.Page, error) {
	if r.sent == r.pages {
		return storage.Page{}, io.EOF
	}
	r.sent++
	var p storage.Page
	for i := range 60 {
		name := "elev_row_" + strings.Repeat("x", 700)
		if r.sent == r.pages && i == 59 {
			name = "elev_row_canary_last_row"
		}
		value := model.FloatBits(math.Float64bits(1))
		p.IDs = append(p.IDs, model.NewID())
		p.Times = append(p.Times, 1)
		p.ObservedTimes = append(p.ObservedTimes, 1)
		p.Resources = append(p.Resources, model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "i", Labels: model.Labels{}})
		p.Values = append(p.Values, model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &value, Unit: "1", Type: "counter"}})
		p.Origins = append(p.Origins, model.Cursor{})
		p.Projects = append(p.Projects, model.NewID())
		p.Sources = append(p.Sources, model.NewID())
		p.Loss = append(p.Loss, 0)
	}
	return p, nil
}
func (r *staticRows) Watermarks() []model.Cursor { return nil }
func (r *staticRows) Close() error               { return nil }

func TestElevationReadAuditMustCommit(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	disk, err := control.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	store := &auditFailStore{Store: disk}
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	activateHTTPControl(t, disk, dir)
	boot, _ := disk.BootstrapToken()
	session, err := service.Bootstrap(ctx, boot, "elevated-owner@example.test", "elevated owner password 2026")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := service.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	org, project := model.NewID(), model.NewID()
	for _, c := range []struct {
		kind string
		p    auth.AdminPayload
	}{{"create_org", auth.AdminPayload{Name: "elevated"}}, {"create_project", auth.AdminPayload{ID: project, Name: "p"}}} {
		var revision model.Revision
		_ = disk.View(ctx, func(st control.State) error { revision = st.Revision; return nil })
		c.p.Reason = "elevation audit regression"
		raw, _ := json.Marshal(c.p)
		if _, err = service.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: c.kind, Payload: raw}); err != nil {
			t.Fatal(err)
		}
	}
	deletes := service.SourceLifecycleGenerations()
	cache, err := auth.NewCache(service, deletes, 16, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	exp, err := exports.New(service, cache, deletes, staticScanner{pages: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer exp.Close()
	server := httptest.NewTLSServer(httpapi.NewServer("", service, nil, func(mux *http.ServeMux) {
		httpapi.RegisterExportRoutes(mux, service, exp)
	}).Handler)
	defer server.Close()
	post := func(path string, body any) (*http.Response, error) {
		raw, merr := json.Marshal(body)
		if merr != nil {
			t.Fatal(merr)
		}
		req, _ := http.NewRequest("POST", server.URL+path, bytes.NewReader(raw))
		req.Header.Set("Cookie", "__Host-soundpost="+session.Token)
		req.Header.Set("Origin", server.URL)
		req.Header.Set("X-CSRF-Token", session.CSRF)
		return server.Client().Do(req)
	}
	resp, err := post("/api/v1/elevation", map[string]any{"reason": "audit must commit", "orgs": []model.ID{org}})
	if err != nil {
		t.Fatal(err)
	}
	var elevation struct{ ID model.ID }
	if err = json.NewDecoder(resp.Body).Decode(&elevation); err != nil || resp.StatusCode != 200 {
		t.Fatal("elevation", resp.StatusCode, err)
	}
	resp.Body.Close()
	request := func(op string, id model.ID, ticket string) httpapi.ExportRequest {
		return httpapi.ExportRequest{Operation: op, Org: org, Project: project, Elevation: httpapi.OptionalID(elevation.ID), Signal: model.Metric, Start: 0, End: model.Int64(math.MaxInt64), ID: httpapi.OptionalID(id), Ticket: ticket}
	}
	resp, err = post("/api/v1/exports", request("create", model.ID{}, ""))
	if err != nil {
		t.Fatal(err)
	}
	var grant exports.Grant
	if err = json.NewDecoder(resp.Body).Decode(&grant); err != nil || resp.StatusCode != http.StatusAccepted {
		t.Fatal("elevated create", resp.StatusCode, err)
	}
	resp.Body.Close()
	var op exports.Operation
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(25 * time.Millisecond) {
		resp, err = post("/api/v1/exports", request("status", grant.Operation.ID, ""))
		if err != nil {
			t.Fatal(err)
		}
		if err = json.NewDecoder(resp.Body).Decode(&op); err != nil || resp.StatusCode != 200 {
			t.Fatal("elevated status", resp.StatusCode, err)
		}
		resp.Body.Close()
		if op.Phase != "running" {
			break
		}
	}
	if op.Phase != "complete" || op.Chunks < 3 {
		t.Fatalf("elevated export phase %q chunks %d", op.Phase, op.Chunks)
	}
	audits := func(action string) (n int) {
		_ = disk.View(ctx, func(st control.State) error {
			for _, a := range st.Audits {
				if a.Action == action {
					n++
				}
			}
			return nil
		})
		return n
	}
	download := func() (status int, body []byte, readErr error) {
		resp, err := post("/api/v1/exports", request("download", grant.Operation.ID, grant.Ticket))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, readErr = io.ReadAll(resp.Body)
		return resp.StatusCode, body, readErr
	}
	// Control: every released chunk of an elevated export has a committed audit.
	status, body, readErr := download()
	if status != 200 || readErr != nil || !bytes.Contains(body, []byte("elev_row_canary_last_row")) || audits("export.chunk") != int(op.Chunks) {
		t.Fatalf("audited elevated download: %d err=%v chunks audited=%d of %d", status, readErr, audits("export.chunk"), op.Chunks)
	}
	// First chunk's audit fails to commit: no byte is released.
	base := int(store.chunks.Load())
	store.failAt.Store(int64(base) + 1)
	status, body, _ = download()
	if status == 200 || bytes.Contains(body, []byte("elev_row_")) || audits("export.chunk") != base {
		t.Fatalf("failed audit released elevated bytes: status %d audited=%d", status, audits("export.chunk"))
	}
	// A later chunk's audit fails: the stream aborts, the rest is never sent.
	base = int(store.chunks.Load())
	store.failAt.Store(int64(base) + 2)
	status, body, readErr = download()
	if bytes.Contains(body, []byte("elev_row_canary_last_row")) || readErr == nil && status == 200 {
		t.Fatalf("mid-stream audit failure completed the elevated stream: status %d err=%v", status, readErr)
	}
	if got, want := audits("export.chunk"), int(op.Chunks)+1; got != want {
		t.Fatalf("audit count %d, want the full baseline plus exactly one committed chunk (%d)", got, want)
	}
}
