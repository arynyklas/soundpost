// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"log"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/policy"
	"soundpost/internal/query"
	"soundpost/profiles"
)

// ---------------------------------------------------------------- rig

const (
	hostExporterToken = "CANARY-exporter-bearer-9d41c07e6a"
	hostMetric        = "wiring_temp"
)

// countingIngest is the node's real ingest service with a counter on the
// admissions that reached it (a refused or failed admission still counts as an
// attempt; admitted counts the ones with a durable receipt).
type countingIngest struct {
	inner    ScrapeIngest
	admitted atomic.Int64
	resolved atomic.Int64
}

func (c *countingIngest) ResolveSource(ctx context.Context, cr auth.SourceCredential, b model.Batch) (policy.SourceGrant, error) {
	c.resolved.Add(1)
	return c.inner.ResolveSource(ctx, cr, b)
}

func (c *countingIngest) Admit(ctx context.Context, g policy.SourceGrant, b model.Batch) (model.Receipt, error) {
	r, err := c.inner.Admit(ctx, g, b)
	if err == nil {
		c.admitted.Add(1)
	}
	return r, err
}

// tlsExporter is an in-process OpenMetrics exporter that requires a bearer.
type tlsExporter struct {
	srv      *httptest.Server
	listener *scrapeCountListener
	token    string
	body     atomic.Value // string
	mu       sync.Mutex
	auths    []string
	ok, deny int
}

func newTLSExporter(t *testing.T, token string) *tlsExporter {
	t.Helper()
	e := &tlsExporter{token: token}
	e.body.Store("# TYPE " + hostMetric + " gauge\n" + hostMetric + "{job=\"api\"} 41\n# EOF\n")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		e.mu.Lock()
		e.auths = append(e.auths, got)
		if got != "Bearer "+e.token {
			e.deny++
			e.mu.Unlock()
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		e.ok++
		e.mu.Unlock()
		scrapeOM(w, e.body.Load().(string))
	}))
	e.listener = &scrapeCountListener{Listener: srv.Listener}
	srv.Listener = e.listener
	srv.StartTLS()
	t.Cleanup(srv.Close)
	e.srv = srv
	return e
}

func (e *tlsExporter) counts() (ok, deny int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.ok, e.deny
}

func (e *tlsExporter) authorizations() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.auths...)
}

func (e *tlsExporter) rootsPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.srv.Certificate().Raw})
}

type hostRig struct {
	f         *scrapeFixture
	exporter  *tlsExporter
	secrets   string
	reader    *DirSecretReader
	ingest    *countingIngest
	sourceRaw string
	source    model.ID
	configRaw []byte
	logs      *bytes.Buffer
}

func hostPolicy(f *scrapeFixture) model.SourcePolicy {
	line := model.TemplateField{Name: "line", Type: "string", MaxBytes: 64, Sensitivity: "metadata", Values: []model.Scalar{scrapeScalar(f.t, "alpha")}}
	return model.SourcePolicy{
		Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric},
		Templates:     []model.LogTemplate{{ID: "scrape.line", Revision: 1, Line: "{line}", Severity: "info", Fields: []model.TemplateField{line}}},
		Resources:     model.ResourceRegistry{Services: []model.ID{f.resource.Service}, Environments: []model.ID{f.resource.Environment}, Builds: []model.ID{f.resource.Build}, Instances: []string{f.resource.Instance}},
		Labels:        map[string][]string{"job": {"api", "worker"}, "region": {"eu", "us"}},
		RetentionDays: map[model.Kind]uint32{model.Metric: 7}, MaxBytes: 64 << 20, MaxSeries: 1000,
	}
}

// newHostRig builds a real node with a provisioned source, a private secrets
// directory holding the source credential and the exporter bearer, an
// in-process TLS exporter and the configuration file that ties them together.
func newHostRig(t *testing.T) *hostRig {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the private-directory rules are POSIX modes")
	}
	f := newScrapeFixture(t)
	// The owner reads the scraped samples back through the real query path.
	var owner model.ID
	f.app.Control.View(f.ctx, func(st model.ControlState) error {
		for _, u := range st.Users {
			owner = u.ID
		}
		return nil
	})
	f.command("membership", auth.AdminPayload{UserID: owner, Enabled: true})
	f.command("grant", auth.AdminPayload{UserID: owner, ProjectID: f.project, Permissions: []string{string(auth.Read)}, Enabled: true})
	r := &hostRig{f: f, source: model.NewID(), logs: &bytes.Buffer{}}
	issued, err := f.app.Auth.OnboardSource(f.ctx, f.actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: f.org, Project: f.project, Source: r.source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: hostPolicy(f), Reason: "scrape host"})
	if err != nil {
		t.Fatal(err)
	}
	r.sourceRaw = issued.Credential
	r.secrets = privateDir(t)
	putSecret(t, r.secrets, "source-token", r.sourceRaw, 0o600)
	putSecret(t, r.secrets, "exporter-token", hostExporterToken, 0o600)
	if r.reader, err = NewDirSecretReader(r.secrets); err != nil {
		t.Fatal(err)
	}
	r.exporter = newTLSExporter(t, hostExporterToken)
	r.ingest = &countingIngest{inner: f.app.Ingest}
	r.writeConfig(nil)
	oldOut, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(r.logs)
	t.Cleanup(func() { log.SetOutput(oldOut); log.SetFlags(oldFlags) })
	return r
}

func (r *hostRig) writeConfig(mutate func(target map[string]any)) {
	r.f.t.Helper()
	roots := filepath.Join(r.f.t.TempDir(), "exporter-ca.pem")
	if err := os.WriteFile(roots, r.exporter.rootsPEM(), 0o644); err != nil {
		r.f.t.Fatal(err)
	}
	res := r.f.resource
	target := map[string]any{
		"alias": "wiring", "url": r.exporter.srv.URL + "/metrics", "interval": "1s", "timeout": "1s", "max_bytes": 1 << 20,
		"tls":    map[string]any{"roots_file": roots, "server_name": "example.com"},
		"auth":   "bearer",
		"secret": "exporter-token",
		"stale":  map[string]any{"on_disappear": true, "on_failure": true},
		"source": map[string]any{
			"project": r.f.project.String(), "source": r.source.String(), "producer": model.ID{0xaa, 7}.String(), "policy_revision": 1,
			"credential_secret": "source-token",
			"resource":          map[string]any{"service": res.Service.String(), "environment": res.Environment.String(), "build": res.Build.String(), "instance": res.Instance},
		},
	}
	if mutate != nil {
		mutate(target)
	}
	raw, err := json.Marshal(map[string]any{"version": 1, "targets": []any{target}})
	if err != nil {
		r.f.t.Fatal(err)
	}
	r.configRaw = raw
}

// start loads the configuration through the same loader serve uses and starts
// the host over the real node. loopback lifts the test-only egress seam so the
// in-process exporter on 127.0.0.1 is reachable (production can never lift it).
func (r *hostRig) start(t *testing.T, loopback bool) *ScrapeHost {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scrape.json")
	if err := os.WriteFile(path, r.configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadScrapeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := cfg.Specs(r.reader)
	if err != nil {
		t.Fatal(err)
	}
	var adjust func(*ScrapeTarget)
	if loopback {
		adjust = func(tg *ScrapeTarget) { tg.Egress.loopbackOK = true }
	}
	ctx, cancel := context.WithCancel(context.Background())
	h, err := startScrapeHost(ctx, ScrapeHostDeps{Auth: r.f.app.Auth, Ingest: r.ingest, Secrets: r.reader}, specs, adjust)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); h.Close() })
	return h
}

func waitFor(t *testing.T, what string, within time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (r *hostRig) only(t *testing.T, h *ScrapeHost) ScrapeTargetStatus {
	t.Helper()
	st := h.Status()
	if len(st) != 1 || st[0].Alias != "wiring" {
		t.Fatalf("status %+v", st)
	}
	return st[0]
}

// queryMetric runs PromQL through the real C06 engine under the owner's read
// scope and returns the float values of every element of the vector.
func (r *hostRig) queryMetric(t *testing.T, name string) []float64 {
	t.Helper()
	scope, err := r.f.app.Auth.Authorize(r.f.ctx, r.f.actor, r.f.org, []model.ID{r.f.project}, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	files, err := profiles.Query()
	if err != nil {
		t.Fatal(err)
	}
	const profileID = "promql-prometheus-3.13.5"
	rawProfile, err := fs.ReadFile(files, profileID+".json")
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		FeatureSets []struct {
			ID string `json:"id"`
		} `json:"feature_sets"`
	}
	if json.Unmarshal(rawProfile, &p) != nil || len(p.FeatureSets) == 0 {
		t.Fatal("no feature set")
	}
	at := model.UnixNano(time.Now().Add(2 * time.Second).Truncate(time.Millisecond).UnixNano())
	res, err := r.f.app.Query.Execute(r.f.ctx, scope, query.Request{
		Language: query.LanguagePromQL, Profile: profileID, FeatureSet: p.FeatureSets[0].ID, Expression: name,
		Evaluation: query.Evaluation{Instant: true, Time: at}, Projects: []model.ID{r.f.project},
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	var out []float64
	for _, pr := range res.Projects {
		if pr.Failure != nil {
			t.Fatalf("query failure: %+v", pr.Failure)
		}
		if pr.Value == nil {
			continue
		}
		for _, el := range pr.Value.Vector {
			if el.Sample.Float != nil {
				out = append(out, math.Float64frombits(uint64(*el.Sample.Float)))
			}
		}
	}
	return out
}

func (r *hostRig) assertNoCanary(t *testing.T, h *ScrapeHost) {
	t.Helper()
	text := fmt.Sprintf("%+v %#v", h.Status(), h.Status()) + r.logs.String()
	for _, canary := range []string{hostExporterToken, r.sourceRaw} {
		if strings.Contains(text, canary) {
			t.Fatalf("a secret leaked into the status or logs: %s", text)
		}
	}
}

// ---------------------------------------------------------------- the wiring test

// A configured target is scraped by a node-hosted Scraper with a secret read
// from the private directory, authenticated with the operator's source
// credential and admitted through the real ingest path: the samples are
// queryable through the real C06 engine, and the exporter saw exactly the
// bearer header and nothing else.
func TestScrapeHostScrapesConfiguredTargetIntoTheRealIngestPath(t *testing.T) {
	r := newHostRig(t)
	h := r.start(t, true)
	waitFor(t, "a healthy admitted cycle", 20*time.Second, func() bool {
		ok, _ := r.exporter.counts()
		return ok >= 1 && r.only(t, h).OK() && r.ingest.admitted.Load() >= 1
	})
	st := r.only(t, h)
	if st.Reason != ScrapeReasonNone || st.Last.Health.Status != ScrapeOK || st.Last.Coverage != CoverageComplete || st.Last.Samples != 1 || st.Last.Target != "wiring" {
		t.Fatalf("status %+v", st)
	}
	if got := r.queryMetric(t, hostMetric); len(got) != 1 || got[0] != 41 {
		t.Fatalf("the scraped sample is not queryable through the real query path: %v", got)
	}
	auths := r.exporter.authorizations()
	if len(auths) == 0 {
		t.Fatal("the exporter was never contacted")
	}
	for _, a := range auths {
		if a != "Bearer "+hostExporterToken {
			t.Fatalf("the exporter must see exactly the bearer header, got %q", a)
		}
	}
	if _, deny := r.exporter.counts(); deny != 0 {
		t.Fatalf("%d requests were refused by the exporter", deny)
	}
	r.assertNoCanary(t, h)

	// Close stops the schedule: no request is made afterwards.
	h.Close()
	ok, _ := r.exporter.counts()
	time.Sleep(2500 * time.Millisecond)
	if after, _ := r.exporter.counts(); after != ok {
		t.Fatalf("the exporter was scraped %d more times after Close", after-ok)
	}
	h.Close() // idempotent
}

// ---------------------------------------------------------------- negatives

func TestScrapeHostWrongTargetSecretIsTypedAndAdmitsNothing(t *testing.T) {
	r := newHostRig(t)
	putSecret(t, r.secrets, "exporter-token", "WRONG-"+hostExporterToken, 0o600)
	h := r.start(t, true)
	waitFor(t, "an exporter refusal", 20*time.Second, func() bool {
		_, deny := r.exporter.counts()
		return deny >= 1 && r.only(t, h).Cycles >= 1
	})
	st := r.only(t, h)
	if st.Reason != ScrapeReason(ScrapeBadStatus) || st.Last.Health.HTTPStatus != http.StatusUnauthorized || st.Last.Coverage != CoverageUnknown || st.OK() {
		t.Fatalf("status %+v", st)
	}
	if ok, _ := r.exporter.counts(); ok != 0 {
		t.Fatalf("the exporter accepted the wrong secret %d times", ok)
	}
	for _, a := range r.exporter.authorizations() {
		if a != "Bearer WRONG-"+hostExporterToken {
			t.Fatalf("authorization %q", a)
		}
	}
	if n := r.ingest.admitted.Load(); n != 0 {
		t.Fatalf("%d batches were admitted from a refused scrape", n)
	}
	if got := r.queryMetric(t, hostMetric); len(got) != 0 {
		t.Fatalf("a refused scrape produced samples: %v", got)
	}
	r.assertNoCanary(t, h)
}

func TestScrapeHostMissingTargetSecretIsSecretUnavailableAndNeverDials(t *testing.T) {
	r := newHostRig(t)
	if err := os.Remove(filepath.Join(r.secrets, "exporter-token")); err != nil {
		t.Fatal(err)
	}
	h := r.start(t, true)
	waitFor(t, "a typed secret_unavailable cycle", 20*time.Second, func() bool {
		return r.only(t, h).Cycles >= 1
	})
	st := r.only(t, h)
	if st.Reason != ScrapeReason(ScrapeSecretUnavailable) || st.Last.Health.Status != ScrapeSecretUnavailable {
		t.Fatalf("status %+v", st)
	}
	if n := r.exporter.listener.accepts.Load(); n != 0 {
		t.Fatalf("the exporter was dialed %d times without its credential", n)
	}
	if r.ingest.admitted.Load() != 0 {
		t.Fatal("something was admitted")
	}
}

// Without the test-only loopback seam the real egress policy applies: a
// loopback target is refused before any socket is opened.
func TestScrapeHostEgressBlockedTargetIsRefusedBeforeDial(t *testing.T) {
	r := newHostRig(t)
	h := r.start(t, false)
	waitFor(t, "an egress_denied cycle", 20*time.Second, func() bool { return r.only(t, h).Cycles >= 1 })
	st := r.only(t, h)
	if st.Reason != ScrapeReason(ScrapeEgressDenied) || st.Last.Health.Status != ScrapeEgressDenied {
		t.Fatalf("status %+v", st)
	}
	if n := r.exporter.listener.accepts.Load(); n != 0 {
		t.Fatalf("a blocked target was dialed %d times", n)
	}
	if auths := r.exporter.authorizations(); len(auths) != 0 {
		t.Fatalf("the exporter saw a request: %q", auths)
	}
	if r.ingest.admitted.Load() != 0 {
		t.Fatal("something was admitted")
	}
}

// Revoking the source credential stops admission with a typed reason; the
// grant is resolved per attempt, so no cached grant outlives the revocation,
// and the exporter is not contacted once the grant is denied.
func TestScrapeHostRevokedSourceStopsAdmitting(t *testing.T) {
	r := newHostRig(t)
	h := r.start(t, true)
	waitFor(t, "a healthy admitted cycle", 20*time.Second, func() bool {
		return r.only(t, h).OK() && r.ingest.admitted.Load() >= 1
	})
	if err := r.f.app.Auth.RevokeSource(r.f.ctx, r.f.actor, r.source, "scrape host revocation regression"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "grant_denied", 20*time.Second, func() bool { return r.only(t, h).Reason == ScrapeReasonGrantDenied })
	// let any cycle that was already in flight settle, then nothing more happens
	time.Sleep(1200 * time.Millisecond)
	admitted := r.ingest.admitted.Load()
	hits, _ := r.exporter.counts()
	time.Sleep(2500 * time.Millisecond)
	if after := r.ingest.admitted.Load(); after != admitted {
		t.Fatalf("%d batches were admitted after the source was revoked", after-admitted)
	}
	if after, _ := r.exporter.counts(); after != hits {
		t.Fatalf("the exporter was scraped %d times after the grant was denied", after-hits)
	}
	if st := r.only(t, h); st.Reason != ScrapeReasonGrantDenied || st.OK() {
		t.Fatalf("status %+v", st)
	}
	r.assertNoCanary(t, h)
}

func TestScrapeHostTypedGrantFailures(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(r *hostRig)
		reason ScrapeReason
	}{
		{"source credential secret missing", func(r *hostRig) { os.Remove(filepath.Join(r.secrets, "source-token")) }, ScrapeReasonCredentialUnavailable},
		{"unknown source credential", func(r *hostRig) { putSecret(r.f.t, r.secrets, "source-token", "not-a-credential-of-this-node", 0o600) }, ScrapeReasonGrantDenied},
		{"credential of another source than configured", func(r *hostRig) {
			r.writeConfig(func(target map[string]any) { target["source"].(map[string]any)["source"] = model.NewID().String() })
		}, ScrapeReasonGrantDenied},
		{"stale policy revision", func(r *hostRig) {
			r.writeConfig(func(target map[string]any) { target["source"].(map[string]any)["policy_revision"] = 2 })
		}, ScrapeReasonPolicyStale},
		{"source credential file with a wrong mode", func(r *hostRig) { os.Chmod(filepath.Join(r.secrets, "source-token"), 0o644) }, ScrapeReasonCredentialUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newHostRig(t)
			c.setup(r)
			h := r.start(t, true)
			waitFor(t, "a typed grant failure", 20*time.Second, func() bool { return r.only(t, h).Cycles >= 1 })
			if st := r.only(t, h); st.Reason != c.reason || st.OK() {
				t.Fatalf("status %+v, want reason %q", st, c.reason)
			}
			if n := r.exporter.listener.accepts.Load(); n != 0 || r.ingest.admitted.Load() != 0 {
				t.Fatalf("an unauthorized scrape reached the exporter (%d dials) or the store (%d admissions)", n, r.ingest.admitted.Load())
			}
			r.assertNoCanary(t, h)
		})
	}
}

// A grant lives five seconds. The grant function must resolve a new one for
// every call; a grant kept from an earlier call is stale and unusable.
func TestScrapeGrantIsResolvedFreshPerAttempt(t *testing.T) {
	r := newHostRig(t)
	cfg, err := ParseScrapeConfig(r.configRaw)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := cfg.Specs(r.reader)
	if err != nil {
		t.Fatal(err)
	}
	grant := scrapeGrantFunc(ScrapeHostDeps{Auth: r.f.app.Auth, Ingest: r.ingest, Secrets: r.reader}, specs[0])
	first, err := grant(r.f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = first.Scope(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5300 * time.Millisecond)
	if _, err = first.Scope(); err == nil {
		t.Fatal("test premise: a five second grant must be stale by now")
	}
	second, err := grant(r.f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = second.Scope(); err != nil {
		t.Fatalf("a call after expiry must resolve a fresh grant: %v", err)
	}
	if n := r.ingest.resolved.Load(); n != 2 {
		t.Fatalf("resolved %d grants for 2 calls", n)
	}
}

func TestStartScrapeHostRefusesBadWiringAndTargets(t *testing.T) {
	r := newHostRig(t)
	cfg, err := ParseScrapeConfig(r.configRaw)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := cfg.Specs(r.reader)
	if err != nil {
		t.Fatal(err)
	}
	deps := ScrapeHostDeps{Auth: r.f.app.Auth, Ingest: r.ingest, Secrets: r.reader}
	for name, d := range map[string]ScrapeHostDeps{"no auth": {Ingest: r.ingest, Secrets: r.reader}, "no ingest": {Auth: r.f.app.Auth, Secrets: r.reader}, "no secrets": {Auth: r.f.app.Auth, Ingest: r.ingest}} {
		if _, err := StartScrapeHost(context.Background(), d, specs); err == nil {
			t.Errorf("%s: started", name)
		}
	}
	bad := append([]ScrapeTargetSpec(nil), specs...)
	bad[0].Target.Interval = 0
	if _, err := StartScrapeHost(context.Background(), deps, bad); err == nil {
		t.Error("an invalid target started")
	}
	dup := []ScrapeTargetSpec{specs[0], specs[0]}
	if _, err := StartScrapeHost(context.Background(), deps, dup); err == nil {
		t.Error("duplicate aliases started")
	}
}
