// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"soundpost/internal/adapters/queryinput"
	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/policy"
)

// ---- real policy fixture (same construction as the queryinput fixture) ----

type scrapeFixture struct {
	t        *testing.T
	ctx      context.Context
	app      *appcore.App
	actor    auth.Credential
	org      model.ID
	project  model.ID
	source   model.ID
	resource model.Resource
	cred     auth.SourceCredential
	grant    policy.SourceGrant
}

func scrapeScalar(t testing.TB, s string) model.Scalar {
	t.Helper()
	var v model.Scalar
	raw, _ := json.Marshal(s)
	if err := v.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	return v
}

func newScrapeFixture(t *testing.T) *scrapeFixture {
	t.Helper()
	ctx := context.Background()
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	token, err := app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := app.Auth.Bootstrap(ctx, token, "scrape-owner@example.test", "scrape fixture password 2026")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	f := &scrapeFixture{t: t, ctx: ctx, app: app, actor: actor, org: model.NewID(), project: model.NewID(), source: model.NewID()}
	f.command("create_org", auth.AdminPayload{Name: "scrape"})
	f.command("create_project", auth.AdminPayload{ID: f.project, Name: "scrape"})
	f.resource = model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "inst-1", Labels: model.Labels{}}
	line := model.TemplateField{Name: "line", Type: "string", MaxBytes: 64, Sensitivity: "metadata", Values: []model.Scalar{scrapeScalar(t, "alpha")}}
	pol := model.SourcePolicy{
		Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric},
		Templates:     []model.LogTemplate{{ID: "scrape.line", Revision: 1, Line: "{line}", Severity: "info", Fields: []model.TemplateField{line}}},
		Resources:     model.ResourceRegistry{Services: []model.ID{f.resource.Service}, Environments: []model.ID{f.resource.Environment}, Builds: []model.ID{f.resource.Build}, Instances: []string{f.resource.Instance}},
		Labels:        map[string][]string{"job": {"api", "worker"}, "region": {"eu", "us"}},
		RetentionDays: map[model.Kind]uint32{model.Metric: 7}, MaxBytes: 64 << 20, MaxSeries: 1000,
	}
	issued, err := app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: f.org, Project: f.project, Source: f.source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: pol, Reason: "scrape fixture"})
	if err != nil {
		t.Fatal(err)
	}
	f.cred, err = app.Auth.AuthenticateSource(ctx, issued.Credential, "", false)
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Now()
	ps, err := policy.New(app.Auth, func() time.Time { return fixed })
	if err != nil {
		t.Fatal(err)
	}
	f.grant, err = ps.ResolveSource(ctx, f.cred, f.project, f.source, 1)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *scrapeFixture) command(kind string, p auth.AdminPayload) {
	f.t.Helper()
	var rev model.Revision
	f.app.Control.View(f.ctx, func(st model.ControlState) error { rev = st.Revision; return nil })
	p.Reason = "scrape fixture"
	raw, _ := json.Marshal(p)
	if _, err := f.app.Auth.AdminCommand(f.ctx, f.actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: f.org, Kind: kind, Payload: raw}); err != nil {
		f.t.Fatalf("admin %s: %v", kind, err)
	}
}

func (f *scrapeFixture) profile() queryinput.InputProfile {
	return queryinput.InputProfile{
		Project: f.project, Source: f.source, Producer: model.ID{0xaa, 7}, PolicyRevision: 1, Resource: f.resource,
		Limits: queryinput.DefaultLimits(),
		Names:  queryinput.NamesStrict, OutOfOrder: queryinput.OutOfOrderSort, Histograms: queryinput.HistogramsPreserve,
		Exemplars: queryinput.ExemplarsReject, Help: queryinput.HelpReject,
	}
}

var scrapeT0 = time.Unix(1_900_000_000, 0)

func scrapeClockAt(at time.Time) func() time.Time { return func() time.Time { return at } }

func (f *scrapeFixture) target(url string) ScrapeTarget {
	return ScrapeTarget{
		Alias: "host-exporter", URL: url, Interval: 2 * time.Second, Timeout: time.Second, MaxBytes: 1 << 20,
		Egress: EgressPolicy{loopbackOK: true}, Profile: f.profile(), Clock: scrapeClockAt(scrapeT0),
	}
}

// ---- real servers ----

type scrapeCountListener struct {
	net.Listener
	accepts atomic.Int64
}

func (l *scrapeCountListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepts.Add(1)
	}
	return c, err
}

func scrapeServe(t *testing.T, h http.Handler) (*httptest.Server, *scrapeCountListener) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	cl := &scrapeCountListener{Listener: srv.Listener}
	srv.Listener = cl
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, cl
}

func scrapeOM(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/openmetrics-text; version=1.0.0; charset=utf-8")
	fmt.Fprint(w, body)
}

// ---- projection of results ----

type scrapeRec struct {
	Name, Labels, Kind, Unit, Type string
	Bits                           uint64
	At                             int64
}

func scrapeLabelsString(l model.Labels) string {
	var p []string
	for _, x := range l {
		p = append(p, x.Name+"="+x.Value)
	}
	sort.Strings(p)
	return strings.Join(p, ",")
}

func scrapeFlatten(t *testing.T, batches []model.Batch) []scrapeRec {
	t.Helper()
	var out []scrapeRec
	for _, b := range batches {
		for _, r := range b.Records {
			m := r.Payload.Metric
			if m == nil || m.Value == nil {
				t.Fatalf("unexpected non-float record kind=%s", r.Kind)
			}
			out = append(out, scrapeRec{m.Name, scrapeLabelsString(m.Labels), m.SampleKind, m.Unit, m.Type, uint64(*m.Value), int64(r.ObservedAt)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name+"|"+out[i].Labels+"|"+out[i].Kind < out[j].Name+"|"+out[j].Labels+"|"+out[j].Kind
	})
	return out
}

func scrapeSamples(recs []scrapeRec) []scrapeRec {
	var out []scrapeRec
	for _, r := range recs {
		if r.Kind != "stale" {
			out = append(out, r)
		}
	}
	return out
}

func scrapeStales(recs []scrapeRec) []scrapeRec {
	var out []scrapeRec
	for _, r := range recs {
		if r.Kind == "stale" {
			out = append(out, r)
		}
	}
	return out
}

func scrapeFloat(v float64) uint64 { return math.Float64bits(v) }

func scrapeSeen(t *testing.T, got []SeriesRef) []string {
	t.Helper()
	var out []string
	for _, s := range got {
		out = append(out, s.Name+"{"+scrapeLabelsString(s.Labels)+"}")
	}
	return out
}

func scrapeEq(t *testing.T, what string, got, want any) {
	t.Helper()
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if string(g) != string(w) {
		t.Fatalf("%s:\n got  %s\n want %s", what, g, w)
	}
}

func scrapeMustOK(t *testing.T, res ScrapeResult, err error) ScrapeResult {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Health.Status != ScrapeOK || res.Coverage != CoverageComplete {
		t.Fatalf("health = %+v coverage=%s, want ok/complete", res.Health, res.Coverage)
	}
	return res
}

func scrapeMustFail(t *testing.T, res ScrapeResult, err error, want ScrapeStatus) {
	t.Helper()
	if err != nil {
		t.Fatalf("runtime failure must not be an error: %v", err)
	}
	if res.Health.Status != want {
		t.Fatalf("status = %q (http %d), want %q", res.Health.Status, res.Health.HTTPStatus, want)
	}
	if res.Coverage != CoverageUnknown {
		t.Fatalf("coverage = %q, want unknown", res.Coverage)
	}
	if res.Target != "host-exporter" {
		t.Fatalf("target = %q", res.Target)
	}
}

const scrapeWantStale = uint64(0x7ff0000000000002)

// ---- the required test ----

func TestScrapeTimeoutStalenessAndEndpointPolicy(t *testing.T) {
	f := newScrapeFixture(t)

	t.Run("changing exporter admits exact samples", func(t *testing.T) {
		var mu sync.Mutex
		hits := 0
		gauge := "21.5"
		srv, _ := scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits++
			n, g := hits, gauge
			mu.Unlock()
			if r.Header.Get("Accept") != "application/openmetrics-text; version=1.0.0" || r.Header.Get("User-Agent") != "soundpost-agent" || r.Method != http.MethodGet {
				http.Error(w, "bad request headers", 400)
				return
			}
			if r.Header.Get("Authorization") != "" || len(r.Cookies()) != 0 {
				http.Error(w, "unexpected credentials", 400)
				return
			}
			scrapeOM(w, fmt.Sprintf("# TYPE reqs counter\nreqs_total{job=\"api\"} %d\n# TYPE temp gauge\ntemp{job=\"worker\"} %s\n# EOF\n", n, g))
		}))
		tg := f.target(srv.URL + "/metrics")
		res1 := f.fetchOK(t, tg)
		scrapeEq(t, "fetch 1 samples", scrapeFlatten(t, res1.Batches), []scrapeRec{
			{"reqs_total", "job=api", "float", "1", "counter", scrapeFloat(1), scrapeT0.UnixNano()},
			{"temp", "job=worker", "float", "1", "gauge", scrapeFloat(21.5), scrapeT0.UnixNano()},
		})
		scrapeEq(t, "fetch 1 seen", scrapeSeen(t, res1.Seen), []string{"reqs_total{job=api}", "temp{job=worker}"})
		if res1.Samples != 2 || res1.StaleMarkers != 0 || res1.At != model.UnixNano(scrapeT0.UnixNano()) || res1.Health.HTTPStatus != 200 || res1.Health.Bytes == 0 {
			t.Fatalf("counters = samples %d stale %d at %d health %+v", res1.Samples, res1.StaleMarkers, res1.At, res1.Health)
		}

		mu.Lock()
		gauge = "30"
		mu.Unlock()
		t1 := scrapeT0.Add(15 * time.Second)
		tg.Previous, tg.Clock = res1.Seen, scrapeClockAt(t1)
		tg.Stale = StalePolicy{OnDisappear: true, OnFailure: true}
		res2 := f.fetchOK(t, tg)
		scrapeEq(t, "fetch 2 samples", scrapeFlatten(t, res2.Batches), []scrapeRec{
			{"reqs_total", "job=api", "float", "1", "counter", scrapeFloat(2), t1.UnixNano()},
			{"temp", "job=worker", "float", "1", "gauge", scrapeFloat(30), t1.UnixNano()},
		})
		scrapeEq(t, "fetch 2 seen", scrapeSeen(t, res2.Seen), []string{"reqs_total{job=api}", "temp{job=worker}"})
		mu.Lock()
		defer mu.Unlock()
		if hits != 2 || res2.StaleMarkers != 0 {
			t.Fatalf("server served %d requests, stale=%d", hits, res2.StaleMarkers)
		}
	})

	t.Run("disappearing series gets exactly one stale marker", func(t *testing.T) {
		var mu sync.Mutex
		body := "# TYPE temp gauge\ntemp{job=\"api\"} 1\ntemp{job=\"worker\"} 2\n# EOF\n"
		srv, _ := scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			scrapeOM(w, body)
		}))
		tg := f.target(srv.URL)
		res1 := f.fetchOK(t, tg)
		mu.Lock()
		body = "# TYPE temp gauge\ntemp{job=\"api\"} 3\n# EOF\n"
		mu.Unlock()

		t1 := scrapeT0.Add(20 * time.Second)
		tg.Previous, tg.Clock = res1.Seen, scrapeClockAt(t1)

		off := f.fetchOK(t, tg)
		if got := scrapeStales(scrapeFlatten(t, off.Batches)); len(got) != 0 || off.StaleMarkers != 0 {
			t.Fatalf("markers without OnDisappear: %+v", got)
		}
		scrapeEq(t, "seen without marker", scrapeSeen(t, off.Seen), []string{"temp{job=api}"})

		tg.Stale.OnDisappear = true
		on := f.fetchOK(t, tg)
		recs := scrapeFlatten(t, on.Batches)
		scrapeEq(t, "samples", scrapeSamples(recs), []scrapeRec{{"temp", "job=api", "float", "1", "gauge", scrapeFloat(3), t1.UnixNano()}})
		scrapeEq(t, "stale", scrapeStales(recs), []scrapeRec{{"temp", "job=worker", "stale", "1", "unknown", scrapeWantStale, t1.UnixNano()}})
		if on.StaleMarkers != 1 || on.Samples != 1 {
			t.Fatalf("stale=%d samples=%d", on.StaleMarkers, on.Samples)
		}
		scrapeEq(t, "seen excludes stale series", scrapeSeen(t, on.Seen), []string{"temp{job=api}"})

		// every stale batch is single-slot, carries the profile identity and the owner slot
		scope, err := f.grant.Scope()
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range on.Batches {
			for _, r := range b.Records {
				slot, err := model.OwnerSlot(scope.OrgID(), f.project, f.source, model.ID{0xaa, 7}, r)
				if err != nil || slot != b.RouteSlot {
					t.Fatalf("record slot %d (%v) != batch slot %d", slot, err, b.RouteSlot)
				}
			}
			if b.Project != f.project || b.Source != f.source || b.Producer != (model.ID{0xaa, 7}) || b.PolicyRevision != 1 || b.Version != 1 {
				t.Fatalf("batch identity %+v", b)
			}
		}
		// a retry of the same scrape reproduces identical stale batch and record IDs
		again := f.fetchOK(t, tg)
		ids := func(r ScrapeResult) (out []string) {
			for _, b := range r.Batches {
				s := b.ID.String()
				for _, rec := range b.Records {
					s += "/" + rec.ID.String()
				}
				out = append(out, s)
			}
			sort.Strings(out)
			return
		}
		scrapeEq(t, "idempotent ids", ids(again), ids(on))
		// a different timestamp must not reuse them
		tg.Clock = scrapeClockAt(t1.Add(time.Second))
		later := f.fetchOK(t, tg)
		for _, a := range ids(later) {
			for _, b := range ids(on) {
				if a == b {
					t.Fatalf("batch/record ids reused across timestamps: %s", a)
				}
			}
		}
	})

	prev := []SeriesRef{
		{Name: "temp", Labels: model.Labels{{Name: "job", Value: "api"}}},
		{Name: "temp", Labels: model.Labels{{Name: "job", Value: "worker"}}},
	}

	t.Run("timeout", func(t *testing.T) {
		srv, _ := scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		}))
		tg := f.target(srv.URL)
		tg.Timeout = 300 * time.Millisecond
		tg.Previous = prev

		began := time.Now()
		res, err := FetchScrape(f.ctx, f.grant, tg)
		if el := time.Since(began); el > tg.Timeout+700*time.Millisecond {
			t.Fatalf("fetch took %v for timeout %v", el, tg.Timeout)
		}
		scrapeMustFail(t, res, err, ScrapeTimeout)
		if len(res.Batches) != 0 || res.StaleMarkers != 0 || res.Samples != 0 {
			t.Fatalf("batches/markers without OnFailure: %+v", res.Batches)
		}
		scrapeEq(t, "seen unchanged", res.Seen, prev)

		tg.Stale.OnFailure = true
		tf := scrapeT0.Add(40 * time.Second)
		tg.Clock = scrapeClockAt(tf)
		res, err = FetchScrape(f.ctx, f.grant, tg)
		scrapeMustFail(t, res, err, ScrapeTimeout)
		recs := scrapeFlatten(t, res.Batches)
		scrapeEq(t, "failure markers", recs, []scrapeRec{
			{"temp", "job=api", "stale", "1", "unknown", scrapeWantStale, tf.UnixNano()},
			{"temp", "job=worker", "stale", "1", "unknown", scrapeWantStale, tf.UnixNano()},
		})
		if res.StaleMarkers != 2 || len(res.Seen) != 0 {
			t.Fatalf("markers=%d seen=%v", res.StaleMarkers, res.Seen)
		}
		// OnDisappear alone must not mark on failure
		tg.Stale = StalePolicy{OnDisappear: true}
		res, err = FetchScrape(f.ctx, f.grant, tg)
		scrapeMustFail(t, res, err, ScrapeTimeout)
		if len(res.Batches) != 0 {
			t.Fatalf("OnDisappear produced failure markers")
		}
	})

	t.Run("timeout bounds a stalled body", func(t *testing.T) {
		srv, _ := scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/openmetrics-text")
			w.Header().Set("Content-Length", "100000")
			w.WriteHeader(200)
			fmt.Fprint(w, "# TYPE temp gauge\n")
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		}))
		tg := f.target(srv.URL)
		tg.Timeout = 300 * time.Millisecond
		began := time.Now()
		res, err := FetchScrape(f.ctx, f.grant, tg)
		if el := time.Since(began); el > tg.Timeout+700*time.Millisecond {
			t.Fatalf("stalled body not bounded: %v", el)
		}
		scrapeMustFail(t, res, err, ScrapeTimeout)
		if len(res.Batches) != 0 {
			t.Fatal("partial body admitted")
		}
	})

	t.Run("connection reset and early close are one class", func(t *testing.T) {
		secret := "reset-secret-token-123"
		for name, h := range map[string]http.HandlerFunc{
			"rst mid body": func(w http.ResponseWriter, r *http.Request) {
				c, _, _ := w.(http.Hijacker).Hijack()
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Type: application/openmetrics-text\r\nContent-Length: 1000\r\n\r\n# TYPE temp gauge\ntemp 1\n")
				c.(*net.TCPConn).SetLinger(0)
				c.Close()
			},
			"rst before response": func(w http.ResponseWriter, r *http.Request) {
				c, _, _ := w.(http.Hijacker).Hijack()
				c.(*net.TCPConn).SetLinger(0)
				c.Close()
			},
			"early close mid body": func(w http.ResponseWriter, r *http.Request) {
				c, _, _ := w.(http.Hijacker).Hijack()
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\nContent-Type: application/openmetrics-text\r\nContent-Length: 1000\r\n\r\n# TYPE temp gauge\ntemp 1\n")
				c.Close()
			},
		} {
			t.Run(name, func(t *testing.T) {
				srv, _ := scrapeServe(t, h)
				tg := f.target(srv.URL)
				tg.Auth, tg.Secret, tg.Secrets = ScrapeAuthBearer, "ref", &scrapeSecrets{value: secret}
				tg.Previous = prev
				res, err := FetchScrape(f.ctx, f.grant, tg)
				scrapeMustFail(t, res, err, ScrapeConnectionReset)
				if len(res.Batches) != 0 || res.Samples != 0 {
					t.Fatal("partial exposition admitted")
				}
				if strings.Contains(fmt.Sprintf("%+v|%#v", res, res), secret) {
					t.Fatal("secret leaked into result")
				}
			})
		}
	})

	t.Run("connection refused", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		l.Close()
		tg := f.target("http://" + addr)
		res, ferr := FetchScrape(f.ctx, f.grant, tg)
		scrapeMustFail(t, res, ferr, ScrapeConnectionRefused)
	})

	t.Run("oversize body is never truncated", func(t *testing.T) {
		body := "# TYPE temp gauge\ntemp{job=\"api\"} 1\n# EOF\n"
		for name, chunked := range map[string]bool{"content-length": false, "chunked": true} {
			t.Run(name, func(t *testing.T) {
				srv, _ := scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/openmetrics-text")
					if chunked {
						half := len(body) / 2
						fmt.Fprint(w, body[:half])
						w.(http.Flusher).Flush()
						fmt.Fprint(w, body[half:])
						return
					}
					fmt.Fprint(w, body)
				}))
				tg := f.target(srv.URL)
				tg.MaxBytes = int64(len(body))
				ok := f.fetchOK(t, tg)
				if ok.Samples != 1 || ok.Health.Bytes != int64(len(body)) {
					t.Fatalf("exact-size body: samples=%d bytes=%d", ok.Samples, ok.Health.Bytes)
				}
				tg.MaxBytes = int64(len(body)) - 1
				res, err := FetchScrape(f.ctx, f.grant, tg)
				scrapeMustFail(t, res, err, ScrapeTooLarge)
				if len(res.Batches) != 0 || res.Samples != 0 {
					t.Fatalf("truncated body admitted: %+v", res.Batches)
				}
			})
		}
	})

	t.Run("bad status content type and malformed body", func(t *testing.T) {
		good := "# TYPE temp gauge\ntemp 1\n# EOF\n"
		cases := []struct {
			name   string
			status int
			ctype  string
			body   string
			want   ScrapeStatus
		}{
			{"500", 500, "application/openmetrics-text", good, ScrapeBadStatus},
			{"404", 404, "application/openmetrics-text", good, ScrapeBadStatus},
			{"204", 204, "application/openmetrics-text", "", ScrapeBadStatus},
			{"text plain", 200, "text/plain; version=0.0.4", good, ScrapeDecodeFailed},
			{"no content type", 200, "", good, ScrapeDecodeFailed},
			{"missing EOF", 200, "application/openmetrics-text", "# TYPE temp gauge\ntemp 1\n", ScrapeDecodeFailed},
			{"garbage", 200, "application/openmetrics-text", "\x00\x01 not metrics\n# EOF\n", ScrapeDecodeFailed},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				srv, _ := scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if c.ctype != "" {
						w.Header().Set("Content-Type", c.ctype)
					} else {
						w.Header()["Content-Type"] = nil
					}
					w.WriteHeader(c.status)
					fmt.Fprint(w, c.body)
				}))
				tg := f.target(srv.URL)
				tg.Previous, tg.Stale = prev, StalePolicy{OnFailure: true}
				res, err := FetchScrape(f.ctx, f.grant, tg)
				scrapeMustFail(t, res, err, c.want)
				if c.status != 200 && res.Health.HTTPStatus != c.status {
					t.Fatalf("http status %d", res.Health.HTTPStatus)
				}
				if got := scrapeSamples(scrapeFlatten(t, res.Batches)); len(got) != 0 || res.Samples != 0 {
					t.Fatalf("samples admitted from a failed exchange: %+v", got)
				}
				if res.StaleMarkers != 2 {
					t.Fatalf("OnFailure markers = %d", res.StaleMarkers)
				}
			})
		}
	})

	t.Run("redirect is refused and never followed", func(t *testing.T) {
		for _, code := range []int{301, 302, 303, 307, 308} {
			t.Run(fmt.Sprint(code), func(t *testing.T) {
				second, secondL := scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					scrapeOM(w, "# TYPE temp gauge\ntemp 1\n# EOF\n")
				}))
				first, _ := scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, second.URL+"/metrics", code)
				}))
				res, err := FetchScrape(f.ctx, f.grant, f.target(first.URL))
				scrapeMustFail(t, res, err, ScrapeRedirectRefused)
				if res.Health.HTTPStatus != code || len(res.Batches) != 0 {
					t.Fatalf("http=%d batches=%d", res.Health.HTTPStatus, len(res.Batches))
				}
				if n := secondL.accepts.Load(); n != 0 {
					t.Fatalf("redirect target received %d connections", n)
				}
			})
		}
	})

	t.Run("forbidden destinations are never connected to", func(t *testing.T) {
		var served atomic.Int64
		srv, cl := scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			served.Add(1)
			scrapeOM(w, "# TYPE temp gauge\ntemp 1\n# EOF\n")
		}))
		port := srv.Listener.Addr().(*net.TCPAddr).Port
		deny := func(t *testing.T, tg ScrapeTarget) {
			t.Helper()
			began := time.Now()
			res, err := FetchScrape(f.ctx, f.grant, tg)
			scrapeMustFail(t, res, err, ScrapeEgressDenied)
			if len(res.Batches) != 0 {
				t.Fatal("batches from denied destination")
			}
			if time.Since(began) > 500*time.Millisecond {
				t.Fatal("denial was not immediate (a dial was attempted)")
			}
			if cl.accepts.Load() != 0 || served.Load() != 0 {
				t.Fatalf("listener saw %d accepts, %d requests", cl.accepts.Load(), served.Load())
			}
		}
		t.Run("literal loopback under default policy", func(t *testing.T) {
			tg := f.target(fmt.Sprintf("http://127.0.0.1:%d/metrics", port))
			tg.Egress = EgressPolicy{}
			deny(t, tg)
		})
		for _, lit := range []string{"[::1]", "10.0.0.1", "169.254.169.254", "[::ffff:127.0.0.1]", "0.0.0.0", "192.168.1.1", "[fe80::1]"} {
			t.Run("literal "+lit, func(t *testing.T) {
				tg := f.target(fmt.Sprintf("http://%s:%d/", lit, port))
				tg.Egress = EgressPolicy{}
				tg.Timeout = 2 * time.Second
				deny(t, tg)
			})
		}
		for _, answers := range [][]string{
			{"127.0.0.1"}, {"10.0.0.1"}, {"169.254.169.254"}, {"::ffff:127.0.0.1"}, {"::1"},
			{"8.8.8.8", "127.0.0.1"}, {"127.0.0.1", "8.8.8.8"}, {"8.8.8.8", "::ffff:10.0.0.1"},
		} {
			t.Run("name resolving to "+strings.Join(answers, ","), func(t *testing.T) {
				res := &scrapeResolver{answers: answers}
				tg := f.target(fmt.Sprintf("http://exporter.example:%d/metrics", port))
				tg.Egress = EgressPolicy{Resolver: res}
				deny(t, tg)
				if res.calls.Load() != 1 {
					t.Fatalf("resolver called %d times", res.calls.Load())
				}
			})
		}
		t.Run("loopback seam cannot lift link-local or private", func(t *testing.T) {
			for _, a := range []string{"169.254.169.254", "10.0.0.1"} {
				tg := f.target(fmt.Sprintf("http://exporter.example:%d/", port))
				tg.Egress = EgressPolicy{loopbackOK: true, Resolver: &scrapeResolver{answers: []string{a}}}
				deny(t, tg)
			}
		})
		t.Run("allow list cannot cover never-allowed ranges", func(t *testing.T) {
			for _, p := range []string{"127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/0", "::/0", "::1/128", "fe80::/10", "100.100.100.200/32"} {
				tg := f.target("http://exporter.example/")
				tg.Egress = EgressPolicy{AllowPrefixes: []netip.Prefix{netip.MustParsePrefix(p)}}
				_, err := FetchScrape(f.ctx, f.grant, tg)
				scrapeWantFault(t, err, model.Invalid)
			}
			tg := f.target("http://exporter.example/")
			tg.Egress = EgressPolicy{AllowPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
			if err := tg.Egress.validate(); err != nil {
				t.Fatalf("private allow prefix rejected: %v", err)
			}
		})
		t.Run("a permitted name resolves and connects to the validated literal", func(t *testing.T) {
			res := &scrapeResolver{answers: []string{"127.0.0.1"}}
			tg := f.target(fmt.Sprintf("http://exporter.example:%d/metrics", port))
			tg.Egress = EgressPolicy{loopbackOK: true, Resolver: res}
			f.fetchOK(t, tg)
			if cl.accepts.Load() != 1 || served.Load() != 1 || res.lastHost.Load().(string) != "exporter.example" {
				t.Fatalf("accepts=%d served=%d host=%v", cl.accepts.Load(), served.Load(), res.lastHost.Load())
			}
		})
		t.Run("dialer and Control re-check the connected address", func(t *testing.T) {
			before := cl.accepts.Load()
			p := EgressPolicy{}
			dial := p.dialContext(time.Second)
			if c, err := dial(f.ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port)); !errors.Is(err, errScrapeEgress) || c != nil {
				t.Fatalf("literal loopback dial: %v", err)
			}
			if c, err := dial(f.ctx, "udp", "8.8.8.8:53"); !errors.Is(err, errScrapeEgress) || c != nil {
				t.Fatalf("udp dial: %v", err)
			}
			if err := p.control("tcp4", fmt.Sprintf("127.0.0.1:%d", port), nil); !errors.Is(err, errScrapeEgress) {
				t.Fatalf("control tcp4 loopback: %v", err)
			}
			if err := p.control("tcp6", "[::ffff:10.0.0.1]:80", nil); !errors.Is(err, errScrapeEgress) {
				t.Fatalf("control mapped private: %v", err)
			}
			if err := p.control("udp4", "8.8.8.8:53", nil); !errors.Is(err, errScrapeEgress) {
				t.Fatalf("control udp: %v", err)
			}
			if err := p.control("tcp4", "not-an-address", nil); !errors.Is(err, errScrapeEgress) {
				t.Fatalf("control malformed: %v", err)
			}
			if err := p.control("tcp4", "8.8.8.8:443", nil); err != nil {
				t.Fatalf("control public: %v", err)
			}
			if cl.accepts.Load() != before {
				t.Fatalf("a refused dial reached the listener")
			}
		})
	})

	t.Run("secrets", func(t *testing.T) {
		const secret = "s3cr3t-token-XYZ-0042"
		var mu sync.Mutex
		var seen []string
		status := 200
		srv, cl := scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen = append(seen, r.Header.Get("Authorization"))
			st := status
			mu.Unlock()
			if st == 500 {
				http.Error(w, "boom "+r.Header.Get("Authorization"), 500)
				return
			}
			if st == 0 {
				c, _, _ := w.(http.Hijacker).Hijack()
				c.(*net.TCPConn).SetLinger(0)
				c.Close()
				return
			}
			scrapeOM(w, "# TYPE temp gauge\ntemp 1\n# EOF\n")
		}))
		leakCheck := func(t *testing.T, res ScrapeResult, err error, secrets ...string) {
			t.Helper()
			dump := fmt.Sprintf("%+v|%#v|%v", res, res, err)
			for _, s := range secrets {
				if strings.Contains(dump, s) {
					t.Fatalf("secret %q leaked into result/error", s)
				}
			}
		}
		t.Run("bearer sent, zeroed, not leaked", func(t *testing.T) {
			for _, st := range []int{200, 500, 0} {
				mu.Lock()
				status, seen = st, nil
				mu.Unlock()
				rd := &scrapeSecrets{value: secret}
				tg := f.target(srv.URL)
				tg.Auth, tg.Secret, tg.Secrets = ScrapeAuthBearer, "metrics-token", rd
				res, err := FetchScrape(f.ctx, f.grant, tg)
				switch st {
				case 200:
					scrapeMustOK(t, res, err)
				case 500:
					scrapeMustFail(t, res, err, ScrapeBadStatus)
				default:
					scrapeMustFail(t, res, err, ScrapeConnectionReset)
				}
				mu.Lock()
				got := append([]string(nil), seen...)
				mu.Unlock()
				scrapeEq(t, "authorization seen by server", got, []string{"Bearer " + secret})
				if rd.ref != "metrics-token" || rd.reads != 1 {
					t.Fatalf("reader got ref %q reads %d", rd.ref, rd.reads)
				}
				for i, b := range rd.last {
					if b != 0 {
						t.Fatalf("secret byte %d not zeroed (status %d)", i, st)
					}
				}
				if len(rd.last) != len(secret) {
					t.Fatalf("kept slice len %d", len(rd.last))
				}
				leakCheck(t, res, err, secret, "Bearer")
			}
		})
		t.Run("secret is read fresh on every fetch", func(t *testing.T) {
			mu.Lock()
			status, seen = 200, nil
			mu.Unlock()
			rd := &scrapeSecrets{value: "first-token-1"}
			tg := f.target(srv.URL)
			tg.Auth, tg.Secret, tg.Secrets = ScrapeAuthBearer, "r", rd
			f.fetchOK(t, tg)
			rd.value = "second-token-2"
			f.fetchOK(t, tg)
			mu.Lock()
			defer mu.Unlock()
			scrapeEq(t, "rotated", seen, []string{"Bearer first-token-1", "Bearer second-token-2"})
		})
		t.Run("basic", func(t *testing.T) {
			mu.Lock()
			status, seen = 200, nil
			mu.Unlock()
			rd := &scrapeSecrets{value: "scraper:pa:ss"}
			tg := f.target(srv.URL)
			tg.Auth, tg.Secret, tg.Secrets = ScrapeAuthBasic, "basic", rd
			f.fetchOK(t, tg)
			mu.Lock()
			defer mu.Unlock()
			scrapeEq(t, "basic header", seen, []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("scraper:pa:ss"))})
		})
		t.Run("unavailable secret sends nothing", func(t *testing.T) {
			before := cl.accepts.Load()
			for name, rd := range map[string]*scrapeSecrets{
				"read error": {err: errors.New("vault says " + secret)},
				"empty":      {value: ""},
				"newline":    {value: secret + "\n"},
			} {
				tg := f.target(srv.URL)
				tg.Auth, tg.Secret, tg.Secrets = ScrapeAuthBearer, "r", rd
				tg.Previous, tg.Stale = prev, StalePolicy{OnFailure: true}
				res, err := FetchScrape(f.ctx, f.grant, tg)
				scrapeMustFail(t, res, err, ScrapeSecretUnavailable)
				leakCheck(t, res, err, secret)
				if res.StaleMarkers != 2 {
					t.Fatalf("%s: markers %d", name, res.StaleMarkers)
				}
				for i, b := range rd.last {
					if b != 0 {
						t.Fatalf("%s: byte %d not zeroed", name, i)
					}
				}
			}
			tg := f.target(srv.URL)
			tg.Auth, tg.Secret, tg.Secrets = ScrapeAuthBasic, "r", &scrapeSecrets{value: "no-colon-here"}
			res, err := FetchScrape(f.ctx, f.grant, tg)
			scrapeMustFail(t, res, err, ScrapeSecretUnavailable)
			if cl.accepts.Load() != before {
				t.Fatalf("requests were sent without a usable secret: %d connections", cl.accepts.Load()-before)
			}
		})
	})

	t.Run("tls", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scrapeOM(w, "# TYPE temp gauge\ntemp 1\n# EOF\n")
		}))
		t.Cleanup(srv.Close)
		tg := f.target(srv.URL)
		res, err := FetchScrape(f.ctx, f.grant, tg)
		scrapeMustFail(t, res, err, ScrapeTLSFailed) // system roots do not trust the test CA
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		tg.TLS.RootCAs = pool
		f.fetchOK(t, tg)
		tg.TLS.ServerName = "wrong.example"
		res, err = FetchScrape(f.ctx, f.grant, tg)
		scrapeMustFail(t, res, err, ScrapeTLSFailed)
		plain, _ := scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { scrapeOM(w, "# EOF\n") }))
		tg = f.target("https://" + strings.TrimPrefix(plain.URL, "http://"))
		tg.TLS.RootCAs = pool
		res, err = FetchScrape(f.ctx, f.grant, tg)
		scrapeMustFail(t, res, err, ScrapeTLSFailed)
	})

	t.Run("cancellation", func(t *testing.T) {
		var served atomic.Int64
		srv, _ := scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			served.Add(1)
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		}))
		ctx, cancel := context.WithCancel(f.ctx)
		cancel()
		_, err := FetchScrape(ctx, f.grant, f.target(srv.URL))
		scrapeWantFault(t, err, model.Cancelled)
		if served.Load() != 0 {
			t.Fatal("request sent after cancellation")
		}
		ctx, cancel = context.WithCancel(f.ctx)
		time.AfterFunc(150*time.Millisecond, cancel)
		tg := f.target(srv.URL)
		tg.Timeout, tg.Interval = 2*time.Second, 2*time.Second
		res, err := FetchScrape(ctx, f.grant, tg)
		scrapeMustFail(t, res, err, ScrapeCancelled)
	})

	t.Run("invalid configuration is a typed error and sends nothing", func(t *testing.T) {
		srv, cl := scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scrapeOM(w, "# TYPE temp gauge\ntemp 1\n# EOF\n")
		}))
		long := strings.Repeat("a", 65)
		cases := []struct {
			name string
			mut  func(*ScrapeTarget)
		}{
			{"userinfo", func(t *ScrapeTarget) { t.URL = strings.Replace(srv.URL, "http://", "http://user:pw@", 1) }},
			{"fragment", func(t *ScrapeTarget) { t.URL += "/#frag" }},
			{"ftp", func(t *ScrapeTarget) { t.URL = "ftp://127.0.0.1/x" }},
			{"relative", func(t *ScrapeTarget) { t.URL = "/metrics" }},
			{"no host", func(t *ScrapeTarget) { t.URL = "http:///metrics" }},
			{"empty alias", func(t *ScrapeTarget) { t.Alias = "" }},
			{"alias slash", func(t *ScrapeTarget) { t.Alias = "a/b" }},
			{"alias url", func(t *ScrapeTarget) { t.Alias = "http://x" }},
			{"alias 65", func(t *ScrapeTarget) { t.Alias = long }},
			{"timeout > interval", func(t *ScrapeTarget) { t.Timeout = t.Interval + time.Millisecond }},
			{"timeout 0", func(t *ScrapeTarget) { t.Timeout = 0 }},
			{"interval < 1s", func(t *ScrapeTarget) { t.Interval, t.Timeout = 999*time.Millisecond, 500*time.Millisecond }},
			{"max bytes 0", func(t *ScrapeTarget) { t.MaxBytes = 0 }},
			{"max bytes negative", func(t *ScrapeTarget) { t.MaxBytes = -1 }},
			{"max bytes > 64MiB", func(t *ScrapeTarget) { t.MaxBytes = 64<<20 + 1 }},
			{"auth without secrets", func(t *ScrapeTarget) { t.Auth, t.Secret = ScrapeAuthBearer, "r" }},
			{"auth without ref", func(t *ScrapeTarget) { t.Auth, t.Secrets = ScrapeAuthBearer, &scrapeSecrets{value: "x"} }},
			{"unknown auth", func(t *ScrapeTarget) { t.Auth, t.Secret, t.Secrets = "digest", "r", &scrapeSecrets{value: "x"} }},
			{"secret without auth", func(t *ScrapeTarget) { t.Secret = "r" }},
			{"profile limits zero", func(t *ScrapeTarget) { t.Profile.Limits = queryinput.Limits{} }},
			{"profile without producer", func(t *ScrapeTarget) { t.Profile.Producer = model.ID{} }},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				tg := f.target(srv.URL)
				c.mut(&tg)
				_, err := FetchScrape(f.ctx, f.grant, tg)
				scrapeWantFault(t, err, model.Invalid)
			})
		}
		t.Run("grant that does not cover the profile", func(t *testing.T) {
			tg := f.target(srv.URL)
			tg.Profile.Project = model.NewID()
			_, err := FetchScrape(f.ctx, f.grant, tg)
			scrapeWantFault(t, err, model.Forbidden)
			tg = f.target(srv.URL)
			tg.Profile.Source = model.NewID()
			_, err = FetchScrape(f.ctx, f.grant, tg)
			scrapeWantFault(t, err, model.Forbidden)
		})
		t.Run("zero grant", func(t *testing.T) {
			_, err := FetchScrape(f.ctx, policy.SourceGrant{}, f.target(srv.URL))
			scrapeWantFault(t, err, model.Stale)
		})
		if cl.accepts.Load() != 0 {
			t.Fatalf("invalid configuration reached the network: %d connections", cl.accepts.Load())
		}
		t.Run("boundary values are accepted", func(t *testing.T) {
			tg := f.target(srv.URL)
			tg.Interval, tg.Timeout, tg.MaxBytes = time.Second, time.Second, 64<<20
			f.fetchOK(t, tg)
			tg.MaxBytes, tg.Alias = 1, strings.Repeat("a", 64)
			res, err := FetchScrape(f.ctx, f.grant, tg)
			if err != nil || res.Health.Status != ScrapeTooLarge || res.Target != strings.Repeat("a", 64) {
				t.Fatalf("1-byte cap: %v %+v", err, res.Health)
			}
		})
	})

	t.Run("empty exposition is a successful scrape with no series", func(t *testing.T) {
		srv, _ := scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { scrapeOM(w, "# EOF\n") }))
		tg := f.target(srv.URL)
		tg.Previous, tg.Stale = prev, StalePolicy{OnDisappear: true}
		res := f.fetchOK(t, tg)
		if res.Samples != 0 || res.StaleMarkers != 2 || len(res.Seen) != 0 {
			t.Fatalf("samples=%d stale=%d seen=%v", res.Samples, res.StaleMarkers, res.Seen)
		}
		if got := scrapeStales(scrapeFlatten(t, res.Batches)); len(got) != 2 {
			t.Fatalf("stale records %+v", got)
		}
	})
}

func (f *scrapeFixture) fetchOK(t *testing.T, tg ScrapeTarget) ScrapeResult {
	t.Helper()
	res, err := FetchScrape(f.ctx, f.grant, tg)
	return scrapeMustOK(t, res, err)
}

// ---- fakes ----

type scrapeSecrets struct {
	value string
	err   error
	ref   SecretRef
	reads int
	last  []byte
}

func (s *scrapeSecrets) ReadSecret(_ context.Context, ref SecretRef) ([]byte, error) {
	s.ref = ref
	s.reads++
	if s.err != nil {
		s.last = []byte("error-path-secret-bytes")
		return s.last, s.err
	}
	s.last = []byte(s.value)
	return s.last, nil
}

type scrapeResolver struct {
	answers  []string
	calls    atomic.Int64
	lastHost atomic.Value
}

func (r *scrapeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.calls.Add(1)
	r.lastHost.Store(host)
	var out []netip.Addr
	for _, a := range r.answers {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

func scrapeWantFault(t *testing.T, err error, code model.Code) {
	t.Helper()
	var f *model.Fault
	if !errors.As(err, &f) || f.Code != code {
		t.Fatalf("error = %v, want model.Fault %s", err, code)
	}
}

// ---- default egress table ----

func TestScrapeDefaultEgressTable(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.255.255.255", "::1", "::ffff:127.0.0.1", "::ffff:7f00:1", "0.0.0.0", "::", "0.1.2.3",
		"10.0.0.1", "10.255.255.255", "::ffff:10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.0.1", "192.168.255.255",
		"100.64.0.1", "100.127.255.255", "169.254.169.254", "169.254.0.1", "fe80::1", "fd00:ec2::254", "100.100.100.200", "168.63.129.16", "192.0.0.192",
		"224.0.0.1", "239.255.255.255", "ff02::1", "255.255.255.255", "240.0.0.1", "fc00::1", "fd12:3456::1",
		"64:ff9b::7f00:1", "64:ff9b::a00:1", "2002:7f00:1::1", "203.0.113.5", "198.51.100.1", "192.0.2.1", "198.18.0.1", "2001:db8::1", "fec0::1",
		"fe80::1%eth0",
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "172.15.255.255", "172.32.0.1", "11.0.0.1", "9.255.255.255", "100.63.255.255", "100.128.0.1", "2606:4700:4700::1111", "::ffff:8.8.8.8", "169.253.255.255"}
	def := EgressPolicy{}
	for _, s := range blocked {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if err := def.check(a); !errors.Is(err, errScrapeEgress) {
			t.Errorf("default policy admits %s", s)
		}
	}
	for _, s := range allowed {
		if err := def.check(netip.MustParseAddr(s)); err != nil {
			t.Errorf("default policy blocks public %s: %v", s, err)
		}
	}
	if err := def.check(netip.Addr{}); !errors.Is(err, errScrapeEgress) {
		t.Error("invalid address admitted")
	}

	lift := EgressPolicy{AllowPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("::ffff:192.168.0.0/112")}}
	if err := lift.validate(); err != nil {
		t.Fatal(err)
	}
	for s, ok := range map[string]bool{
		"10.1.2.3": true, "::ffff:10.1.2.3": true, "192.168.4.4": true, "11.0.0.1": true,
		"172.16.0.1": false, "127.0.0.1": false, "169.254.169.254": false, "::1": false, "100.64.0.1": false,
	} {
		err := lift.check(netip.MustParseAddr(s))
		if ok != (err == nil) {
			t.Errorf("allow-list %s: admitted=%v want %v", s, err == nil, ok)
		}
	}

	seam := EgressPolicy{loopbackOK: true}
	for s, ok := range map[string]bool{
		"127.0.0.1": true, "::1": true, "::ffff:127.0.0.1": true, "127.9.9.9": true,
		"10.0.0.1": false, "169.254.169.254": false, "0.0.0.0": false, "fe80::1": false, "8.8.8.8": true,
	} {
		err := seam.check(netip.MustParseAddr(s))
		if ok != (err == nil) {
			t.Errorf("loopback seam %s: admitted=%v want %v", s, err == nil, ok)
		}
	}
}
