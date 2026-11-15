// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

// fakeScrapeStatus is a labelled test double for the node's scrape host adapter: it
// answers fixed states. The authorization under test is the real auth service
// and the real control store.
type fakeScrapeStatus []httpapi.ScrapeTargetState

func (f fakeScrapeStatus) ScrapeTargets() []httpapi.ScrapeTargetState {
	return []httpapi.ScrapeTargetState(f)
}

func TestScrapeStatusRouteAuthorizationMatrix(t *testing.T) {
	e := newIsoEnv(t)
	projA, projB := model.NewID(), model.NewID()
	orgA, orgB := e.org("scrape-a", projA), e.org("scrape-b", projB)
	adminA, adminB := e.user(orgA, "scrape-admin-a@example.test"), e.user(orgB, "scrape-admin-b@example.test")
	memberA := e.user(orgA, "scrape-member-a@example.test")
	readerA := e.user(orgA, "scrape-reader-a@example.test")
	e.grant(orgA, readerA, projA, true, auth.Read)
	e.cmd(orgA, "org_admin", auth.AdminPayload{UserID: adminA.ID, Enabled: true})
	e.cmd(orgB, "org_admin", auth.AdminPayload{UserID: adminB.ID, Enabled: true})
	attempt := time.Unix(1_700_000_000, 0).UTC()
	host := fakeScrapeStatus{
		{Alias: "alpha", Project: projA, Cycles: 3, LastAttempt: attempt, AdmitFailures: 1, Health: "ok", HTTPStatus: 200, Coverage: "complete", Samples: 41, StaleMarkers: 2},
		{Alias: "beta", Project: projB, Cycles: 1, Reason: "grant_denied", LastAttempt: attempt, Health: "bad_status"},
	}
	srv := httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterScrapeStatusRoutes(mux, e.app.Auth, e.app.Control, host)
	}).Handler)
	t.Cleanup(srv.Close)
	get := func(who *person, query string) (int, []byte) {
		req, _ := http.NewRequest("GET", srv.URL+"/api/v1/admin/scrape/targets"+query, nil)
		if who != nil {
			req.Header.Set("Cookie", "__Host-soundpost="+who.Session.Token)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		return resp.StatusCode, []byte(b.String())
	}

	status, raw := get(&adminA, "?org="+orgA.String())
	if status != 200 {
		t.Fatalf("org admin A: %d %s", status, raw)
	}
	var view struct {
		Targets []map[string]any `json:"targets"`
	}
	if err := json.Unmarshal(raw, &view); err != nil || len(view.Targets) != 1 {
		t.Fatalf("org admin A sees exactly the targets admitting into A: %s", raw)
	}
	got := view.Targets[0]
	want := map[string]bool{"alias": true, "last_attempt_at": true, "cycles": true, "health": true, "reason": true, "http_status": true, "coverage": true, "samples": true, "stale_markers": true, "admit_failures": true}
	for k := range got {
		if !want[k] {
			t.Fatalf("unexpected field %q in %s", k, raw)
		}
	}
	if got["alias"] != "alpha" || got["health"] != "ok" || got["samples"] != float64(41) || got["stale_markers"] != float64(2) || got["cycles"] != float64(3) || got["admit_failures"] != float64(1) || got["coverage"] != "complete" {
		t.Fatalf("payload %s", raw)
	}
	if got["last_attempt_at"] == nil || got["last_attempt_at"] == "" {
		t.Fatalf("last attempt time missing: %s", raw)
	}
	if strings.Contains(string(raw), "beta") || strings.Contains(string(raw), projA.String()) || strings.Contains(string(raw), projB.String()) {
		t.Fatalf("another org's target or a project id leaked: %s", raw)
	}

	status, raw = get(&adminB, "?org="+orgB.String())
	if status != 200 || !strings.Contains(string(raw), `"beta"`) || strings.Contains(string(raw), "alpha") || !strings.Contains(string(raw), "grant_denied") {
		t.Fatalf("org admin B: %d %s", status, raw)
	}

	for name, c := range map[string]struct {
		who   *person
		query string
		want  int
	}{
		"admin of A asks for B":   {&adminA, "?org=" + orgB.String(), 404},
		"member (not admin) of A": {&memberA, "?org=" + orgA.String(), 404},
		"member with read grant":  {&readerA, "?org=" + orgA.String(), 404},
		"missing org":             {&adminA, "", 404},
		"malformed org":           {&adminA, "?org=nope", 404},
		"unknown org":             {&adminA, "?org=" + model.NewID().String(), 404},
		"extra query key":         {&adminA, "?org=" + orgA.String() + "&x=1", 400},
		"unauthenticated":         {nil, "?org=" + orgA.String(), 401},
	} {
		if status, raw := get(c.who, c.query); status != c.want {
			t.Fatalf("%s: %d want %d: %s", name, status, c.want, raw)
		}
	}
	// Existing-but-forbidden and absent must be indistinguishable.
	strip := func(raw []byte) string {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("%s", raw)
		}
		delete(m, "request_id")
		out, _ := json.Marshal(m)
		return string(out)
	}
	_, forbidden := get(&adminA, "?org="+orgB.String())
	_, absent := get(&adminA, "?org="+model.NewID().String())
	if strip(forbidden) != strip(absent) {
		t.Fatalf("a foreign org is distinguishable from an absent one:\n%s\n%s", forbidden, absent)
	}
	// Read-only.
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/admin/scrape/targets?org="+orgA.String(), nil)
	req.Header.Set("Cookie", "__Host-soundpost="+adminA.Session.Token)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST must not be routed: %d", resp.StatusCode)
	}
}

func TestScrapeStatusRouteCarriesNoSecretOrURL(t *testing.T) {
	e := newIsoEnv(t)
	proj := model.NewID()
	org := e.org("scrape-canary", proj)
	admin := e.user(org, "scrape-canary-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	// Everything a ScrapeTargetStatus could carry is filled; the canary sits in
	// the one free-text field (alias is operator-chosen and documented as safe),
	// so this asserts only that the response is built from typed fields.
	host := fakeScrapeStatus{{Alias: "svc", Project: proj, Cycles: 1, Reason: "credential_unavailable", LastAttempt: time.Now(), Health: "secret_unavailable"}}
	srv := httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterScrapeStatusRoutes(mux, e.app.Auth, e.app.Control, host)
	}).Handler)
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/admin/scrape/targets?org="+org.String(), nil)
	req.Header.Set("Cookie", "__Host-soundpost="+admin.Session.Token)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		body.Write(buf[:n])
		if err != nil {
			break
		}
	}
	text := body.String()
	for _, banned := range []string{"http://", "https://", "secret_ref", "url", "token", "authorization", "credential_secret"} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(banned)) {
			t.Fatalf("%q in %s", banned, text)
		}
	}
	if !strings.Contains(text, "credential_unavailable") || !strings.Contains(text, "secret_unavailable") {
		t.Fatalf("typed health/reason missing: %s", text)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("cache header %q", resp.Header.Get("Cache-Control"))
	}
}

// scrapeHostHolding stands for the real scrape host: it holds everything a
// target is configured with and everything a fetch returned (URL with a query
// token, secret reference and value, request header, response body, transport
// error text), and, like the production adapter, answers the route with typed
// states only. Every string field of ScrapeTargetState is also planted with a
// canary by reflection, so a field added to the state (and copied to the view)
// that is not a closed-vocabulary field shows up here.
type scrapeHostHolding struct {
	held  map[string]string
	state httpapi.ScrapeTargetState
}

func (h *scrapeHostHolding) ScrapeTargets() []httpapi.ScrapeTargetState {
	return []httpapi.ScrapeTargetState{h.state}
}

func TestScrapeStatusRouteNeverCarriesWhatTheHostHolds(t *testing.T) {
	e := newIsoEnv(t)
	proj := model.NewID()
	org := e.org("scrape-host-canary", proj)
	admin := e.user(org, "scrape-host-canary-admin@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})

	host := &scrapeHostHolding{held: map[string]string{
		"url":              "https://exporter-canary-8a1f.example.test/metrics?token=canary-query-token-5c2e",
		"secret reference": "canary-secret-ref-77d0",
		"secret value":     "CANARY-secret-value-93b4",
		"authorization":    "Bearer CANARY-bearer-1e6a",
		"response body":    "node_secret{pw=\"CANARY-body-4d83\"} 1",
		"transport error":  "Get \"https://exporter-canary-8a1f.example.test/metrics\": dial tcp 10.9.8.7:443: connect: connection refused",
	}}
	// every string and number of the state is filled; the closed-vocabulary
	// fields and the operator alias are the only ones allowed to be answered
	planted := map[string]string{}
	v := reflect.ValueOf(&host.state).Elem()
	for i := range v.NumField() {
		name, f := v.Type().Field(i).Name, v.Field(i)
		switch f.Kind() {
		case reflect.String:
			planted[name] = "CANARY-" + name + "-3f9a"
			f.SetString(planted[name])
		case reflect.Uint64:
			f.SetUint(7)
		case reflect.Int:
			f.SetInt(200)
		}
	}
	host.state.Project = proj
	host.state.LastAttempt = time.Unix(1_700_000_000, 0).UTC()
	answered := map[string]bool{"Alias": true, "Health": true, "Reason": true, "Coverage": true}

	srv := httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterScrapeStatusRoutes(mux, e.app.Auth, e.app.Control, host)
	}).Handler)
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/admin/scrape/targets?org="+org.String(), nil)
	req.Header.Set("Cookie", "__Host-soundpost="+admin.Session.Token)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if rerr != nil {
			break
		}
	}
	text := sb.String()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, text)
	}
	forms := func(s string) []string {
		q := strconv.Quote(s)
		return []string{s, q[1 : len(q)-1], url.QueryEscape(s), url.PathEscape(s)}
	}
	for what, secret := range host.held {
		for _, form := range forms(secret) {
			if strings.Contains(text, form) {
				t.Errorf("the route carries the host's %s: %s", what, text)
			}
		}
	}
	for name, canary := range planted {
		has := strings.Contains(text, canary)
		switch {
		case answered[name] && !has:
			t.Errorf("the planted %s is not answered (the planting is broken): %s", name, text)
		case !answered[name] && has:
			t.Errorf("the state field %s reaches the route, but it is not a closed-vocabulary field: %s", name, text)
		}
	}
	if strings.Contains(text, proj.String()) {
		t.Errorf("a project id reaches the route: %s", text)
	}
}
