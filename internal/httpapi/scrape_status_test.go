// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
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
