// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

// serve registers the scrape status route exactly when it hosts scrapers, over
// the node's own authority; the route answers an unauthenticated caller 401 (a
// missing route would be 404).
func TestScrapeStatusRoutesAreRegisteredOnlyWithAHost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if r := scrapeStatusRoutes(app, nil); r != nil {
		t.Fatal("no host, no route")
	}
	config, secrets := scrapeCmdFiles(t, "https://127.0.0.1:9/metrics", nil)
	settings, err := parseScrapeFlags(t, "--scrape-config", config, "--scrape-secrets-dir", secrets).settings()
	if err != nil {
		t.Fatal(err)
	}
	host, err := settings.start(context.Background(), app)
	if err != nil || host == nil {
		t.Fatalf("%v %v", host, err)
	}
	defer host.Close()
	register := scrapeStatusRoutes(app, host)
	if register == nil {
		t.Fatal("a host must register the route")
	}
	srv := httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, register).Handler)
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL + "/api/v1/admin/scrape/targets?org=" + "00000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

// scrapeCanaryForms are the encodings a leak could take on the wire.
func scrapeCanaryForms(s string) []string {
	q := strconv.Quote(s)
	return []string{s, q[1 : len(q)-1], url.QueryEscape(s), url.PathEscape(s), base64.StdEncoding.EncodeToString([]byte(s)), base64.URLEncoding.EncodeToString([]byte(s)), hex.EncodeToString([]byte(s))}
}

// The scrape host holds the target URL (with a path and a query token), the
// target's secret reference and value, the source credential, the TLS server
// name and the resource identity. A canary is planted in every one of them, the
// real host runs real cycles (the host name does not resolve, so the transport
// error text would quote the whole URL), and the status route, called as a real
// organization administrator through the real adapter, must carry none of them,
// in any encoding.
func TestScrapeStatusRouteNeverCarriesWhatTheHostHolds(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	ctx := context.Background()
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	boot, err := app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := app.Auth.Bootstrap(ctx, boot, "scrape-owner@example.test", "scrape status owner password 2026")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	org, admin := model.NewID(), model.NewID()
	command := func(kind string, p auth.AdminPayload) {
		t.Helper()
		var revision model.Revision
		if err := app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
			t.Fatal(err)
		}
		p.Reason = "scrape status canary"
		raw, _ := json.Marshal(p)
		if _, err := app.Auth.AdminCommand(ctx, owner, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
			t.Fatalf("admin %s: %v", kind, err)
		}
	}
	command("create_org", auth.AdminPayload{Name: "scrape-canary"})
	command("create_project", auth.AdminPayload{ID: model.ID{1}, Name: "scrape"}) // the project of scrapeCmdFiles
	command("create_user", auth.AdminPayload{ID: admin, Email: "scrape-admin@example.test", Password: "scrape status admin password 2026"})
	command("membership", auth.AdminPayload{UserID: admin, Enabled: true})
	command("org_admin", auth.AdminPayload{UserID: admin, Enabled: true})
	login, err := app.Auth.Login(ctx, "scrape-admin@example.test", "scrape status admin password 2026", "")
	if err != nil {
		t.Fatal(err)
	}

	const (
		canaryHost     = "canary-host-7d3a91.invalid"
		canaryPath     = "canary-path-2c58e0"
		canaryQuery    = "canary-query-token-91ab34"
		canaryRef      = "canaryref9f2c11"
		canaryRefValue = "CANARY-ref-value-0e6d77"
		canaryInstance = "canaryinstance41ab09"
		canarySNI      = "canary-sni-4e9b12.example.test"
	)
	config, secrets := scrapeCmdFiles(t, "https://"+canaryHost+"/"+canaryPath+"/metrics?token="+canaryQuery, func(target map[string]any) {
		target["secret"] = canaryRef
		target["tls"] = map[string]any{"server_name": canarySNI}
		src := target["source"].(map[string]any)
		res := src["resource"].(map[string]any)
		res["instance"] = canaryInstance
	})
	if err := os.WriteFile(filepath.Join(secrets, canaryRef), []byte(canaryRefValue), 0o600); err != nil {
		t.Fatal(err)
	}
	// A real source for the target to admit as: with its credential in the
	// secrets directory the grant resolves and the host really fetches.
	var alpha model.Scalar
	if err := alpha.UnmarshalJSON([]byte(`"alpha"`)); err != nil {
		t.Fatal(err)
	}
	line := model.TemplateField{Name: "line", Type: "string", MaxBytes: 64, Sensitivity: "metadata", Values: []model.Scalar{alpha}}
	issued, err := app.Auth.OnboardSource(ctx, owner, auth.SourceOnboarding{
		CommandID: model.NewID(), Org: org, Project: model.ID{1}, Source: model.ID{2}, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Reason: "scrape status canary",
		Policy: model.SourcePolicy{
			Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric},
			Templates:     []model.LogTemplate{{ID: "scrape.line", Revision: 1, Line: "{line}", Severity: "info", Fields: []model.TemplateField{line}}},
			Resources:     model.ResourceRegistry{Services: []model.ID{{4}}, Environments: []model.ID{{5}}, Builds: []model.ID{{6}}, Instances: []string{canaryInstance}},
			Labels:        map[string][]string{},
			RetentionDays: map[model.Kind]uint32{model.Metric: 7}, MaxBytes: 64 << 20, MaxSeries: 1000,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secrets, "source-token"), []byte(issued.Credential), 0o600); err != nil {
		t.Fatal(err)
	}
	settings, err := parseScrapeFlags(t, "--scrape-config", config, "--scrape-secrets-dir", secrets).settings()
	if err != nil {
		t.Fatal(err)
	}
	host, err := settings.start(ctx, app)
	if err != nil || host == nil {
		t.Fatalf("%v %v", host, err)
	}
	defer host.Close()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if st := host.Status(); len(st) == 1 && st[0].Cycles >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the host ran no cycle")
		}
		time.Sleep(20 * time.Millisecond)
	}

	srv := httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, scrapeStatusRoutes(app, host)).Handler)
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/admin/scrape/targets?org="+org.String(), nil)
	req.Header.Set("Cookie", "__Host-soundpost="+login.Token)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	body := string(raw)
	t.Logf("status route answered: %s", body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"alias":"cmd-target"`) {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	var view struct {
		Targets []map[string]any `json:"targets"`
	}
	if err := json.Unmarshal(raw, &view); err != nil || len(view.Targets) != 1 || view.Targets[0]["cycles"].(float64) < 1 || view.Targets[0]["health"] == nil || view.Targets[0]["health"] == "" {
		t.Fatalf("the route did not report a fetch of the unreachable target (the host must have run a real fetch for this test to mean anything): %s", body)
	}
	banned := map[string]string{
		"host name": canaryHost, "path": canaryPath, "query token": canaryQuery, "secret reference": canaryRef, "secret value": canaryRefValue,
		"target credential": scrapeCmdCanary, "source credential": string(issued.Credential), "resource instance": canaryInstance, "tls server name": canarySNI,
		"project id": model.ID{1}.String(), "source id": model.ID{2}.String(), "producer id": model.ID{3}.String(), "service id": model.ID{4}.String(),
		"environment id": model.ID{5}.String(), "build id": model.ID{6}.String(), "org id": org.String(),
		"config path": config, "secrets path": secrets, "credential secret ref": "source-token", "session": login.Token,
		"url scheme": "https://", "authorization": "Bearer",
	}
	for what, secret := range banned {
		for _, form := range scrapeCanaryForms(secret) {
			if strings.Contains(body, form) {
				t.Errorf("the status route carries the %s (%q): %s", what, form, body)
			}
		}
	}
}
