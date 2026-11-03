// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"testing"
	"time"
)

func TestBrowserSourceKeyCannotReadOrElevate(t *testing.T) {
	app, e := appcore.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer app.Close()
	ctx := context.Background()
	bootstrap, _ := app.Control.BootstrapToken()
	session, e := app.Auth.Bootstrap(ctx, bootstrap, "browser@example.test", "browser source password 2026")
	if e != nil {
		t.Fatal(e)
	}
	actor, e := app.Auth.Authenticate(ctx, session.Token)
	if e != nil {
		t.Fatal(e)
	}
	org, project, source := model.NewID(), model.NewID(), model.NewID()
	command := func(kind string, p auth.AdminPayload) {
		t.Helper()
		var revision model.Revision
		app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil })
		p.Reason = "browser regression"
		raw, _ := json.Marshal(p)
		if _, e = app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); e != nil {
			t.Fatal(e)
		}
	}
	command("create_org", auth.AdminPayload{Name: "browser"})
	command("create_project", auth.AdminPayload{ID: project, Name: "browser"})
	serviceID, environmentID, buildID := model.NewID(), model.NewID(), model.NewID()
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{serviceID}, Environments: []model.ID{environmentID}, Builds: []model.ID{buildID}, Instances: []string{"test"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 30}, MaxBytes: 1 << 20, MaxSeries: 100}
	issued, e := app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Browser: true, Origins: []string{"https://browser.example.test"}, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "browser regression"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = app.Auth.Authenticate(ctx, issued.Credential); e == nil {
		t.Fatal("source became session/server credential")
	}
	server := httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, app.Register).Handler)
	defer server.Close()
	client := server.Client()
	value := model.FloatBits(0x7ff0000000000002)
	batch := model.Batch{Version: 1, Project: project, Source: source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: 9007199254740993, Resource: model.Resource{Service: serviceID, Environment: environmentID, Build: buildID, Instance: "test", Labels: model.Labels{}}, Payload: model.Payload{Metric: &model.MetricPoint{Name: "request_total", Labels: model.Labels{}, SampleKind: "stale", Value: &value, Unit: "1", Type: "counter"}}}}}
	batch.RouteSlot, _ = model.OwnerSlot(org, project, source, batch.Producer, batch.Records[0])
	raw, _ := json.Marshal(batch)
	request := func(origin, cookie string, want int) {
		t.Helper()
		r, _ := http.NewRequest("POST", server.URL+"/ingest/v1/batches", bytes.NewReader(raw))
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Soundpost-Source", issued.Credential)
		if cookie != "" {
			r.Header.Set("Cookie", cookie)
		}
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("browser status %d want %d", response.StatusCode, want)
		}
		if response.Header.Get("Set-Cookie") != "" || response.Header.Get("Access-Control-Allow-Credentials") != "" {
			t.Fatal("ingestion cookie behavior")
		}
		if want == 200 && (response.Header.Get("Access-Control-Allow-Origin") != origin || response.Header.Get("Access-Control-Expose-Headers") == "") {
			t.Fatal("CORS exposure missing")
		}
		if (origin != "https://browser.example.test" || cookie != "") && response.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("foreign origin reflected")
		}
	}
	request("https://browser.example.test", "", 200)
	request("https://foreign.example.test", "", 403)
	request("https://browser.example.test", "__Host-soundpost="+session.Token, 403)
	for _, endpoint := range []string{"/api/v1/control/authorize", "/api/v1/elevation"} {
		r, _ := http.NewRequest("POST", server.URL+endpoint, bytes.NewBufferString(`{}`))
		r.Header.Set("Authorization", "Bearer "+issued.Credential)
		r.Header.Set("Origin", server.URL)
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		response.Body.Close()
		if response.StatusCode == 200 {
			t.Fatal("browser source read/elevation authority")
		}
	}
	batch.Project = model.NewID()
	raw, _ = json.Marshal(batch)
	request("https://browser.example.test", "", 403)
}
