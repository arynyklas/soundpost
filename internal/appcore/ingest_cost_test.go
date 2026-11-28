// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

// TestIngestRequestCostDoesNotGrowWithAdmittedHistory is the red test of the live collapse of the
// single-host overload gate (07.06#11): at 2,000 records/s only 235 of 79,179 batches were ACKed. The
// CPU profile of the live server (30 s, 4 CPUs) put 81 % of all CPU in the source resolution of the
// ingest route: retention.AdmissionResolver read the retention versions with Store.View, which hands
// the reader the state with the admission ledger assembled, so every request decoded every reservation
// and every per-series quota record admitted before it. What one request costs has to be a function of
// the request, not of the history: the same number of requests, measured after a long history of
// admitted batches and series, must cost about what they cost on a fresh installation. The bounds are
// loose (3x time, 2x allocation); the defect is a factor of ten and more at this size.
func TestIngestRequestCostDoesNotGrowWithAdmittedHistory(t *testing.T) {
	app, e := appcore.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer app.Close()
	ctx := context.Background()
	bootstrap, _ := app.Control.BootstrapToken()
	session, e := app.Auth.Bootstrap(ctx, bootstrap, "cost@example.test", "ingest cost source password 2026")
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
		p.Reason = "ingest cost"
		raw, _ := json.Marshal(p)
		if _, e = app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); e != nil {
			t.Fatal(e)
		}
	}
	command("create_org", auth.AdminPayload{Name: "cost"})
	command("create_project", auth.AdminPayload{ID: project, Name: "cost"})
	serviceID, environmentID, buildID := model.NewID(), model.NewID(), model.NewID()
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{serviceID}, Environments: []model.ID{environmentID}, Builds: []model.ID{buildID}, Instances: []string{"test"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 30}, MaxBytes: 1 << 34, MaxSeries: 1 << 20}
	issued, e := app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "ingest cost"})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, app.Register).Handler)
	defer server.Close()
	client := server.Client()
	producer := model.NewID()
	value := model.FloatBits(0x3ff0000000000000)
	// send is one ingest request of a batch holding one point of a series that was not admitted before: every
	// request adds a series to the three quota tiers and a reservation to the books, the way a real estate grows.
	send := func(name string) {
		t.Helper()
		record := model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: 9007199254740993, Resource: model.Resource{Service: serviceID, Environment: environmentID, Build: buildID, Instance: "test", Labels: model.Labels{}},
			Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &value, Unit: "1", Type: "counter"}}}
		batch := model.Batch{Version: 1, Project: project, Source: source, Producer: producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{record}}
		batch.RouteSlot, _ = model.OwnerSlot(org, project, source, producer, record)
		raw, _ := json.Marshal(batch)
		r, _ := http.NewRequest("POST", server.URL+"/ingest/v1/batches", bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+issued.Credential)
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatalf("ingest %s: status %d", name, response.StatusCode)
		}
	}
	cost := func(from, n int) (time.Duration, uint64) {
		t.Helper()
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		for i := range n {
			send(fmt.Sprintf("history_series_%06d", from+i))
		}
		elapsed := time.Since(start)
		runtime.ReadMemStats(&after)
		return elapsed / time.Duration(n), (after.TotalAlloc - before.TotalAlloc) / uint64(n)
	}
	const probe, history = 20, 1500
	// The first requests pay one-time costs (caches, connection setup, page allocation): not the baseline.
	cost(0, probe)
	earlyTime, earlyAlloc := cost(probe, probe)
	cost(2*probe, history)
	lateTime, lateAlloc := cost(2*probe+history, probe)
	t.Logf("after %d requests: %v and %d B per request; after %d: %v and %d B", 2*probe, earlyTime, earlyAlloc, 2*probe+history, lateTime, lateAlloc)
	if lateAlloc > 2*earlyAlloc+64<<10 {
		t.Errorf("allocation per ingest request grew from %d B to %d B with the history of %d requests", earlyAlloc, lateAlloc, history)
	}
	if lateTime > 3*earlyTime+2*time.Millisecond {
		t.Errorf("time per ingest request grew from %v to %v with the history of %d requests", earlyTime, lateTime, history)
	}
}
