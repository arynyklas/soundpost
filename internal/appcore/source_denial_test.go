// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSourceAuthorityDenialsAreForbiddenAcrossIngestAndReceipts(t *testing.T) {
	ctx := context.Background()
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	token, err := app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := app.Auth.Bootstrap(ctx, token, "source-denial@example.test", "source denial password 2026")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	org, project, source := model.NewID(), model.NewID(), model.NewID()
	command := func(kind string, p auth.AdminPayload) {
		t.Helper()
		var revision model.Revision
		if err := app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
			t.Fatal(err)
		}
		p.Reason = "source denial regression"
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
			t.Fatal(err)
		}
	}
	command("create_org", auth.AdminPayload{Name: "source denial"})
	command("create_project", auth.AdminPayload{ID: project, Name: "source denial"})
	service, environment, build := model.NewID(), model.NewID(), model.NewID()
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{"opaque-instance"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 30}, MaxBytes: 1 << 20, MaxSeries: 100}
	issued, err := app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "source denial regression"})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := app.Auth.AuthenticateSource(ctx, issued.Credential, "", false)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, app.Register).Handler)
	defer server.Close()
	client := server.Client()
	value := model.FloatBits(0x3ff0000000000000)
	batch := model.Batch{Version: 1, Project: project, Source: source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: 1, Resource: model.Resource{Service: service, Environment: environment, Build: build, Instance: "opaque-instance", Labels: model.Labels{}}, Payload: model.Payload{Metric: &model.MetricPoint{Name: "source_denial_total", Labels: model.Labels{}, SampleKind: "float", Value: &value, Unit: "1", Type: "counter"}}}}}
	batch.RouteSlot, err = model.OwnerSlot(org, project, source, batch.Producer, batch.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	call := func(path, authorization string, v any, want int) []byte {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest("POST", server.URL+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("source status %d, want %d", response.StatusCode, want)
		}
		var wire json.RawMessage
		if err = json.NewDecoder(response.Body).Decode(&wire); err != nil {
			t.Fatal(err)
		}
		return wire
	}
	var receipt model.Receipt
	if err = json.Unmarshal(call("/ingest/v1/batches", "Bearer "+issued.Credential, batch, 200), &receipt); err != nil {
		t.Fatal(err)
	}
	query := model.ReceiptRequest{Source: source, Producer: batch.Producer, RouteSlot: batch.RouteSlot, BatchID: batch.ID, OriginalHash: receipt.Hash}
	call("/ingest/v1/receipts", "Bearer "+issued.Credential, query, 200)
	for _, authorization := range []string{"", "Bearer invalid-source-key", "invalid-scheme"} {
		call("/ingest/v1/receipts", authorization, query, 403)
		call("/ingest/v1/batches", authorization, batch, 403)
	}
	if _, err = app.Auth.AuthenticateSource(ctx, "invalid-source-key", "", false); !hasForbidden(err) {
		t.Fatal("invalid source authority did not deny forbidden")
	}
	expiredAt := model.UnixNano(time.Now().Add(-time.Minute).UnixNano())
	if err = app.Control.Update(ctx, func(st *model.ControlState) error {
		src := st.Sources[source.String()]
		src.Expires = expiredAt
		st.Sources[source.String()] = src
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = app.Auth.SourceScope(ctx, credential, true); !hasForbidden(err) {
		t.Fatal("saved expired source credential did not deny forbidden")
	}
	call("/ingest/v1/receipts", "Bearer "+issued.Credential, query, 403)
	renewedUntil := model.UnixNano(time.Now().Add(time.Hour).UnixNano())
	if err = app.Control.Update(ctx, func(st *model.ControlState) error {
		src := st.Sources[source.String()]
		src.Expires = renewedUntil
		st.Sources[source.String()] = src
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = app.Auth.RevokeSource(ctx, actor, source, "source denial regression"); err != nil {
		t.Fatal(err)
	}
	if _, err = app.Auth.SourceScope(ctx, credential, true); !hasForbidden(err) {
		t.Fatal("saved revoked source credential did not deny forbidden")
	}
	call("/ingest/v1/receipts", "Bearer "+issued.Credential, query, 403)
	call("/ingest/v1/batches", "Bearer "+issued.Credential, batch, 403)
	// General browser/session authentication is a different authority and retains 401.
	call("/api/v1/control/authorize", "Bearer "+issued.Credential, map[string]any{}, 401)
	if err = app.Control.View(ctx, func(st model.ControlState) error {
		if len(st.Reservations) != 1 {
			t.Fatal("source denial reserved new admission")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func hasForbidden(err error) bool {
	var fault *model.Fault
	return errors.As(err, &fault) && fault.Code == model.Forbidden
}
