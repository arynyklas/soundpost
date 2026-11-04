// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
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

func TestFreshSourcePolicySignsIndependentCapabilitiesAndRestrictions(t *testing.T) {
	ctx := context.Background()
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	bootstrap, err := app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := app.Auth.Bootstrap(ctx, bootstrap, "policy-signing@example.test", "policy signing password 2026")
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
		p.Reason = "signed policy capability regression"
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
			t.Fatal(err)
		}
	}
	command("create_org", auth.AdminPayload{Name: "policy signing"})
	command("create_project", auth.AdminPayload{ID: project, Name: "policy signing"})
	service, environment, build := model.NewID(), model.NewID(), model.NewID()
	expires := model.UnixNano(time.Now().Add(20 * time.Minute).UnixNano())
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.SpanKind, model.ErrorKind, model.Loss, model.JobAttempt}, Resources: model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{"opaque-instance"}}, Operations: []string{"operation"}, RetentionDays: map[model.Kind]uint32{model.SpanKind: 30, model.ErrorKind: 30, model.Loss: 30, model.JobAttempt: 30}, MaxBytes: 8 << 20, MaxSeries: 100, Expires: expires}
	issued, err := app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "signed policy capability regression"})
	if err != nil {
		t.Fatal(err)
	}
	verify := func(response auth.SourceOnboarded, revision model.Revision, want map[string]bool) {
		t.Helper()
		envelope := response.Policy
		if envelope.Version != 1 || envelope.Algorithm != "Ed25519" {
			t.Fatal("wrong policy envelope")
		}
		public, err := base64.RawURLEncoding.DecodeString(response.TrustedKeys[envelope.KeyID])
		if err != nil || len(public) != ed25519.PublicKeySize {
			t.Fatal("invalid installation trust")
		}
		payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
		if err != nil || !ed25519.Verify(public, payload, signature) {
			t.Fatal("policy signature invalid")
		}
		var wire map[string]json.RawMessage
		if err = json.Unmarshal(payload, &wire); err != nil {
			t.Fatal(err)
		}
		canonical, err := model.CanonicalJSON(wire)
		if err != nil || !bytes.Equal(canonical, payload) {
			t.Fatal("policy not canonical")
		}
		var binding struct {
			Org      model.ID       `json:"org"`
			Project  model.ID       `json:"project"`
			Source   model.ID       `json:"source"`
			Revision model.Revision `json:"revision"`
			Expires  model.UnixNano `json:"expires_ns"`
		}
		if err = json.Unmarshal(payload, &binding); err != nil || binding.Org != org || binding.Project != project || binding.Source != source || binding.Revision != revision || binding.Expires != expires {
			t.Fatal("policy binding or minimum expiry changed")
		}
		for name, expected := range want {
			raw, ok := wire[name]
			var actual bool
			if !ok || json.Unmarshal(raw, &actual) != nil || actual != expected {
				t.Fatalf("signed capability %s is not %v", name, expected)
			}
		}
	}
	enabled := map[string]bool{"errors": true, "logs": false, "traces": true, "jobs": true, "loss": true, "replay": false, "bodies": false}
	verify(issued, 1, enabled)
	credential, err := app.Auth.AuthenticateSource(ctx, issued.Credential, "", false)
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := app.Auth.SourceConfiguration(ctx, credential)
	if err != nil {
		t.Fatal(err)
	}
	verify(refresh, 1, enabled)
	// These permissions admit genuine source-key writes, not a signing-only flag.
	server := httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, app.Register).Handler)
	defer server.Close()
	client := server.Client()
	resource := model.Resource{Service: service, Environment: environment, Build: build, Instance: "opaque-instance", Labels: model.Labels{}}
	producer := model.NewID()
	clock := model.TraceClock{Wall: 1, Mono: 1, Domain: model.ClockDomain{Host: model.NewID(), Boot: model.NewID(), Runtime: model.NewID()}}
	end := clock
	end.Mono = 2
	var span model.SpanID
	span[0] = 1
	records := []model.Record{
		{ID: model.NewID(), Kind: model.SpanKind, ObservedAt: 1, Resource: resource, Payload: model.Payload{Span: &model.Span{Trace: model.NewID(), ID: span, Kind: "internal", Operation: "operation", Start: clock, End: &end, Status: "ok", SampleProbability: model.FloatBits(0x3ff0000000000000), SampleDecision: "keep"}}},
		{ID: model.NewID(), Kind: model.ErrorKind, ObservedAt: 1, Resource: resource, Payload: model.Payload{Error: &model.ErrorOccurrence{Occurrence: model.NewID(), Class: "TypeError", Mechanism: "manual", Build: build, Handled: true, Frames: []model.Frame{}}}},
		{ID: model.NewID(), Kind: model.JobAttempt, ObservedAt: 1, Resource: resource, Payload: model.Payload{Job: &model.JobAttemptEvent{Job: model.NewID(), Run: model.NewID(), Attempt: model.NewID(), Schedule: "schedule", Ordinal: 1, Epoch: model.NewID(), Sequence: 1, State: "started", Observed: 1}}},
		{ID: model.NewID(), Kind: model.Loss, ObservedAt: 1, Resource: resource, Payload: model.Payload{Loss: &model.LossReport{Source: source, Producer: producer, Epoch: model.NewID(), Start: 1, End: 2, Signal: model.SpanKind, Reason: "queue_full", Count: 1}}},
	}
	for _, record := range records {
		batch := model.Batch{Version: 1, Project: project, Source: source, Producer: producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{record}}
		batch.RouteSlot, err = model.OwnerSlot(org, project, source, producer, record)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(batch)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest("POST", server.URL+"/ingest/v1/batches", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+issued.Credential)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatalf("source capability %s did not admit genuine record: %d", record.Kind, response.StatusCode)
		}
	}
	reader := model.NewID()
	command("create_user", auth.AdminPayload{ID: reader, Email: "policy-reader@example.test", Password: "policy reader password 2026"})
	command("membership", auth.AdminPayload{UserID: reader, Enabled: true})
	command("grant", auth.AdminPayload{UserID: reader, ProjectID: project, Enabled: true, Permissions: []string{string(auth.Read)}})
	readerSession, err := app.Auth.Login(ctx, "policy-reader@example.test", "policy reader password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	readerCredential, err := app.Auth.Authenticate(ctx, readerSession.Token)
	if err != nil {
		t.Fatal(err)
	}
	readScope, err := app.Auth.Authorize(ctx, readerCredential, org, []model.ID{project}, auth.Read)
	if err != nil || !readScope.AllowsProject(project) {
		t.Fatal("separate reader grant failed")
	}
	if _, err = app.Auth.Authenticate(ctx, issued.Credential); err == nil {
		t.Fatal("source capture permission became read/session authority")
	}
	next := policy
	next.Revision = 2
	next.Kinds = []model.Kind{model.ErrorKind, model.Loss, model.JobAttempt}
	if _, err = app.Auth.ChangeSourcePolicy(ctx, actor, auth.SourcePolicyChange{CommandID: model.NewID(), Source: source, ExpectedRevision: 1, Policy: next, Reason: "remove traces"}); err != nil {
		t.Fatal(err)
	}
	denied := map[string]bool{"errors": false, "logs": false, "traces": false, "jobs": false, "loss": false, "replay": false, "bodies": false}
	closing, err := app.Auth.SourceConfiguration(ctx, credential)
	if err != nil {
		t.Fatal(err)
	}
	verify(closing, 2, denied)
	if err = app.Auth.DrainSourceFences(ctx); err != nil {
		t.Fatal(err)
	}
	restricted, err := app.Auth.SourceConfiguration(ctx, credential)
	if err != nil {
		t.Fatal(err)
	}
	verify(restricted, 2, map[string]bool{"errors": true, "logs": false, "traces": false, "jobs": true, "loss": true, "replay": false, "bodies": false})
	disabled := next
	disabled.Revision = 3
	disabled.Enabled = false
	if _, err = app.Auth.ChangeSourcePolicy(ctx, actor, auth.SourcePolicyChange{CommandID: model.NewID(), Source: source, ExpectedRevision: 2, Policy: disabled, Reason: "disable capture"}); err != nil {
		t.Fatal(err)
	}
	if err = app.Auth.DrainSourceFences(ctx); err != nil {
		t.Fatal(err)
	}
	configuration, err := app.Auth.SourceConfiguration(ctx, credential)
	if err != nil {
		t.Fatal(err)
	}
	verify(configuration, 3, denied)
	if err = app.Auth.RevokeSource(ctx, actor, source, "deny signed source policy"); err != nil {
		t.Fatal(err)
	}
	if _, err = app.Auth.SourceConfiguration(ctx, credential); !hasForbidden(err) {
		t.Fatal("revoked source received signed capture authority")
	}
}
