// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
)

func TestHTTPAuditPersistsRequestCorrelationAndOutcome(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := control.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	activateHTTPControl(t, store, dir)
	server := httptest.NewTLSServer(httpapi.NewServer("", service, nil).Handler)
	defer server.Close()
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	post := func(path string, payload any, csrf string) (int, []byte, model.ID) {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest("POST", server.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", server.URL)
		req.Header.Set("X-CSRF-Token", csrf)
		supplied := model.NewID()
		req.Header.Set("X-Request-ID", supplied.String())
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		requestID, err := model.ParseID(response.Header.Get("X-Request-ID"))
		if err != nil {
			t.Fatal(err)
		}
		if requestID == supplied {
			t.Fatal("client controlled trusted correlation context")
		}
		return response.StatusCode, raw, requestID
	}
	token, _ := store.BootstrapToken()
	status, raw, _ := post("/api/v1/bootstrap", map[string]string{"Token": token, "Email": "owner@example.test", "Password": "correct horse battery staple 2026"}, "")
	if status != 200 {
		t.Fatalf("bootstrap status %d", status)
	}
	var session auth.Session
	if err := json.Unmarshal(raw, &session); err != nil {
		t.Fatal(err)
	}
	var revision model.Revision
	if err := store.View(ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	org, commandID := model.NewID(), model.NewID()
	payload, _ := json.Marshal(auth.AdminPayload{Name: "audited organization", Reason: "explicit safe reason"})
	status, _, requestID := post("/api/v1/admin/commands", auth.AdminCommandRequest{CommandID: commandID, ExpectedRevision: revision, OrgID: org, Kind: "create_org", Payload: payload}, session.CSRF)
	if status != 200 {
		t.Fatalf("command status %d", status)
	}
	check := func(st control.State) error {
		t.Helper()
		if len(st.Audits) != 1 {
			t.Fatalf("unexpected audit count %d", len(st.Audits))
		}
		audit := st.Audits[0]
		if audit.RequestID != requestID || audit.RequestID == audit.ID || audit.RequestID == commandID || audit.Outcome != model.AuditAllowed {
			t.Fatal("durable audit did not retain actual HTTP request observation")
		}
		return nil
	}
	if err := store.View(ctx, check); err != nil {
		t.Fatal(err)
	}
	status, raw, failureID := post("/api/v1/admin/read", auth.AdminReadRequest{OrgID: org, Kind: "organization"}, "wrong")
	if status != 403 {
		t.Fatalf("denial status %d", status)
	}
	var fault model.Fault
	if err := json.Unmarshal(raw, &fault); err != nil {
		t.Fatal(err)
	}
	if fault.RequestID != failureID {
		t.Fatal("safe failure response lost request correlation")
	}
	server.Close()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := control.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	activateHTTPControl(t, reopened, dir)
	if err := reopened.View(ctx, check); err != nil {
		t.Fatal(err)
	}
}
