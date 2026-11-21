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
	"testing/fstest"
	"time"
)

// A restored installation says so in its session, lists exactly what is still inactive,
// and reinstates one named item per audited reconciliation over HTTP; an ordinary
// session body has no restore field, and a non-administrator can neither list nor reconcile.
func TestRestoreStateIsExposedAndReconciledOverHTTP(t *testing.T) {
	ctx := context.Background()
	store, err := control.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	activateHTTPControl(t, store, t.TempDir())
	boot, err := store.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	ownerSession, err := service.Bootstrap(ctx, boot, "restore-owner@example.test", "restore owner password 2026")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := service.Authenticate(ctx, ownerSession.Token)
	if err != nil {
		t.Fatal(err)
	}
	org, reader := model.NewID(), model.NewID()
	command := func(kind string, payload auth.AdminPayload) {
		t.Helper()
		var revision model.Revision
		_ = store.View(ctx, func(st control.State) error { revision = st.Revision; return nil })
		payload.Reason = "restore http fixture"
		raw, _ := json.Marshal(payload)
		if _, e := service.AdminCommand(ctx, owner, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); e != nil {
			t.Fatal(kind, e)
		}
	}
	command("create_org", auth.AdminPayload{Name: "restored http org"})
	command("create_user", auth.AdminPayload{ID: reader, Email: "restored-reader@example.test", Password: "restored reader password"})
	command("membership", auth.AdminPayload{UserID: reader, Enabled: true})

	registrar, err := httpapi.UIRoutes(fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(`<div id="root"></div><script type="module" src="/assets/main.js"></script>`)}, "assets/main.js": &fstest.MapFile{Data: []byte(`document.title='Soundpost'`)}})
	if err != nil {
		t.Fatal(err)
	}
	// Before any restore: the session body carries no restore field.
	server := httptest.NewTLSServer(httpapi.NewServer("", service, nil, registrar).Handler)
	defer server.Close()
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	call := func(method, route string, body any, csrf string) (int, []byte) {
		t.Helper()
		data, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, server.URL+route, bytes.NewReader(data))
		req.Header.Set("Origin", server.URL)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, raw
	}
	status, raw := call("POST", "/api/v1/login", map[string]string{"Email": "restore-owner@example.test", "Password": "restore owner password 2026"}, "")
	if status != 200 {
		t.Fatalf("login %d %s", status, raw)
	}
	status, raw = call("GET", "/api/v1/session", nil, "")
	var plain map[string]any
	if err = json.Unmarshal(raw, &plain); status != 200 || err != nil {
		t.Fatalf("session %d %s", status, raw)
	}
	if _, has := plain["restore"]; has {
		t.Fatalf("a never-restored installation's session carries a restore field: %s", raw)
	}

	// Restore: quarantine through the real replicated update, then a new process opens the control state.
	token, hash := auth.NewRecoveryBootstrap()
	sealed, err := auth.SealedBearerKey(store.Seal)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Update(ctx, func(st *model.ControlState) error {
		_, e := auth.QuarantineRestoredState(st, auth.RestoreInput{Generation: model.NewID(), Backup: model.NewID(), BootstrapHash: hash, SealedBearerKey: sealed, At: time.Now()})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	restored, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	restoredServer := httptest.NewTLSServer(httpapi.NewServer("", restored, nil, registrar).Handler)
	defer restoredServer.Close()
	client = restoredServer.Client()
	client.Jar, _ = cookiejar.New(nil)
	server = restoredServer

	status, raw = call("POST", "/api/v1/bootstrap", map[string]string{"Token": token, "Email": "recovery-http@example.test", "Password": "recovery http password 2026"}, "")
	var recovery auth.Session
	if err = json.Unmarshal(raw, &recovery); status != 200 || err != nil || recovery.CSRF == "" {
		t.Fatalf("recovery bootstrap %d %s", status, raw)
	}
	status, raw = call("GET", "/api/v1/session", nil, "")
	var restoredSession struct {
		CSRF    string `json:"csrf"`
		Restore *struct {
			Pending int `json:"pending"`
		} `json:"restore"`
	}
	if err = json.Unmarshal(raw, &restoredSession); status != 200 || err != nil || restoredSession.Restore == nil || restoredSession.Restore.Pending == 0 || restoredSession.CSRF == "" {
		t.Fatalf("restored session does not say it is bootstrap-only with pending items: %d %s", status, raw)
	}
	pending := restoredSession.Restore.Pending

	// A request without the CSRF token is refused; the list is the instance administrator's.
	if status, raw = call("POST", "/api/v1/restore/items", struct{}{}, ""); status != 403 {
		t.Fatalf("restore items without CSRF: %d %s", status, raw)
	}
	status, raw = call("POST", "/api/v1/restore/items", struct{}{}, recovery.CSRF)
	var view auth.RestoreView
	if err = json.Unmarshal(raw, &view); status != 200 || err != nil || view.Pending != pending || len(view.Items) != pending {
		t.Fatalf("items %d %s (pending %d)", status, raw, pending)
	}
	var account auth.RestoreItem
	for _, item := range view.Items {
		if item.Kind == auth.ReconcileAccount && item.User == reader.String() {
			account = item
		}
	}
	if account.Label != "restored-reader@example.test" {
		t.Fatalf("the reader's account is not listed: %s", raw)
	}
	// Reconcile exactly that account: audited, and the list and the session count both shrink by one.
	status, raw = call("POST", "/api/v1/restore/reconcile", map[string]string{"Kind": string(account.Kind), "User": account.User, "Reason": "reauthorize the reader over http"}, recovery.CSRF)
	var done auth.Reconciled
	if err = json.Unmarshal(raw, &done); status != 200 || err != nil || done.Audit == (model.ID{}) {
		t.Fatalf("reconcile %d %s", status, raw)
	}
	var audited bool
	_ = store.View(ctx, func(st control.State) error {
		for _, a := range st.Audits {
			if a.ID == done.Audit && a.Action == "restore.reconcile.account" && a.Reason == "reauthorize the reader over http" {
				audited = true
			}
		}
		return nil
	})
	if !audited {
		t.Fatal("the reconciliation committed no audit record")
	}
	status, raw = call("GET", "/api/v1/session", nil, "")
	if err = json.Unmarshal(raw, &restoredSession); status != 200 || err != nil || restoredSession.Restore == nil || restoredSession.Restore.Pending != pending-1 {
		t.Fatalf("pending after one reconciliation: %d %s", status, raw)
	}
	// An item that is not (or no longer) quarantined, and an empty kind, are refused, not guessed.
	if status, raw = call("POST", "/api/v1/restore/reconcile", map[string]string{"Kind": string(account.Kind), "User": account.User, "Reason": "again"}, recovery.CSRF); status != 404 {
		t.Fatalf("a reconciled item was reconciled again: %d %s", status, raw)
	}
	if status, raw = call("POST", "/api/v1/restore/reconcile", map[string]string{"Reason": "no kind"}, recovery.CSRF); status != 400 {
		t.Fatalf("a reconciliation without a kind: %d %s", status, raw)
	}

	// The reinstated reader is an ordinary account: it can neither list nor reconcile.
	client.Jar, _ = cookiejar.New(nil)
	status, raw = call("POST", "/api/v1/login", map[string]string{"Email": "restored-reader@example.test", "Password": "restored reader password"}, "")
	var readerSession auth.Session
	if err = json.Unmarshal(raw, &readerSession); status != 200 || err != nil {
		t.Fatalf("reinstated reader login %d %s", status, raw)
	}
	for _, route := range []string{"/api/v1/restore/items", "/api/v1/restore/reconcile"} {
		body := any(struct{}{})
		if route == "/api/v1/restore/reconcile" {
			body = map[string]string{"Kind": "account", "User": reader.String(), "Reason": "self service"}
		}
		if status, raw = call("POST", route, body, readerSession.CSRF); status != 403 {
			t.Fatalf("%s by a non-administrator: %d %s", route, status, raw)
		}
	}
}
