// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/httpapi"
	"testing"
)

func TestSmokeOrganizationsReadAfterRealHTTPSBootstrap(t *testing.T) {
	store, e := control.Open(t.TempDir())
	if e != nil {
		t.Fatal("control", classifySmokeError(e))
	}
	defer store.Close()
	service, e := auth.NewService(auth.AuthDependencies{Control: store})
	if e != nil {
		t.Fatal("auth", classifySmokeError(e))
	}
	if e = store.EnableSingle(context.Background(), filepath.Join(t.TempDir(), "raft-control")); e != nil {
		t.Fatal("real control activation", classifySmokeError(e))
	}
	server := httptest.NewTLSServer(httpapi.NewServer("", service, nil).Handler)
	defer server.Close()
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	child := &smokeChild{client: client, address: childAddress{URL: server.URL}}
	token, e := store.BootstrapToken()
	if e != nil {
		t.Fatal("bootstrap token", classifySmokeError(e))
	}
	status, raw, e := child.call("/api/v1/bootstrap", map[string]string{"Token": token, "Email": "selector@example.test", "Password": "instance selector password 2026"}, "", "")
	if e != nil || status != 200 {
		t.Fatal("bootstrap", status, classifySmokeError(e))
	}
	var session auth.Session
	if e = json.Unmarshal(raw, &session); e != nil {
		t.Fatal("session", classifySmokeError(e))
	}
	status, raw, e = child.organizationsRead(session.CSRF)
	if e != nil || status != 200 {
		t.Fatal("instance selector", status, classifySmokeError(e))
	}
	var view auth.AdminView
	if e = json.Unmarshal(raw, &view); e != nil || view.Revision == 0 {
		t.Fatal("instance revision unavailable")
	}
}
