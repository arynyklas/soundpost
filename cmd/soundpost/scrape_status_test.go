// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"soundpost/internal/appcore"
	"soundpost/internal/httpapi"
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
