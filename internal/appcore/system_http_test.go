// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
)

// routePatterns lists every route the server source registers ("METHOD /path").
func routePatterns(t *testing.T) []string {
	t.Helper()
	re := regexp.MustCompile(`(?:HandleFunc|Handle)\("([A-Z]+) (/[^"]*)"`)
	seen := map[string]bool{}
	var out []string
	for _, dir := range []string{"../httpapi", "."} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
				path := regexp.MustCompile(`\{[^}]*\}`).ReplaceAllString(m[2], "x")
				if key := m[1] + " " + path; !seen[key] {
					seen[key] = true
					out = append(out, key)
				}
			}
		}
	}
	return out
}

// No HTTP route yields the runner's scope: every route the product registers, hit with
// every shape of credential that could name the runner (its actor name, its principal
// ID, a session cookie and a bearer token spelled that way), refuses or ignores it and
// commits nothing to control state, so nothing is ever audited as system:runner.
func TestNoHTTPRouteAcceptsTheSystemPrincipal(t *testing.T) {
	n := newWorkerNode(t)
	routes := routePatterns(t)
	if len(routes) < 40 {
		t.Fatalf("only %d routes found: the scan broke", len(routes))
	}
	server := httptest.NewTLSServer(httpapi.NewServer("", n.app.Auth, nil, n.app.Register).Handler)
	defer server.Close()
	client := server.Client()
	client.Transport.(*http.Transport).TLSClientConfig.MinVersion = tls.VersionTLS13

	principal := auth.SystemPrincipal(n.org)
	secrets := []string{auth.SystemRunner, principal.String(), "Bearer " + auth.SystemRunner, strings.Repeat("00", 16)}
	var revision model.Revision
	audits := n.auditCount()
	if err := n.app.Control.View(n.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	requests := 0
	for _, route := range routes {
		method, path, _ := strings.Cut(route, " ")
		for _, secret := range secrets {
			for _, carrier := range []string{"bearer", "cookie"} {
				req, err := http.NewRequestWithContext(n.ctx, method, server.URL+path, strings.NewReader(`{}`))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", server.URL)
				req.Header.Set("X-CSRF-Token", secret)
				if carrier == "bearer" {
					req.Header.Set("Authorization", "Bearer "+secret)
				} else {
					req.AddCookie(&http.Cookie{Name: "__Host-soundpost", Value: secret})
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("%s: %v", route, err)
				}
				resp.Body.Close()
				requests++
				if resp.StatusCode < 400 || resp.StatusCode >= 500 {
					t.Fatalf("%s with %s credential %q: status %d, want a 4xx refusal", route, carrier, secret, resp.StatusCode)
				}
			}
		}
	}
	var after model.Revision
	if err := n.app.Control.View(n.ctx, func(st model.ControlState) error { after = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	if after != revision || n.auditCount() != audits {
		t.Fatalf("control state moved during %d refused requests: revision %d -> %d, audits %d -> %d", requests, revision, after, audits, n.auditCount())
	}
	// And the scope itself exists only inside the process.
	if _, err := n.app.Auth.AuthorizeSystem(context.Background(), n.org, nil, auth.OrgAdmin); err != nil {
		t.Fatal(err)
	}
	var _ = appcore.StageAuth
}
