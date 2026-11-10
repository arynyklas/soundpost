// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/httpapi"
	"strings"
	"testing"
	"testing/fstest"
)

// uiServer serves a production-shaped bundle (hashed Vite asset names, one unhashed script, the sandboxed replay
// frame) next to the real authenticated API surface on one TLS origin, exactly as `soundpost serve` composes them.
func uiServer(t *testing.T) *httptest.Server {
	t.Helper()
	store, err := control.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	activateHTTPControl(t, store, t.TempDir())
	file := func(data string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(data)} }
	bundle := fstest.MapFS{
		"index.html":                   file(`<!doctype html><html lang="en"><head><link rel="stylesheet" href="/assets/index-BcCLi0Nq.css"></head><body><div id="root"></div><script type="module" src="/assets/index-Dtvqgl4G.js"></script></body></html>`),
		"assets/index-Dtvqgl4G.js":     file(`document.title='Soundpost'`),
		"assets/index-BcCLi0Nq.css":    file(`body{margin:0}`),
		"assets/main-releases.js":      file(`/* eight letters, no digit: not provably a content hash */`),
		"assets/short-Ab1Cd.js":        file(`/* five characters after the dash: too short to be a build hash */`),
		"assets/replay-frame.html":     file(`<html><style>b{}</style><script>1</script></html>`),
		"assets/notes.txt":             file(`plain`),
		"assets/sub/chunk-AbCd1234.js": file(`/* nested */`),
	}
	register, err := httpapi.UIRoutes(bundle)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(httpapi.NewServer("", service, nil, register).Handler)
	t.Cleanup(server.Close)
	return server
}

func uiGet(t *testing.T, server *httptest.Server, path string) (*http.Response, string) {
	t.Helper()
	response, err := server.Client().Get(server.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response, string(body)
}

func TestUIHashedAssetsAreImmutableAndNothingElseIsCachedForeverOrAtAll(t *testing.T) {
	server := uiServer(t)
	const immutable = "public, max-age=31536000, immutable"
	for _, tc := range []struct{ path, kind string }{
		{"/assets/index-Dtvqgl4G.js", "text/javascript"},
		{"/assets/index-BcCLi0Nq.css", "text/css"},
		{"/assets/sub/chunk-AbCd1234.js", "text/javascript"},
	} {
		response, _ := uiGet(t, server, tc.path)
		if response.StatusCode != 200 || response.Header.Get("Cache-Control") != immutable {
			t.Fatalf("%s: status %d Cache-Control %q, want 200 %q", tc.path, response.StatusCode, response.Header.Get("Cache-Control"), immutable)
		}
		if got := response.Header.Get("Content-Type"); !strings.HasPrefix(got, tc.kind) {
			t.Fatalf("%s: Content-Type %q, want %s", tc.path, got, tc.kind)
		}
		if response.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: missing nosniff", tc.path)
		}
	}
	// The shell names the hashed files and must always be revalidated: caching it would pin an old bundle.
	for _, path := range []string{"/"} {
		response, _ := uiGet(t, server, path)
		if response.StatusCode != 200 && response.StatusCode != 301 {
			t.Fatalf("%s: status %d", path, response.StatusCode)
		}
		if cc := response.Header.Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("%s: Cache-Control %q, want no-store", path, cc)
		}
	}
	// A file whose name carries no provable content hash, a non-script type and the replay frame are never immutable.
	for _, path := range []string{"/assets/main-releases.js", "/assets/short-Ab1Cd.js", "/assets/notes.txt", "/assets/replay-frame.html"} {
		response, _ := uiGet(t, server, path)
		if cc := response.Header.Get("Cache-Control"); strings.Contains(cc, "immutable") || cc != "no-store" {
			t.Fatalf("%s: Cache-Control %q, want no-store", path, cc)
		}
	}
	// A hashed-looking name that does not exist is a 404 that must not be cached as immutable.
	response, _ := uiGet(t, server, "/assets/index-ZZZZ9999.js")
	if response.StatusCode != 404 || strings.Contains(response.Header.Get("Cache-Control"), "immutable") {
		t.Fatalf("missing hashed asset: status %d Cache-Control %q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
}

func TestUIShellCarriesTheSecurePolicyOnEveryResponseIncludingRefusals(t *testing.T) {
	server := uiServer(t)
	for _, path := range []string{"/", "/assets/index-Dtvqgl4G.js", "/assets/missing.js", "/assets/../index.html", "/nowhere"} {
		response, _ := uiGet(t, server, path)
		csp := response.Header.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'", "connect-src 'self'"} {
			if !strings.Contains(csp, want) {
				t.Fatalf("%s: CSP %q lacks %q", path, csp, want)
			}
		}
		if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") || strings.Contains(csp, "*") {
			t.Fatalf("%s: weak CSP %q", path, csp)
		}
		if response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("%s: missing nosniff/referrer headers", path)
		}
	}
	response, body := uiGet(t, server, "/")
	if got := response.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("shell Content-Type %q", got)
	}
	if !strings.Contains(body, `id="root"`) {
		t.Fatal("the compiled shell was not served")
	}
}

func TestUIDeepLinksNeverBypassAuthAndPathGuessesAreNotSilentlyRewritten(t *testing.T) {
	server := uiServer(t)
	// Native deep links live in the URL fragment, which no server ever sees: the shell served for a deep link is the same
	// public document as for "/", and it contains no organization, project or telemetry data.
	_, shell := uiGet(t, server, "/")
	for _, hash := range []string{"#org=" + strings.Repeat("a", 32) + "&view=incidents", "#view=replays&target=x"} {
		response, err := server.Client().Get(server.URL + "/" + hash)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if string(body) != shell {
			t.Fatalf("a deep link changed the shell served for %q", hash)
		}
	}
	if strings.Contains(shell, strings.Repeat("a", 32)) {
		t.Fatal("the public shell carries scope data")
	}
	// Every route a deep link reads is authenticated: without a session each is 401, never the shell and never data.
	for _, route := range []string{"/api/v1/session", "/api/v1/investigate", "/api/v1/query", "/api/v1/traces/view", "/api/v1/replays/stream", "/api/v1/profiles/view"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			request, _ := http.NewRequest(method, server.URL+route, strings.NewReader("{}"))
			request.Header.Set("Origin", server.URL)
			request.Header.Set("Content-Type", "application/json")
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if strings.Contains(string(body), `id="root"`) {
				t.Fatalf("%s %s answered with the shell", method, route)
			}
			if response.StatusCode == 200 || response.StatusCode >= 500 {
				t.Fatalf("%s %s without a session: status %d", method, route, response.StatusCode)
			}
		}
	}
	// A path that is not a file is 404, never the shell: an API typo must not look like a working page, and a
	// path-shaped "deep link" must not pretend that the server authorized anything.
	for _, path := range []string{"/incidents/" + strings.Repeat("a", 32), "/api/v1/nowhere", "/assets", "/assets/sub", "/assets/..%2findex.html"} {
		response, body := uiGet(t, server, path)
		if response.StatusCode != 404 || strings.Contains(body, `id="root"`) {
			t.Fatalf("%s: status %d, want 404 and no shell", path, response.StatusCode)
		}
	}
}
