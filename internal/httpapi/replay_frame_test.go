// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"soundpost/internal/httpapi"
)

func frameFS(frame string) fstest.MapFS {
	return fstest.MapFS{
		"index.html":               {Data: []byte(`<!doctype html><div id="root"></div><script type="module" src="/assets/app.js"></script>`)},
		"assets/app.js":            {Data: []byte("console.log(1)")},
		"assets/replay-frame.html": {Data: []byte(frame)},
	}
}

func serveUI(t *testing.T, fs fstest.MapFS, path string) *httptest.ResponseRecorder {
	t.Helper()
	register, err := httpapi.UIRoutes(fs)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

func sri(text string) string {
	sum := sha256.Sum256([]byte(text))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

func TestReplayFrameIsServedUnderItsOwnHashOnlyNoNetworkPolicy(t *testing.T) {
	script, style := `window.x=1;/* a "quoted" </b> value */`, `body{margin:0}`
	doc := `<!doctype html><html><head><style>` + style + `</style></head><body><div id="replay"></div><script>` + script + `</script></body></html>`
	rec := serveUI(t, frameFS(doc), "/assets/replay-frame.html")
	if rec.Code != 200 || rec.Body.String() != doc {
		t.Fatalf("frame: %d %q", rec.Code, rec.Body.String())
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "connect-src 'none'", "img-src 'none'", "frame-src 'none'", "form-action 'none'", "base-uri 'none'", "frame-ancestors 'self'", "sandbox allow-scripts", "script-src " + sri(script) + ";", "style-src " + sri(style) + ";"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("frame CSP lacks %q:\n%s", want, csp)
		}
	}
	for _, banned := range []string{"unsafe-inline", "unsafe-eval", "'self'; ", "allow-same-origin", "*", "data:", "blob:"} {
		if strings.Contains(strings.ReplaceAll(csp, "frame-ancestors 'self'", ""), banned) {
			t.Fatalf("frame CSP contains %q:\n%s", banned, csp)
		}
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("headers: %v", rec.Header())
	}
}

func TestAppPolicyOnlyGainsSameOriginFramesAndStillForbidsInlineScript(t *testing.T) {
	rec := serveUI(t, frameFS(`<style></style><script>1</script>`), "/")
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-src 'self'", "frame-ancestors 'none'", "connect-src 'self'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("app CSP lacks %q: %s", want, csp)
		}
	}
	for _, banned := range []string{"unsafe-inline", "unsafe-eval", "blob:", "data:", "*"} {
		if strings.Contains(csp, banned) {
			t.Fatalf("app CSP contains %q: %s", banned, csp)
		}
	}
	// Other assets keep the app policy, never the frame's.
	if js := serveUI(t, frameFS(`<style></style><script>1</script>`), "/assets/app.js").Header().Get("Content-Security-Policy"); js != csp {
		t.Fatalf("a normal asset got a different policy: %s", js)
	}
}

func TestReplayFrameWithAnUnexpectedShapeIsRefusedNotServedWeaklyOrHashed(t *testing.T) {
	for name, doc := range map[string]string{
		"two scripts":         `<style>a</style><script>1</script><script>2</script>`,
		"external script":     `<style>a</style><script src="/assets/x.js"></script>`,
		"two styles":          `<style>a</style><style>b</style><script>1</script>`,
		"no script":           `<style>a</style>`,
		"no style":            `<script>1</script>`,
		"empty script":        `<style>a</style><script></script>`,
		"unterminated script": `<style>a</style><script>1`,
		"script before style": `<script>1</script><style>a</style><script>2</script>`,
	} {
		if rec := serveUI(t, frameFS(doc), "/assets/replay-frame.html"); rec.Code != 404 {
			t.Fatalf("%s: %d", name, rec.Code)
		}
	}
	if rec := serveUI(t, func() fstest.MapFS { m := frameFS(""); delete(m, "assets/replay-frame.html"); return m }(), "/assets/replay-frame.html"); rec.Code != 404 {
		t.Fatalf("absent frame: %d", rec.Code)
	}
}
