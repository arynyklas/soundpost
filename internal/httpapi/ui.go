// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"strings"
)

// UIRoutes admits only a real production bundle, on the existing HTTPS origin.
func UIRoutes(assets fs.FS) (func(*http.ServeMux), error) {
	if assets == nil {
		return nil, fmt.Errorf("UI assets required")
	}
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		return nil, fmt.Errorf("UI index: %w", err)
	}
	refs := regexp.MustCompile(`(?:src|href)="(/assets/[^"?#]+)"`).FindAllSubmatch(index, -1)
	script := false
	if !strings.Contains(string(index), `id="root"`) {
		return nil, fmt.Errorf("UI root missing")
	}
	for _, ref := range refs {
		name := strings.TrimPrefix(string(ref[1]), "/")
		if !fs.ValidPath(name) {
			return nil, fmt.Errorf("invalid UI asset")
		}
		info, e := fs.Stat(assets, name)
		if e != nil || info.IsDir() || info.Size() == 0 {
			return nil, fmt.Errorf("missing UI asset %s", name)
		}
		if strings.HasSuffix(name, ".js") {
			script = true
		}
	}
	if !script {
		return nil, fmt.Errorf("built UI module missing")
	}
	return func(mux *http.ServeMux) { RegisterUI(mux, assets) }, nil
}

// RegisterUI is used after UIRoutes has verified the bundle.
func RegisterUI(mux *http.ServeMux, assets fs.FS) {
	files := http.FileServer(http.FS(assets))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; frame-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path == "/" {
			files.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == noticesPath {
			serveNotices(w, assets)
			return
		}
		if consolePath(r.URL.Path) {
			serveConsoleShell(w, assets)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/assets/") || strings.Contains(r.URL.Path, "\\") || path.Clean(r.URL.Path) != r.URL.Path {
			http.NotFound(w, r)
			return
		}
		info, err := fs.Stat(assets, strings.TrimPrefix(r.URL.Path, "/"))
		if err != nil || info.IsDir() {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == replayFramePath {
			serveReplayFrame(w, r, assets)
			return
		}
		if isHashedAsset(r.URL.Path) {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		files.ServeHTTP(w, r)
	})
}

// noticesPath is the licence notice web/public/THIRD-PARTY-NOTICES.txt that the build copies to the root of the bundle: the MIT code the
// bundle contains requires its notice to travel with the distribution, so the origin that serves the bundle serves it too.
const noticesPath = "/THIRD-PARTY-NOTICES.txt"

// serveNotices answers the notices as plain text under the same headers as every other response; a bundle without the file answers 404.
func serveNotices(w http.ResponseWriter, assets fs.FS) {
	text, err := fs.ReadFile(assets, strings.TrimPrefix(noticesPath, "/"))
	if err != nil {
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(text)
}

// consoleSections are the console views a path-shaped link may name (web/src/app/context.ts SECTIONS). The value says whether
// the view opens one entity, in which case one more path segment, the entity's ID, is allowed.
var consoleSections = map[string]bool{
	"queue": false, "incidents": true, "issues": true, "releases": true, "traces": true, "explore": false,
	"services": true, "jobs": true, "replays": true, "profiles": true, "settings": false,
}

var consoleEntity = regexp.MustCompile(`^[0-9a-f]{32}(?::[0-9a-f]{32})?$`)

// consolePath reports whether a request path is a path-shaped console link: /<section> or /<section>/<entity> for a
// known section and an entity that is a 32-hex ID or a `project:id` pair. Nothing else is a console link (the strict
// grammar also rejects empty, extra and backslash segments), so every other unknown path stays 404: an API typo must
// not look like a working page.
func consolePath(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	section, entity, hasEntity := strings.Cut(p[1:], "/")
	opens, known := consoleSections[section]
	if !known {
		return false
	}
	return !hasEntity || (opens && consoleEntity.MatchString(entity))
}

// serveConsoleShell answers a console path with the same public shell the root serves (no data; the console rewrites the
// path to its hash route and every read stays behind the authenticated API calls).
func serveConsoleShell(w http.ResponseWriter, assets fs.FS) {
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(index)
}

var hashedName = regexp.MustCompile(`^.+?-([A-Za-z0-9_-]{8,})\.(?:js|css)$`)

// isHashedAsset reports whether a served /assets file name carries its content hash in Vite's `name-HASH.ext` form (eight
// or more base64url characters including a digit or an upper-case letter). Such a file never changes under its name, so it
// is the only thing cached forever; the shell and every other name, the replay frame included, stay no-store.
func isHashedAsset(urlPath string) bool {
	m := hashedName.FindStringSubmatch(path.Base(urlPath))
	return m != nil && strings.ContainsAny(m[1], "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

// replayFramePath is the sandboxed replay viewer document built by web/vite.config.ts.
const replayFramePath = "/assets/replay-frame.html"

// replayFrameCSP derives the viewer's hash-only policy from the document itself:
// exactly one inline script and one inline style, each allowed by SHA-256 and
// nothing else, no network of any kind, and a forced sandbox without
// allow-same-origin so even a direct navigation runs in an opaque origin. A
// document that does not have exactly that shape gets no policy and is refused.
func replayFrameCSP(doc string) (string, bool) {
	if strings.Count(doc, "<script") != 1 || strings.Count(doc, "<style") != 1 {
		return "", false
	}
	section := func(open, close string) (string, bool) {
		start := strings.Index(doc, open)
		end := strings.Index(doc, close)
		if start < 0 || end < start+len(open) {
			return "", false
		}
		return doc[start+len(open) : end], true
	}
	script, okScript := section("<script>", "</script>")
	style, okStyle := section("<style>", "</style>")
	if !okScript || !okStyle || script == "" {
		return "", false
	}
	hash := func(text string) string {
		sum := sha256.Sum256([]byte(text))
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}
	return "default-src 'none'; connect-src 'none'; img-src 'none'; media-src 'none'; frame-src 'none'; script-src " + hash(script) + "; style-src " + hash(style) + "; form-action 'none'; base-uri 'none'; frame-ancestors 'self'; sandbox allow-scripts", true
}

func serveReplayFrame(w http.ResponseWriter, r *http.Request, assets fs.FS) {
	doc, err := fs.ReadFile(assets, strings.TrimPrefix(replayFramePath, "/"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	csp, ok := replayFrameCSP(string(doc))
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(doc)
}
