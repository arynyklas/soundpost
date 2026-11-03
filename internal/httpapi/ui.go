// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
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
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path == "/" {
			files.ServeHTTP(w, r)
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
		files.ServeHTTP(w, r)
	})
}
