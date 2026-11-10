// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A browser sends no Origin header on a same-origin GET fetch (only on cross-origin
// requests and on non-GET methods), so the cookie-session stream request carries
// Sec-Fetch-Site instead. The check must accept exactly that shape for GET and HEAD
// and nothing else: a missing Origin on a state-changing method, a mismatched or
// downgraded Origin, and every other Sec-Fetch-Site value stay refused.
func TestSameOriginAcceptsOnlyBrowserSameOriginShapes(t *testing.T) {
	const host = "soundpost.example.test"
	for _, c := range []struct {
		name   string
		method string
		origin string
		site   string
		want   bool
	}{
		{"post with the matching https origin", http.MethodPost, "https://" + host, "", true},
		{"get with the matching https origin", http.MethodGet, "https://" + host, "", true},
		{"post without an origin is refused even when the browser says same-origin", http.MethodPost, "", "same-origin", false},
		{"put without an origin is refused", http.MethodPut, "", "same-origin", false},
		{"delete without an origin is refused", http.MethodDelete, "", "same-origin", false},
		{"get without an origin and without fetch metadata is refused", http.MethodGet, "", "", false},
		{"get without an origin from the same site is refused", http.MethodGet, "", "same-site", false},
		{"get without an origin from another site is refused", http.MethodGet, "", "cross-site", false},
		{"get without an origin and a user-initiated navigation is refused", http.MethodGet, "", "none", false},
		{"get without an origin and a forged value is refused", http.MethodGet, "", "same-origin, cross-site", false},
		{"head without an origin from the same origin is accepted", http.MethodHead, "", "same-origin", true},
		{"get without an origin from the same origin is accepted", http.MethodGet, "", "same-origin", true},
		{"an explicit origin wins over fetch metadata: foreign host", http.MethodGet, "https://evil.example.test", "same-origin", false},
		{"an explicit origin wins over fetch metadata: downgraded scheme", http.MethodGet, "http://" + host, "same-origin", false},
		{"an explicit origin that does not parse is refused", http.MethodGet, "https://%zz", "same-origin", false},
	} {
		r := httptest.NewRequest(c.method, "https://"+host+"/api/v1/live?ticket=x", nil)
		r.Host = host
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		if c.site != "" {
			r.Header.Set("Sec-Fetch-Site", c.site)
		}
		if got := sameOrigin(r); got != c.want {
			t.Errorf("%s: sameOrigin = %v, want %v", c.name, got, c.want)
		}
	}
}
