// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"strconv"
	"strings"
	"time"
)

const sessionCookie = "__Host-soundpost"

func token(r *http.Request) string {
	c, e := r.Cookie(sessionCookie)
	if e != nil {
		return ""
	}
	return c.Value
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return model.Fail(model.Invalid)
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return model.Fail(model.Invalid)
	}
	return nil
}
func reply(w http.ResponseWriter, v any, e error) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if e != nil {
		var f *model.Fault
		if !errors.As(e, &f) {
			f = model.Fail(model.Unavailable)
		}
		if requestID, err := model.ParseID(w.Header().Get("X-Request-ID")); err == nil {
			copy := *f
			copy.RequestID = requestID
			f = &copy
		}
		status := http.StatusBadRequest
		switch f.Code {
		case model.Unauthenticated:
			status = 401
		case model.Forbidden:
			status = 403
		case model.NotFound:
			status = 404
		case model.Conflict:
			status = 409
		case model.Unavailable, model.Corrupt:
			status = 503
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(f)
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}
func setSession(w http.ResponseWriter, s auth.Session) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: s.Token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
}

// sameOrigin reports whether the request was made by a page of this origin.
// An explicit Origin always decides: it must be this host over https. A browser
// sends no Origin on a same-origin GET or HEAD fetch (only on cross-origin
// requests and on other methods), so for those two safe methods the browser's
// own Sec-Fetch-Site: same-origin is accepted instead. Page script cannot set
// or forge Sec-Fetch-Site (it is a forbidden header name), a missing Origin on a
// state-changing method is never accepted, and every caller of protected still
// has to present the CSRF token.
func sameOrigin(r *http.Request) bool {
	v := r.Header.Get("Origin")
	if v == "" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			return false
		}
		return r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	u, e := url.Parse(v)
	return e == nil && u.Scheme == "https" && u.Host == r.Host
}
func protected(s *auth.Service, w http.ResponseWriter, r *http.Request) (auth.Credential, error) {
	if !sameOrigin(r) {
		return auth.Credential{}, model.Fail(model.Forbidden)
	}
	if e := s.CheckCSRF(r.Context(), token(r), r.Header.Get("X-CSRF-Token")); e != nil {
		return auth.Credential{}, e
	}
	return s.Authenticate(r.Context(), token(r))
}

// acceptsHTML requires an explicit positive-quality HTML media range.
func acceptsHTML(value string) bool {
	for _, item := range strings.Split(value, ",") {
		media, params, err := mime.ParseMediaType(strings.TrimSpace(item))
		if err != nil || media != "text/html" {
			continue
		}
		if quality, ok := params["q"]; ok {
			q, err := strconv.ParseFloat(quality, 64)
			if err != nil || !(q > 0 && q <= 1) {
				continue
			}
		}
		return true
	}
	return false
}
func RegisterSessionRoutes(mux *http.ServeMux, s *auth.Service) {
	mux.HandleFunc("POST /api/v1/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			reply(w, nil, model.Fail(model.Forbidden))
			return
		}
		var q struct{ Token, Email, Password string }
		if e := decode(w, r, &q); e != nil {
			reply(w, nil, e)
			return
		}
		v, e := s.Bootstrap(r.Context(), q.Token, q.Email, q.Password)
		if e == nil {
			setSession(w, v)
		}
		reply(w, v, e)
	})
	mux.HandleFunc("POST /api/v1/login", func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			reply(w, nil, model.Fail(model.Forbidden))
			return
		}
		var q struct{ Email, Password, Code string }
		if e := decode(w, r, &q); e != nil {
			reply(w, nil, e)
			return
		}
		host := auth.SourceFrom(r.Context())
		if host == "" {
			var splitErr error
			if host, _, splitErr = net.SplitHostPort(r.RemoteAddr); splitErr != nil {
				host = r.RemoteAddr
			}
		}
		v, e := s.Login(auth.WithSource(r.Context(), host), q.Email, q.Password, q.Code)
		var limited *auth.RateLimitedError
		if errors.As(e, &limited) {
			seconds := int((limited.RetryAfter + time.Second - 1) / time.Second)
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(&model.Fault{Code: "rate_limited", Retryable: true, SafeDetail: "rate_limited", RequestID: model.NewID()})
			return
		}
		if e == nil {
			if old := token(r); old != "" {
				_ = s.Logout(r.Context(), old)
			}
			setSession(w, v)
		}
		reply(w, v, e)
	})
	mux.HandleFunc("GET /api/v1/session", func(w http.ResponseWriter, r *http.Request) { v, e := s.Session(r.Context(), token(r)); reply(w, v, e) })
	mux.HandleFunc("POST /api/v1/logout", func(w http.ResponseWriter, r *http.Request) {
		_, e := protected(s, w, r)
		if e == nil {
			e = s.Logout(r.Context(), token(r))
		}
		if e == nil {
			http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
		}
		reply(w, struct{}{}, e)
	})
	mux.HandleFunc("POST /api/v1/reauthenticate", func(w http.ResponseWriter, r *http.Request) {
		_, e := protected(s, w, r)
		if e != nil {
			reply(w, nil, e)
			return
		}
		var q struct{ Password, Code string }
		if e = decode(w, r, &q); e != nil {
			reply(w, nil, e)
			return
		}
		v, e := s.Reauthenticate(r.Context(), token(r), q.Password, q.Code)
		if e == nil {
			setSession(w, v)
		}
		reply(w, v, e)
	})
	mux.HandleFunc("POST /api/v1/totp/start", func(w http.ResponseWriter, r *http.Request) {
		_, e := protected(s, w, r)
		if e != nil {
			reply(w, nil, e)
			return
		}
		v, e := s.BeginTOTP(r.Context(), token(r))
		reply(w, map[string]string{"secret": v}, e)
	})
	mux.HandleFunc("POST /api/v1/totp/confirm", func(w http.ResponseWriter, r *http.Request) {
		_, e := protected(s, w, r)
		if e != nil {
			reply(w, nil, e)
			return
		}
		var q struct{ Code string }
		if e = decode(w, r, &q); e != nil {
			reply(w, nil, e)
			return
		}
		v, e := s.ConfirmTOTP(r.Context(), token(r), q.Code)
		reply(w, map[string]any{"recovery_codes": v}, e)
	})
	mux.HandleFunc("POST /api/v1/elevation", func(w http.ResponseWriter, r *http.Request) {
		_, e := protected(s, w, r)
		if e != nil {
			reply(w, nil, e)
			return
		}
		var q struct {
			Reason string
			Orgs   []model.ID
		}
		if e = decode(w, r, &q); e != nil {
			reply(w, nil, e)
			return
		}
		v, e := s.Session(r.Context(), token(r))
		if e != nil {
			reply(w, nil, e)
			return
		}
		elev, e := s.Elevate(r.Context(), v, q.Reason, q.Orgs)
		reply(w, elev, e)
	})
}
func RegisterOIDCRoutes(mux *http.ServeMux, s *auth.Service, cfg auth.OIDCConfig) {
	mux.HandleFunc("POST /api/v1/oidc/start", func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			reply(w, nil, model.Fail(model.Forbidden))
			return
		}
		// Unauthenticated: refuse before any body decode, config lookup or
		// outbound fetch once the pending-login cap is reached.
		if err := s.OIDCCapacity(r.Context()); err != nil {
			w.Header().Set("Retry-After", "60")
			reply(w, nil, err)
			return
		}
		selected := cfg
		if selected.Issuer == "" {
			var q struct {
				OrgID      model.ID `json:"org_id"`
				ProviderID model.ID `json:"provider_id"`
			}
			if err := decode(w, r, &q); err != nil {
				reply(w, nil, err)
				return
			}
			var err error
			selected, err = s.ConfiguredOIDC(r.Context(), q.OrgID, q.ProviderID)
			if err != nil {
				reply(w, nil, err)
				return
			}
		}
		binding := control.Random()
		v, err := s.OIDCStart(r.Context(), selected, binding)
		if err == nil {
			http.SetCookie(w, &http.Cookie{Name: "__Host-soundpost-oidc", Value: binding, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 300})
		}
		reply(w, map[string]string{"url": v}, err)
	})
	mux.HandleFunc("GET /api/v1/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		binding := ""
		if c, err := r.Cookie("__Host-soundpost-oidc"); err == nil {
			binding = c.Value
		}
		selected := cfg
		if selected.Issuer == "" {
			var err error
			selected, err = s.OIDCConfigForState(r.Context(), r.URL.Query().Get("state"))
			if err != nil {
				if acceptsHTML(r.Header.Get("Accept")) {
					w.Header().Set("Cache-Control", "no-store")
					w.Header().Set("Referrer-Policy", "no-referrer")
					http.Redirect(w, r, "/?auth=failed", http.StatusSeeOther)
					return
				}
				reply(w, nil, err)
				return
			}
		}
		v, err := s.OIDCCallback(r.Context(), selected, binding, r.URL.Query().Get("state"), r.URL.Query().Get("code"))
		http.SetCookie(w, &http.Cookie{Name: "__Host-soundpost-oidc", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
		if err == nil {
			if old := token(r); old != "" {
				_ = s.Logout(r.Context(), old)
			}
			setSession(w, v)
		}
		if acceptsHTML(r.Header.Get("Accept")) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Referrer-Policy", "no-referrer")
			target := "/"
			if err != nil {
				target = "/?auth=failed"
			}
			http.Redirect(w, r, target, http.StatusSeeOther)
			return
		}
		reply(w, v, err)
	})
}
