// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"crypto/tls"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"net/http"
	"time"
)

func NewServer(address string, s *auth.Service, oidc *auth.OIDCConfig, register ...func(*http.ServeMux)) *http.Server {
	return NewServerBehind(nil, address, s, oidc, register...)
}

// NewServerBehind is NewServer for a deployment behind a reverse proxy: the peers in proxies may
// name the client (see TrustedProxies); nobody else can.
func NewServerBehind(proxies TrustedProxies, address string, s *auth.Service, oidc *auth.OIDCConfig, register ...func(*http.ServeMux)) *http.Server {
	mux := http.NewServeMux()
	RegisterSessionRoutes(mux, s)
	RegisterAdminRoutes(mux, s)
	RegisterTokenRoutes(mux, s)
	RegisterControlRoutes(mux, s)
	cfg := auth.OIDCConfig{}
	if oidc != nil {
		cfg = *oidc
	}
	RegisterOIDCRoutes(mux, s, cfg)
	for _, routes := range register {
		routes(mux)
	}
	return &http.Server{Addr: address, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := model.RequestCorrelationID(r.Context(), model.ID{})
		r = r.WithContext(model.WithRequestID(r.Context(), requestID))
		r = r.WithContext(auth.WithSource(r.Context(), proxies.ClientAddr(r)))
		w.Header().Set("X-Request-ID", requestID.String())
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		if r.TLS == nil {
			http.Error(w, "HTTPS required", 400)
			return
		}
		mux.ServeHTTP(w, r)
	}), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
}
