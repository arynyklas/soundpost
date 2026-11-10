// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"soundpost/internal/health"
)

// ReadyFunc is the node's readiness decision (health.Ready bound to its local state).
type ReadyFunc func(context.Context) (health.Readiness, error)

const (
	readyCacheTTL    = time.Second
	readyEvalTimeout = 3 * time.Second
	readinessPath    = "/readyz"
)

// RegisterHealthRoutes mounts the one unauthenticated route, GET /readyz. It answers
// 200 only when health.Ready says ready and 503 otherwise, with the closed JSON body
// {ready, reason | version, applied_cursor}: no tenant, path, address or credential state.
// An evaluation costs one quorum read per replication group, so results are shared for
// one second and concurrent callers never start parallel evaluations.
func RegisterHealthRoutes(mux *http.ServeMux, ready ReadyFunc) {
	handler := newReadyHandler(ready, readyCacheTTL, time.Now)
	mux.Handle("GET "+readinessPath, handler)
}

type readyHandler struct {
	check ReadyFunc
	ttl   time.Duration
	now   func() time.Time
	mu    sync.Mutex
	at    time.Time
	value health.Readiness
}

func newReadyHandler(check ReadyFunc, ttl time.Duration, now func() time.Time) *readyHandler {
	return &readyHandler{check: check, ttl: ttl, now: now}
}

func (h *readyHandler) current(ctx context.Context) health.Readiness {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.at.IsZero() && h.now().Sub(h.at) < h.ttl {
		return h.value
	}
	eval, cancel := context.WithTimeout(ctx, readyEvalTimeout)
	defer cancel()
	value, err := h.check(eval)
	if err != nil {
		value = health.Unready(health.ReasonStateUnavailable)
	}
	h.value, h.at = value, h.now()
	return value
}

func (h *readyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	writeReadiness(w, h.current(r.Context()))
}

func writeReadiness(w http.ResponseWriter, v health.Readiness) {
	// Whatever the decision function returned, the wire carries only the closed shape: an
	// unready answer is its valid reason alone, a ready one has no reason.
	if !v.Ready {
		reason := v.Reason
		if !reason.Valid() {
			reason = health.ReasonStateUnavailable
		}
		v = health.Unready(reason)
	} else {
		v.Reason = ""
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if !v.Ready {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(v)
}

// Gate is the handler a serving process installs before storage has opened. Until Open
// it answers /readyz with the unready reason and everything else with a retryable 503;
// after Open it only delegates. The listener therefore exists while recovery runs, and a
// probe sees "not ready" instead of a refused connection or a ready lie.
type Gate struct {
	reason atomic.Value // health.Reason
	next   atomic.Pointer[http.Handler]
}

// NewGate returns a closed gate that reports reason.
func NewGate(reason health.Reason) *Gate {
	g := &Gate{}
	g.reason.Store(reason)
	return g
}

// SetReason changes the reason a closed gate reports.
func (g *Gate) SetReason(r health.Reason) { g.reason.Store(r) }

// Open makes the gate delegate every request to h from now on.
func (g *Gate) Open(h http.Handler) { g.next.Store(&h) }

func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if next := g.next.Load(); next != nil {
		(*next).ServeHTTP(w, r)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	if r.Method == http.MethodGet && r.URL.Path == readinessPath {
		writeReadiness(w, health.Unready(g.reason.Load().(health.Reason)))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", "1")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte("{\"code\":\"unavailable\",\"retryable\":true}\n"))
}

// StartupServer is the HTTPS server a process starts before storage opens, with the same
// TLS floor, timeouts and header limit as NewServer.
func StartupServer(address string, handler http.Handler) *http.Server {
	return &http.Server{Addr: address, Handler: handler, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
}
