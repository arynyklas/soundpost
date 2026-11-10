// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"soundpost/internal/health"
	"soundpost/internal/model"
)

const healthCanary = "SOUNDPOST_HEALTH_ROUTE_CANARY"

func probe(t *testing.T, h http.Handler, method, path string) (int, map[string]json.RawMessage, http.Header, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	var body map[string]json.RawMessage
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body, rec.Header(), rec.Body.String()
}

func readyMux(f ReadyFunc) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterHealthRoutes(mux, f)
	return mux
}

// /readyz is 200 only for a ready decision, and a 503 carries the closed reason and
// nothing else; the ready body carries version and cursor and nothing else.
func TestReadyzMapsTheDecisionToStatusAndClosedBody(t *testing.T) {
	cursor := model.Cursor{Group: model.NewID(), Index: 9}
	ready := health.Readiness{Ready: true, Version: "9.9.9", Applied: &cursor}
	code, body, hdr, raw := probe(t, readyMux(func(context.Context) (health.Readiness, error) { return ready, nil }), "GET", "/readyz")
	if code != 200 || string(body["ready"]) != "true" || string(body["version"]) != `"9.9.9"` || body["applied_cursor"] == nil || len(body) != 3 {
		t.Fatalf("ready answer: %d %s", code, raw)
	}
	if hdr.Get("Cache-Control") != "no-store" || hdr.Get("Retry-After") != "" {
		t.Fatalf("ready headers: %v", hdr)
	}
	code, body, hdr, raw = probe(t, readyMux(func(context.Context) (health.Readiness, error) {
		return health.Unready(health.ReasonNoQuorum), nil
	}), "GET", "/readyz")
	if code != 503 || string(body["ready"]) != "false" || string(body["reason"]) != `"no_quorum"` || len(body) != 2 {
		t.Fatalf("unready answer: %d %s", code, raw)
	}
	if hdr.Get("Retry-After") == "" || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("unready headers: %v", hdr)
	}
}

// A failing evaluation, an off-list reason or an unready answer that smuggles fields must
// never reach the wire as anything but the closed state_unavailable reason.
func TestReadyzNeverEchoesErrorsOrOffListReasons(t *testing.T) {
	for name, f := range map[string]ReadyFunc{
		"error": func(context.Context) (health.Readiness, error) {
			return health.Readiness{}, errors.New("open /srv/" + healthCanary)
		},
		"free reason": func(context.Context) (health.Readiness, error) {
			return health.Readiness{Reason: health.Reason("token " + healthCanary)}, nil
		},
		"unready with ready fields": func(context.Context) (health.Readiness, error) {
			c := model.Cursor{Group: model.NewID(), Index: 1}
			return health.Readiness{Reason: health.ReasonSyncFailed, Version: healthCanary, Applied: &c}, nil
		},
	} {
		code, body, _, raw := probe(t, readyMux(f), "GET", "/readyz")
		if code != 503 || strings.Contains(raw, healthCanary) {
			t.Fatalf("%s: %d %s", name, code, raw)
		}
		if name != "unready with ready fields" && string(body["reason"]) != `"state_unavailable"` {
			t.Fatalf("%s: %s", name, raw)
		}
		if body["version"] != nil || body["applied_cursor"] != nil {
			t.Fatalf("%s: unready answer carries ready fields: %s", name, raw)
		}
	}
}

// A ready decision that also carries a reason is still a plain ready answer on the wire.
func TestReadyzDropsAReasonFromAReadyAnswer(t *testing.T) {
	cursor := model.Cursor{Group: model.NewID(), Index: 3}
	_, body, _, raw := probe(t, readyMux(func(context.Context) (health.Readiness, error) {
		return health.Readiness{Ready: true, Reason: health.ReasonNoQuorum, Version: "1", Applied: &cursor}, nil
	}), "GET", "/readyz")
	if body["reason"] != nil {
		t.Fatalf("ready answer carries a reason: %s", raw)
	}
}

// The route is unauthenticated by design and read-only: no other method answers, and a
// cookie or token on the request changes nothing.
func TestReadyzIsGetOnlyAndIgnoresCredentials(t *testing.T) {
	mux := readyMux(func(context.Context) (health.Readiness, error) { return health.Unready(health.ReasonPolicyStale), nil })
	for _, m := range []string{"POST", "PUT", "DELETE"} {
		if code, _, _, _ := probe(t, mux, m, "/readyz"); code != http.StatusMethodNotAllowed {
			t.Fatalf("%s /readyz answered %d", m, code)
		}
	}
	req := httptest.NewRequest("GET", "/readyz", nil)
	req.Header.Set("Authorization", "Bearer "+healthCanary)
	req.Header.Set("Cookie", "__Host-soundpost="+healthCanary)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 503 || strings.Contains(rec.Body.String(), healthCanary) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

// An evaluation costs one quorum round per group, so an unauthenticated caller must not be able to
// multiply it: results are shared for the TTL, concurrent callers wait for one evaluation, and
// the next evaluation happens once the TTL passed.
func TestReadyzSharesOneEvaluationPerTTLAndNeverRunsTwoAtOnce(t *testing.T) {
	var calls, running, overlap atomic.Int32
	var clockMu sync.Mutex
	clock := time.Unix(1000, 0)
	now := func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return clock }
	h := newReadyHandler(func(context.Context) (health.Readiness, error) {
		if running.Add(1) > 1 {
			overlap.Add(1)
		}
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		running.Add(-1)
		return health.Unready(health.ReasonNoQuorum), nil
	}, time.Second, now)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() { defer wg.Done(); probe(t, h, "GET", "/readyz") }()
	}
	wg.Wait()
	if calls.Load() != 1 || overlap.Load() != 0 {
		t.Fatalf("32 concurrent probes ran %d evaluations (%d overlapping)", calls.Load(), overlap.Load())
	}
	clockMu.Lock()
	clock = clock.Add(999 * time.Millisecond)
	clockMu.Unlock()
	probe(t, h, "GET", "/readyz")
	if calls.Load() != 1 {
		t.Fatalf("a probe inside the TTL re-evaluated (%d)", calls.Load())
	}
	clockMu.Lock()
	clock = clock.Add(2 * time.Millisecond)
	clockMu.Unlock()
	probe(t, h, "GET", "/readyz")
	if calls.Load() != 2 {
		t.Fatalf("a probe after the TTL did not re-evaluate (%d)", calls.Load())
	}
}

// A hung dependency cannot hang the probe: the evaluation context is bounded.
func TestReadyzBoundsTheEvaluation(t *testing.T) {
	h := newReadyHandler(func(ctx context.Context) (health.Readiness, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > readyEvalTimeout {
			t.Errorf("evaluation context has no bounded deadline")
		}
		return health.Readiness{}, ctx.Err()
	}, time.Second, time.Now)
	probe(t, h, "GET", "/readyz")
}

// Before storage opens the process answers, it does not refuse: /readyz says why it is not
// ready and nothing else is served; once opened the gate only delegates.
func TestGateAnswersUnreadyUntilOpenedThenDelegates(t *testing.T) {
	gate := NewGate(health.ReasonStarting)
	code, body, hdr, raw := probe(t, gate, "GET", "/readyz")
	if code != 503 || string(body["reason"]) != `"starting"` || len(body) != 2 || hdr.Get("Retry-After") == "" {
		t.Fatalf("closed gate /readyz: %d %s", code, raw)
	}
	gate.SetReason(health.ReasonStartupHold)
	if _, body, _, _ = probe(t, gate, "GET", "/readyz"); string(body["reason"]) != `"startup_hold"` {
		t.Fatalf("reason not updated: %v", body)
	}
	for _, c := range []struct{ method, path string }{{"POST", "/ingest/v1/batches"}, {"GET", "/"}, {"POST", "/api/v1/bootstrap"}, {"POST", "/readyz"}} {
		code, _, hdr, raw = probe(t, gate, c.method, c.path)
		if code != 503 || hdr.Get("Retry-After") == "" || !strings.Contains(raw, `"retryable":true`) {
			t.Fatalf("closed gate %s %s: %d %s", c.method, c.path, code, raw)
		}
	}
	gate.Open(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	for _, p := range []string{"/readyz", "/anything"} {
		if code, _, _, _ = probe(t, gate, "GET", p); code != 204 {
			t.Fatalf("opened gate did not delegate %s: %d", p, code)
		}
	}
}

// The startup server must not be a weaker door than the real one: it takes its TLS floor
// and timeouts from the same values NewServer uses.
func TestStartupServerHasTheSameHardeningAsTheRealServer(t *testing.T) {
	real, early := NewServer("127.0.0.1:0", nil, nil), StartupServer("127.0.0.1:0", http.NotFoundHandler())
	if early.TLSConfig.MinVersion != real.TLSConfig.MinVersion || early.ReadHeaderTimeout != real.ReadHeaderTimeout || early.ReadTimeout != real.ReadTimeout || early.WriteTimeout != real.WriteTimeout || early.IdleTimeout != real.IdleTimeout || early.MaxHeaderBytes != real.MaxHeaderBytes {
		t.Fatalf("startup server hardening differs: %+v vs %+v", early, real)
	}
}
