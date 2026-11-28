// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/ingest"
)

// The bound on the ingest requests in progress comes before authentication and before the body is read: with no credential at
// all, a request that finds the process full is answered 503 with a Retry-After of 1 to 3 seconds (not 401, which would mean
// that the credential was looked at, and with it a read of the control state), and at once.
func TestTheIngestBoundRefusesBeforeAuthentication(t *testing.T) {
	svc := &ingest.Service{}
	entered := 0
	for svc.Enter() {
		entered++
	}
	mux := http.NewServeMux()
	httpapi.RegisterIngestRoutes(mux, nil, svc)
	seen := map[string]bool{}
	for range 60 {
		rec := httptest.NewRecorder()
		started := time.Now()
		mux.ServeHTTP(rec, httptest.NewRequest("POST", "/ingest/v1/batches", strings.NewReader("{}")))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("a request beyond the bound was answered %d, want 503", rec.Code)
		}
		after, err := strconv.Atoi(rec.Header().Get("Retry-After"))
		if err != nil || after < 1 || after > 3 {
			t.Fatalf("Retry-After %q, want 1 to 3 seconds", rec.Header().Get("Retry-After"))
		}
		seen[rec.Header().Get("Retry-After")] = true
		if !strings.Contains(rec.Body.String(), `"retryable":true`) {
			t.Fatalf("the refusal is not marked retryable: %s", rec.Body)
		}
		if time.Since(started) > time.Second {
			t.Fatalf("the refusal took %v", time.Since(started))
		}
	}
	if len(seen) < 2 {
		t.Fatalf("every refusal told the sender the same Retry-After %v: the senders refused together would return together", seen)
	}
	for range entered {
		svc.Leave()
	}
	if !svc.Enter() {
		t.Fatal("the bound was not released by the requests that left")
	}
}
