// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
)

// Contract C11 (specs/2026-11-03-soundpost-contracts.md, "GET /api/v1/operations/{id}")
// names the answer LifecycleOperation{ID,Kind,Phase,Generation,Progress,SafeReason}.
// This test polls a deletion at the CONTRACT path (not the /lifecycle alias) and
// requires every one of those six fields, with the receipt's values, in the body.
// The body may carry more fields (the web client reads state, pending_groups and
// applied_barriers); nothing named by the contract may be missing or renamed.
func TestOperationsContractPathAnswersEveryC11Field(t *testing.T) {
	e := newActEnv(t)
	org := e.org("operations c11 contract path", model.NewID())
	alice := e.user(org, "alice-c11-path@example.test")
	e.admin(org, alice)
	e.poller.org = org
	physical := model.UnixNano(time.Now().Add(24 * time.Hour).UnixNano())
	id := model.NewID()
	e.poller.receipts[id] = retention.DeleteReceipt{OperationID: id, Mode: "historical_range", Phase: model.DeletePhaseFailed, Generation: 4, Progress: "10/64", Physical: "pending", PhysicalDeadline: physical, BackupDeadline: physical, SafeReason: "barrier_failed"}

	srv := httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterOperationRoutes(mux, e.app.Auth, e.actions)
	}).Handler)
	t.Cleanup(srv.Close)
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/operations/"+id.String()+"?org="+org.String(), nil)
	req.Header.Set("Cookie", "__Host-soundpost="+alice.Session.Token)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("contract path poll: %d %s", resp.StatusCode, raw)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]string{"id": id.String(), "kind": "historical_range", "phase": model.DeletePhaseFailed, "generation": "4", "progress": "10/64", "safe_reason": "barrier_failed"} {
		if got, ok := body[field].(string); !ok || got != want {
			t.Fatalf("C11 field %q = %v, want %q in %s", field, body[field], want, raw)
		}
	}
}
