// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

// L1-R03 F5: an operation whose saga ended failed is answered by the begin route
// with 409, the typed detail deletion_failed and the receipt with its
// safe_reason; it is neither the held answer nor a 503. The operation is a real
// begun deletion that the control store (the operator action every other
// failed-operation test uses) settles as failed; the route is then asked the
// same command again, which is how an old command's failed outcome is read back.
func TestDeletionRouteAnswers409DeletionFailedWithTheSafeReason(t *testing.T) {
	e := newFenceEnv(t)
	command := model.NewID()
	body := map[string]any{"command_id": command.String(), "expected_revision": strconv.FormatUint(uint64(e.revision()), 10), "mode": model.DeleteRetireProject,
		"org_id": e.org.String(), "project_ids": []string{e.project.String()}, "reason": "this one will fail"}
	status, raw := e.do("POST", "/api/v1/admin/deletions", body)
	if status != http.StatusAccepted {
		t.Fatalf("begin: %d %s", status, raw)
	}
	if _, err := e.store.FailDeletion(e.ctx, command, model.UnixNano(time.Now().UnixNano()), "operator_failed"); err != nil {
		t.Fatal(err)
	}

	status, raw = e.do("POST", "/api/v1/admin/deletions", body)
	if status != http.StatusConflict {
		t.Fatalf("a failed operation must answer 409, got %d %s", status, raw)
	}
	var refused httpapi.DeletionRefused
	if err := model.StrictJSON(raw, &refused); err != nil {
		t.Fatalf("not a DeletionRefused: %v %s", err, raw)
	}
	if refused.Code != string(model.Conflict) || refused.Detail != httpapi.DetailDeletionFailed || refused.RequestID == "" {
		t.Fatalf("typed refusal %+v", refused)
	}
	if r := refused.Receipt; r.Phase != model.DeletePhaseFailed || r.SafeReason != "operator_failed" || r.OperationID != command {
		t.Fatalf("receipt %+v", r)
	}
	// Nothing is ever un-deleted: the failed operation keeps the project's reads denied.
	if e.canRead(e.project) {
		t.Fatal("a failed deletion must keep reads denied")
	}
}
