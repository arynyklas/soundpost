// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"unicode/utf8"

	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/retention"
)

// Deleter is the one C11 call that BEGINS a deletion. *retention.Service
// implements it. Polling is not part of it: GET /api/v1/operations/{id}?org=
// (alias /api/v1/lifecycle/operations/{id}) already delegates PollDelete and is
// not duplicated here.
type Deleter interface {
	Delete(ctx context.Context, scope auth.Scope, req retention.DeleteRequest) (retention.DeleteReceipt, error)
}

// Deletion limits. The reason is stored in the deletion operation and in its
// audit entry, so it is bounded like every other admin reason (512 bytes).
const (
	deletionBodyLimit  = 65536
	maxDeletionReason  = 512
	maxDeletionProject = 128
	maxDeletionSignals = 16
	maxDeletionEntity  = 128

	// ReasonDeletionNotWired is the typed not_available reason of a process
	// built without a deletion authority.
	ReasonDeletionNotWired = "deletion_authority_not_wired"
	// DetailDeletionHeld and DetailDeletionFailed are the typed 409 details of a
	// receipt that is not a begun-and-fencing or complete deletion.
	DetailDeletionHeld   = "deletion_held"
	DetailDeletionFailed = "deletion_failed"
)

// DeletionRequest is the closed POST /api/v1/admin/deletions body (the C11
// retention.DeleteRequest). Revision and nanosecond fields are canonical
// decimal strings; an unknown field is rejected. Reason is required.
type DeletionRequest struct {
	CommandID        model.ID     `json:"command_id"`
	ExpectedRevision model.Uint64 `json:"expected_revision"`
	Mode             string       `json:"mode"`
	OrgID            model.ID     `json:"org_id"`
	ProjectIDs       []model.ID   `json:"project_ids,omitempty"`
	Signals          []model.Kind `json:"signals,omitempty"`
	Start            model.Int64  `json:"start_ns,omitempty"`
	End              model.Int64  `json:"end_ns,omitempty"`
	EntityIDs        []model.ID   `json:"entity_ids,omitempty"`
	Reason           string       `json:"reason"`
}

// DeletionReceipt is the closed response body: the safe projection of
// retention.DeleteReceipt. Phase fencing means reads are already denied but the
// erasure is not complete; it is not success.
type DeletionReceipt struct {
	OperationID      model.ID     `json:"operation_id"`
	Mode             string       `json:"mode"`
	Phase            string       `json:"phase"`
	Generation       model.Uint64 `json:"generation"`
	Revision         model.Uint64 `json:"revision"`
	Progress         string       `json:"progress"`
	Physical         string       `json:"physical"`
	PhysicalDeadline model.Int64  `json:"physical_deadline_ns"`
	BackupDeadline   model.Int64  `json:"backup_deadline_ns"`
	Holds            []model.ID   `json:"holds,omitempty"`
	SafeReason       string       `json:"safe_reason,omitempty"`
	ResidualStores   []string     `json:"residual_stores,omitempty"`
}

// DeletionRefused is the HTTP 409 body of a held or failed receipt. Code is the
// fault code, Detail the typed reason, and Receipt the original receipt.
type DeletionRefused struct {
	Code      string          `json:"code"`
	Detail    string          `json:"detail"`
	Receipt   DeletionReceipt `json:"receipt"`
	RequestID string          `json:"request_id,omitempty"`
}

// DeletionNotAvailable is the HTTP 501 body of a process with no deletion
// authority: nothing was changed.
type DeletionNotAvailable struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
}

func deletionReceipt(r retention.DeleteReceipt) DeletionReceipt {
	return DeletionReceipt{OperationID: r.OperationID, Mode: r.Mode, Phase: r.Phase, Generation: model.Uint64(r.Generation), Revision: model.Uint64(r.Revision), Progress: r.Progress, Physical: r.Physical,
		PhysicalDeadline: model.Int64(r.PhysicalDeadline), BackupDeadline: model.Int64(r.BackupDeadline), Holds: r.Holds, SafeReason: r.SafeReason, ResidualStores: r.Residual}
}

// deletionRequest validates the closed body shape before any authority is
// consulted. Every failure is a fixed detail; nothing the caller sent is echoed.
func deletionRequest(q DeletionRequest) (retention.DeleteRequest, error) {
	if q.CommandID == (model.ID{}) || q.OrgID == (model.ID{}) {
		return retention.DeleteRequest{}, invalid("deletion_ids_required")
	}
	if reason := strings.TrimSpace(q.Reason); reason == "" || len(q.Reason) > maxDeletionReason || !utf8.ValidString(q.Reason) {
		return retention.DeleteRequest{}, invalid("deletion_reason_invalid")
	}
	if len(q.ProjectIDs) > maxDeletionProject || len(q.Signals) > maxDeletionSignals || len(q.EntityIDs) > maxDeletionEntity {
		return retention.DeleteRequest{}, invalid("deletion_scope_too_large")
	}
	for _, id := range append(append([]model.ID(nil), q.ProjectIDs...), q.EntityIDs...) {
		if id == (model.ID{}) {
			return retention.DeleteRequest{}, invalid("deletion_ids_required")
		}
	}
	req := retention.DeleteRequest{CommandID: q.CommandID, ExpectedRevision: model.Revision(q.ExpectedRevision), Mode: q.Mode, OrgID: q.OrgID, ProjectIDs: q.ProjectIDs, Signals: q.Signals,
		Start: model.UnixNano(q.Start), End: model.UnixNano(q.End), EntityIDs: q.EntityIDs, Reason: q.Reason}
	predicate := model.DeletePredicate{Operation: req.CommandID, Org: req.OrgID, Mode: req.Mode, Projects: req.ProjectIDs, Signals: req.Signals, Start: req.Start, End: req.End, Entities: req.EntityIDs}
	if predicate.Validate() != nil {
		return retention.DeleteRequest{}, invalid("deletion_scope_invalid")
	}
	return req, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func nilDeleter(d Deleter) bool {
	if d == nil {
		return true
	}
	v := reflect.ValueOf(d)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

// RegisterDeletionRoutes mounts the one route that can begin a deletion:
//
//	POST /api/v1/admin/deletions     DeletionRequest -> DeletionReceipt
//
// 202 while the receipt is fencing (reads are already denied; the erasure is not
// complete), 200 complete, 409 DeletionRefused for held or failed, 501
// DeletionNotAvailable with no deleter. Authentication is a session (CSRF
// bound) or server credential; a deletion is destructive, so it also needs the
// fresh reauthentication every sensitive admin command needs (server tokens are
// never fresh, so they cannot begin one). The scope is derived from the
// CALLER's credential for the requested org with organization-admin permission:
// another org, a non-admin and a missing org are the same NotFound. A retry of
// the same CommandID returns the original receipt. Poll with
// GET /api/v1/operations/{id}?org= (or the /api/v1/lifecycle alias).
func RegisterDeletionRoutes(mux *http.ServeMux, authority *auth.Service, deleter Deleter) {
	mux.HandleFunc("POST /api/v1/admin/deletions", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		if !credential.Fresh() {
			queryReply(w, nil, model.Fail(model.Forbidden))
			return
		}
		if nilDeleter(deleter) {
			writeJSON(w, http.StatusNotImplemented, DeletionNotAvailable{State: "not_available", Reason: ReasonDeletionNotWired})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, deletionBodyLimit)
		raw, err := io.ReadAll(r.Body)
		var body DeletionRequest
		if err != nil || model.StrictJSON(raw, &body) != nil {
			queryReply(w, nil, invalid("deletion_body_invalid"))
			return
		}
		req, err := deletionRequest(body)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		scope, err := authority.Authorize(r.Context(), credential, req.OrgID, nil, auth.OrgAdmin)
		if err == nil && scope.OrgID() != req.OrgID {
			err = model.Fail(model.NotFound)
		}
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		receipt, err := deleter.Delete(r.Context(), scope, req)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		view := deletionReceipt(receipt)
		switch receipt.Phase {
		case model.DeletePhaseFencing:
			writeJSON(w, http.StatusAccepted, view)
		case model.DeletePhaseComplete:
			writeJSON(w, http.StatusOK, view)
		case model.DeletePhaseHeld:
			writeJSON(w, http.StatusConflict, DeletionRefused{Code: string(model.Conflict), Detail: DetailDeletionHeld, Receipt: view, RequestID: w.Header().Get("X-Request-ID")})
		case model.DeletePhaseFailed:
			writeJSON(w, http.StatusConflict, DeletionRefused{Code: string(model.Conflict), Detail: DetailDeletionFailed, Receipt: view, RequestID: w.Header().Get("X-Request-ID")})
		default:
			queryReply(w, nil, model.Fail(model.Unavailable))
		}
	})
}
