//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
)

type deleteOutcome struct {
	Phase              string
	FenceUnreadable    bool
	Completed          bool
	GenerationAdvanced bool
}

// deleteProfile runs the product's own profile deletion: an entity deletion of
// the profile root, begun by the organization administrator through
// retention.Service.Delete (the C11 operation the /api/v1/admin/deletions route
// delegates to), then driven to completion by the retention worker's pass. The
// fence check runs between the two: the deletion has begun and the erasure has
// not, and the profile must already be unreadable.
func deleteProfile(ctx context.Context, app *appcore.App, admin auth.Credential, cfg privateConfig, root model.ID, unreadable func() (bool, error)) (deleteOutcome, error) {
	var out deleteOutcome
	scope, e := app.Auth.Authorize(ctx, admin, cfg.Org, nil, auth.OrgAdmin)
	if e != nil {
		return out, errors.New("fixture_deletion_authority_denied")
	}
	before, e := app.Retention.DeleteGeneration(ctx, cfg.Org, []model.ID{cfg.Project})
	if e != nil {
		return out, errors.New("fixture_deletion_generation_unavailable")
	}
	var revision model.Revision
	if e = app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); e != nil {
		return out, errors.New("fixture_control_revision_unavailable")
	}
	begun, e := app.Retention.Delete(ctx, scope, retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: revision, Mode: model.DeleteEntity, OrgID: cfg.Org, ProjectIDs: []model.ID{cfg.Project}, Signals: []model.Kind{model.Profile}, EntityIDs: []model.ID{root}, Reason: "disposable native export fixture profile deletion"})
	if e != nil {
		return out, errors.New("real_profile_deletion_refused")
	}
	out.Phase = begun.Phase
	if begun.Phase != model.DeletePhaseFencing {
		return out, errors.New("real_profile_deletion_not_fencing")
	}
	gone, e := unreadable()
	if e != nil {
		return out, e
	}
	out.FenceUnreadable = gone
	var done retention.DeleteReceipt
	for range 16 {
		if e = app.Retention.RunOnce(ctx); e != nil {
			return out, errors.New("real_profile_deletion_worker_failed")
		}
		if done, e = app.Retention.PollDelete(ctx, scope, begun.OperationID); e != nil {
			return out, errors.New("real_profile_deletion_poll_failed")
		}
		if done.Phase == model.DeletePhaseComplete && done.Physical == retention.PhysicalDone {
			break
		}
	}
	out.Phase = done.Phase
	out.Completed = done.Phase == model.DeletePhaseComplete && done.Physical == retention.PhysicalDone
	after, e := app.Retention.DeleteGeneration(ctx, cfg.Org, []model.ID{cfg.Project})
	if e != nil {
		return out, errors.New("fixture_deletion_generation_unavailable")
	}
	out.GenerationAdvanced = after > before
	return out, nil
}

// postSourceBatch posts one batch to the real POST /ingest/v1/batches route
// (gzip, bearer source credential) over the verified client.
func postSourceBatch(ctx context.Context, client *http.Client, endpoint, sourceKey string, b model.Batch) (int, []byte, error) {
	wire, e := json.Marshal(b)
	if e != nil {
		return 0, nil, e
	}
	var z bytes.Buffer
	w := gzip.NewWriter(&z)
	if _, e = w.Write(wire); e != nil {
		return 0, nil, e
	}
	if e = w.Close(); e != nil {
		return 0, nil, e
	}
	request, e := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/ingest/v1/batches", &z)
	if e != nil {
		return 0, nil, errors.New("fixture_batch_request_invalid")
	}
	request.Header.Set("Authorization", "Bearer "+sourceKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-Encoding", "gzip")
	response, e := client.Do(request)
	if e != nil {
		return 0, nil, errors.New("verified_tls_batch_route_unavailable")
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if e != nil || len(body) > 64<<10 {
		return response.StatusCode, nil, errors.New("batch_route_response_unreadable")
	}
	return response.StatusCode, body, nil
}
