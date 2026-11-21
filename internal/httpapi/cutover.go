// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"net/http"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// This file is the read-only cutover surface (POST /api/v1/cutover): who owns a
// project's normal notifications (the committed ownership-cutover phase, its
// sanitized timeline, source frontier and restore acknowledgement), what the
// product decided while it only watched (the shadow decisions, each with its stable
// delivery ID so a legacy decision stream can be compared decision by decision),
// the delivery accounting, and the boundary between the legacy owner's read-only
// history and the product's (docs/operations/notification-cutover.md). It is one
// consistent snapshot of committed control state (control.CutoverViewOf); it
// changes nothing, carries no operator text, evidence payload, endpoint or secret,
// and the cutover itself is still advanced only by the operator flow
// (notify.CutoverService.AdvanceCutover).

// CutoverRequest is the closed POST /api/v1/cutover body. Org and Project are
// selectors authorization confirms.
type CutoverRequest struct {
	Org     model.ID `json:"org"`
	Project model.ID `json:"project_id"`
}

func registerCutoverRoutes(mux *http.ServeMux, authority *auth.Service, policies *Policies) {
	mux.HandleFunc("POST /api/v1/cutover", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body CutoverRequest
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		if body.Org == (model.ID{}) || body.Project == (model.ID{}) {
			queryReply(w, nil, invalid("cutover_request_invalid"))
			return
		}
		scope, err := authority.AuthorizeWrite(r.Context(), credential, body.Org, body.Project, auth.PolicyWrite)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var view control.CutoverView
		err = policies.directory.View(r.Context(), func(st control.State) error {
			var e error
			view, e = control.CutoverViewOf(st, scope, body.Project, model.UnixNano(time.Now().UnixNano()))
			return e
		})
		if err == nil {
			err = authority.Revalidate(r.Context(), scope)
		}
		queryReply(w, view, err)
	})
}
