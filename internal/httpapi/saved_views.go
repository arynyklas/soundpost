// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"errors"
	"io"
	"net/http"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// This file is the C11 saved-view route: the project-owned list, save and
// delete of saved queries (internal/auth/saved_views.go owns the authorization,
// internal/control/saved_views.go the commit).
//
//	POST /api/v1/saved-views   SavedViewBody -> SavedViewList | SavedViewCommitted
//
// A query text can hold sensitive literals, so the route is POST-only with a JSON
// body (a URL carries nothing: a request with a query string is refused), a
// view is stored only by an explicit save, and every answer follows the project:
// whoever currently reads the project lists its views; a wrong organization, a
// project the caller cannot read, a revoked reader and an absent view are the
// same not-found. The caller is the session's (or bearer's) own principal and the
// scope is derived from its credential: no body field names an owner, an actor
// or a time. Failures are typed (queryReply): 400 invalid, 403 for a reader who
// may not change a view they can see, 404, 409 for a stale revision or a command
// ID that committed something else, 413 past a bound, 429 for the per-project
// cap.

const maxSavedViewBody = 128 << 10

// The state of a saved-view answer: a listing is ready or empty, a save or a
// delete is committed.
const StateCommitted ViewState = "committed"

// SavedViewBody is the POST /api/v1/saved-views body.
//
//   - list:   org, project.
//   - save:   org, project, command_id, the view fields (name, language, profile,
//     feature_set, expression, projects, mode, step_seconds?, allow_partial,
//     log_limit?, log_order?) and, to update a view, its id and
//     expected_revision (both together; neither to create one).
//   - delete: org, project, command_id, id, expected_revision.
//
// Org and Project are selectors authorization confirms; Project owns the view
// and must be one of Projects. The integers (step_seconds, log_limit,
// expected_revision) are decimal strings like every 64-bit integer on the API.
type SavedViewBody struct {
	Org              model.ID        `json:"org"`
	Project          model.ID        `json:"project"`
	Operation        string          `json:"operation"`
	CommandID        *model.ID       `json:"command_id,omitempty"`
	ID               *model.ID       `json:"id,omitempty"`
	ExpectedRevision *model.Revision `json:"expected_revision,omitempty"`
	auth.SavedViewSpec
}

// SavedViewList answers a list: State is ready, or empty when the project has no
// view. Views are oldest first (created_ns, then id).
type SavedViewList struct {
	State ViewState        `json:"state"`
	Views []auth.SavedView `json:"views"`
}

// SavedViewCommitted answers a save or a delete. Revision is the view's
// revision after the command (for a delete, the revision it removed plus one);
// View is the view as committed, absent for a delete and for a replayed command
// whose view has been changed or removed since.
type SavedViewCommitted struct {
	State    ViewState       `json:"state"`
	View     *auth.SavedView `json:"view,omitempty"`
	Revision model.Revision  `json:"revision"`
}

// decodeSavedViewBody reads the body whole under its own cap (an expression of
// the largest allowed size can be several times larger once JSON-escaped) and
// decodes it strictly: unknown fields, duplicate keys and trailing data are
// refused. A body past the cap is too large, not a malformed one.
func decodeSavedViewBody(w http.ResponseWriter, r *http.Request) (SavedViewBody, error) {
	var body SavedViewBody
	if r.URL.RawQuery != "" {
		return body, model.Fail(model.Invalid)
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSavedViewBody)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			return body, model.Fail(model.TooLarge)
		}
		return body, model.Fail(model.Invalid)
	}
	if model.StrictJSON(raw, &body) != nil {
		return body, model.Fail(model.Invalid)
	}
	return body, nil
}

func revisionOrZero(r *model.Revision) model.Revision {
	if r == nil {
		return 0
	}
	return *r
}

func registerSavedViews(mux *http.ServeMux, authority *auth.Service) {
	// The handler is installed on the control store here, so mounting the route is
	// the whole wiring. A store that cannot commit saved views still lists.
	bound := authority.BindSavedViews()
	mux.HandleFunc("POST /api/v1/saved-views", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		body, err := decodeSavedViewBody(w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		switch body.Operation {
		case auth.SavedViewOpList:
			if body.CommandID != nil || body.ID != nil || body.ExpectedRevision != nil || !body.SavedViewSpec.IsZero() {
				queryReply(w, nil, model.Fail(model.Invalid))
				return
			}
			views, err := authority.ListSavedViews(r.Context(), credential, body.Org, body.Project)
			if err != nil {
				queryReply(w, nil, err)
				return
			}
			out := SavedViewList{State: StateReady, Views: views}
			if len(views) == 0 {
				out.State = StateEmpty
			}
			queryReply(w, out, nil)
		case auth.SavedViewOpSave:
			// An update names its view and its revision together; a create names neither.
			if body.CommandID == nil || (body.ID == nil) != (body.ExpectedRevision == nil) {
				queryReply(w, nil, model.Fail(model.Invalid))
				return
			}
			if bound != nil {
				queryReply(w, nil, bound)
				return
			}
			res, err := authority.SaveSavedView(r.Context(), credential, auth.SavedViewSave{Org: body.Org, Project: body.Project, CommandID: *body.CommandID,
				ID: idOrZero(body.ID), ExpectedRevision: revisionOrZero(body.ExpectedRevision), Spec: body.SavedViewSpec})
			if err != nil {
				queryReply(w, nil, err)
				return
			}
			queryReply(w, SavedViewCommitted{State: StateCommitted, View: res.View, Revision: res.Revision}, nil)
		case auth.SavedViewOpDelete:
			if body.CommandID == nil || body.ID == nil || body.ExpectedRevision == nil || !body.SavedViewSpec.IsZero() {
				queryReply(w, nil, model.Fail(model.Invalid))
				return
			}
			if bound != nil {
				queryReply(w, nil, bound)
				return
			}
			res, err := authority.DeleteSavedView(r.Context(), credential, auth.SavedViewDelete{Org: body.Org, Project: body.Project, CommandID: *body.CommandID, ID: *body.ID, ExpectedRevision: *body.ExpectedRevision})
			if err != nil {
				queryReply(w, nil, err)
				return
			}
			queryReply(w, SavedViewCommitted{State: StateCommitted, Revision: res.Revision}, nil)
		default:
			queryReply(w, nil, model.Fail(model.Invalid))
		}
	})
}
