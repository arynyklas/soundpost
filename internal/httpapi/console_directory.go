// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"net/http"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// MemberNameBody is the POST /api/v1/directory/names body.
type MemberNameBody struct {
	Org         model.ID `json:"org"`
	CommandID   model.ID `json:"command_id"`
	User        model.ID `json:"user"`
	DisplayName string   `json:"display_name"`
}

// MemberNameView answers a committed name change: the name is "set" or "cleared", never echoed.
type MemberNameView struct {
	User  model.ID `json:"user"`
	State string   `json:"state"`
}

// RegisterDirectoryRoutes mounts the display-name directory of the console
// (docs/operations/console-api.md, section 3):
//
//	POST /api/v1/directory        auth.DirectoryRequest -> auth.DirectoryView
//	POST /api/v1/directory/names  MemberNameBody        -> MemberNameView
//
// The credential is a browser session with the CSRF binding; the body names an organization the
// credential must belong to and nothing else about the caller.
func RegisterDirectoryRoutes(mux *http.ServeMux, authority *auth.Service) {
	mux.HandleFunc("POST /api/v1/directory", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body auth.DirectoryRequest
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		view, err := authority.Directory(r.Context(), credential, body)
		queryReply(w, view, err)
	})
	mux.HandleFunc("POST /api/v1/directory/names", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body MemberNameBody
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		if body.Org == (model.ID{}) || body.CommandID == (model.ID{}) || body.User == (model.ID{}) {
			queryReply(w, nil, invalid("directory_ids_required"))
			return
		}
		if body.DisplayName != "" && !auth.ValidMemberName(body.DisplayName) {
			queryReply(w, nil, invalid("display_name_invalid"))
			return
		}
		_, err = authority.SetMemberName(r.Context(), credential, auth.MemberNameCommand{CommandID: body.CommandID, Org: body.Org, User: body.User, DisplayName: body.DisplayName})
		state := "set"
		if body.DisplayName == "" {
			state = "cleared"
		}
		queryReply(w, MemberNameView{User: body.User, State: state}, err)
	})
}
