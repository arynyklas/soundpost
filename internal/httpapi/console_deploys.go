// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"net/http"
	"slices"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// DeployBody is the POST /api/v1/releases/deploys body (docs/operations/console-api.md, section 7).
// Op "record" needs Project, Release, Environment and CommandID; op "list" needs Projects.
type DeployBody struct {
	Op          string       `json:"op"`
	Org         model.ID     `json:"org"`
	CommandID   model.ID     `json:"command_id"`
	Project     model.ID     `json:"project"`
	Projects    []model.ID   `json:"projects"`
	Release     model.ID     `json:"release"`
	Environment model.ID     `json:"environment"`
	DeployedAt  *model.Int64 `json:"deployed_at"`
}

// DeployListView answers op "list".
type DeployListView struct {
	Org      model.ID          `json:"org"`
	Projects []model.ID        `json:"projects"`
	Items    []auth.DeployItem `json:"items"`
}

func distinctProjects(projects []model.ID, limit int) error {
	if len(projects) == 0 || len(projects) > limit {
		return invalid("projects_invalid")
	}
	for i, p := range projects {
		if p == (model.ID{}) || slices.Contains(projects[:i], p) {
			return invalid("projects_invalid")
		}
	}
	return nil
}

// releaseWriterScope is the scope of a release registration or deploy record: an organization administrator's, or, for a
// server token, the one derived from its release.write grant (auth.AuthorizeRelease). A token never holds org.admin.
func releaseWriterScope(ctx context.Context, authority *auth.Service, c auth.Credential, org, project model.ID) (auth.Scope, error) {
	if c.IsServerToken() {
		return authority.AuthorizeRelease(ctx, c, org, project, auth.OrgAdmin)
	}
	return authority.Authorize(ctx, c, org, []model.ID{project}, auth.OrgAdmin)
}

// artifactWriterScope is the scope of a source-map upload: the existing artifacts.write gate first; a server token that
// does not pass it may use release.write instead, for a public source map only (no source content), under the same
// artifact policy.
func artifactWriterScope(ctx context.Context, authority *auth.Service, c auth.Credential, org, project model.ID, sourceContent bool) (auth.Scope, error) {
	scope, err := authority.Authorize(ctx, c, org, []model.ID{project}, auth.ArtifactWrite)
	if err == nil || !c.IsServerToken() || sourceContent || !faultIs(err, model.NotFound) {
		return scope, err
	}
	if released, e := authority.AuthorizeRelease(ctx, c, org, project, auth.ArtifactWrite); e == nil {
		return released, nil
	}
	return scope, err
}

// RegisterDeployRoutes mounts the deploy markers:
//
//	POST /api/v1/releases/deploys  DeployBody -> auth.DeployItem (record) | DeployListView (list)
//
// record needs organization administration of the project or, for a server token, release.write on it (the rule of
// /api/v1/releases/register); list is a reader's.
func RegisterDeployRoutes(mux *http.ServeMux, authority *auth.Service) {
	mux.HandleFunc("POST /api/v1/releases/deploys", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body DeployBody
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		if body.Org == (model.ID{}) {
			queryReply(w, nil, invalid("deploy_ids_required"))
			return
		}
		switch body.Op {
		case "record":
			if body.Project == (model.ID{}) || body.Release == (model.ID{}) || body.Environment == (model.ID{}) || body.CommandID == (model.ID{}) || len(body.Projects) != 0 {
				queryReply(w, nil, invalid("deploy_ids_required"))
				return
			}
			var at int64
			if body.DeployedAt != nil {
				if at = int64(*body.DeployedAt); at <= 0 {
					queryReply(w, nil, invalid(auth.DeployTimeInvalid))
					return
				}
			}
			scope, err := releaseWriterScope(r.Context(), authority, credential, body.Org, body.Project)
			if err != nil {
				queryReply(w, nil, err)
				return
			}
			item, err := authority.RecordDeploy(r.Context(), scope, auth.DeployRecord{CommandID: body.CommandID, Org: body.Org, Project: body.Project, Release: body.Release, Environment: body.Environment, DeployedAt: at})
			if err == nil {
				err = authority.Revalidate(r.Context(), scope)
			}
			queryReply(w, item, err)
		case "list":
			if body.Project != (model.ID{}) || body.Environment != (model.ID{}) || body.DeployedAt != nil || body.CommandID != (model.ID{}) {
				queryReply(w, nil, invalid("deploy_list_fields"))
				return
			}
			if err = distinctProjects(body.Projects, auth.MaxDeployListProjects); err != nil {
				queryReply(w, nil, err)
				return
			}
			scope, err := readScope(r.Context(), authority, credential, body.Org, body.Projects)
			if err != nil {
				queryReply(w, nil, err)
				return
			}
			items, err := authority.ListDeploys(r.Context(), scope, body.Projects, body.Release)
			if err == nil {
				err = authority.Revalidate(r.Context(), scope)
			}
			if items == nil {
				items = []auth.DeployItem{}
			}
			queryReply(w, DeployListView{Org: body.Org, Projects: body.Projects, Items: items}, err)
		default:
			queryReply(w, nil, invalid("deploy_op_unknown"))
		}
	})
}
