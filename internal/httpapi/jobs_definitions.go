// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"net/http"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
)

// This file is the job schedule-definition authoring surface
// (POST /api/v1/jobs/definitions): list, save and retire the schedule
// definitions of one project's jobs, through the job catalogue (jobs.Catalogue)
// over control state.
//
// A save is the audited command of the catalogue: its command ID is replayed
// idempotently, the reason is recorded, the schedule is validated (cron, zone,
// grace) before anything is committed, the definition's revision must be the
// catalogue's next one (the previous definition's plus one, 1 for a new job) and
// expected_revision is the catalogue revision the author read (0 = the job is
// not in the catalogue yet), so a stale author loses with a conflict instead of
// overwriting. Saving and retiring need policy.write on the project, exactly
// like the other job mutations; listing needs telemetry.read. The background
// runner's observer stage feeds every non-retired definition to the job
// reducer, so a saved definition takes effect at the next pass and a retired
// one stops at it (docs/user/jobs.md).

// Job definition operations.
const (
	JobDefinitionList   = "list"
	JobDefinitionSave   = "save"
	JobDefinitionRetire = "retire"
)

// JobDefinitionRequest is the closed POST /api/v1/jobs/definitions body. A list
// carries only the selectors; a save carries command_id, job_id,
// expected_revision, reason and the definition; a retire the same without the
// definition.
type JobDefinitionRequest struct {
	Org              model.ID         `json:"org"`
	Project          model.ID         `json:"project_id"`
	Operation        string           `json:"operation"`
	CommandID        model.ID         `json:"command_id,omitempty"`
	JobID            model.ID         `json:"job_id,omitempty"`
	ExpectedRevision *model.Uint64    `json:"expected_revision,omitempty"`
	Reason           string           `json:"reason,omitempty"`
	Definition       *jobs.Definition `json:"definition,omitempty"`
}

// JobDefinitionView is one catalogue entry as the page shows it. Revision is the
// catalogue revision (the compare-and-set token); Definition.Revision is the
// definition's own.
type JobDefinitionView struct {
	JobID      model.ID        `json:"job_id"`
	Revision   model.Uint64    `json:"revision"`
	Retired    bool            `json:"retired"`
	CreatedNS  model.Int64     `json:"created_ns"`
	UpdatedNS  model.Int64     `json:"updated_ns"`
	Definition jobs.Definition `json:"definition"`
}

// JobDefinitionListAnswer is the answer to a list.
type JobDefinitionListAnswer struct {
	Org       model.ID            `json:"org"`
	Project   model.ID            `json:"project_id"`
	CanAuthor bool                `json:"can_author"`
	Jobs      []JobDefinitionView `json:"jobs"`
}

// JobDefinitionWriteAnswer is the answer to a committed save or retire: the
// entry as committed.
type JobDefinitionWriteAnswer struct {
	State ActionState       `json:"state"`
	Job   JobDefinitionView `json:"job"`
}

func jobDefinitionView(e jobs.Entry) JobDefinitionView {
	return JobDefinitionView{JobID: e.Job, Revision: model.Uint64(e.Revision), Retired: e.Retired, CreatedNS: model.Int64(e.CreatedNS), UpdatedNS: model.Int64(e.UpdatedNS), Definition: e.Definition}
}

func (p *Policies) jobCatalogue(authority *auth.Service) (*jobs.Catalogue, error) {
	store, ok := p.directory.(jobs.CatalogueControl)
	if !ok {
		return nil, model.Fail(model.Unavailable)
	}
	return jobs.NewCatalogue(store, jobs.WithCatalogueClock(func() model.UnixNano { return model.UnixNano(authority.Now().UnixNano()) }))
}

// validJobDefinitionShape checks the closed shape of each operation: exactly the
// fields the operation takes, none of the others.
func validJobDefinitionShape(b JobDefinitionRequest) bool {
	switch b.Operation {
	case JobDefinitionList:
		return b.CommandID == (model.ID{}) && b.JobID == (model.ID{}) && b.ExpectedRevision == nil && b.Reason == "" && b.Definition == nil
	case JobDefinitionSave:
		return b.CommandID != (model.ID{}) && b.JobID != (model.ID{}) && b.ExpectedRevision != nil && b.Reason != "" && b.Definition != nil
	case JobDefinitionRetire:
		return b.CommandID != (model.ID{}) && b.JobID != (model.ID{}) && b.ExpectedRevision != nil && b.Reason != "" && b.Definition == nil
	}
	return false
}

func registerJobDefinitionRoutes(mux *http.ServeMux, authority *auth.Service, policies *Policies) {
	mux.HandleFunc("POST /api/v1/jobs/definitions", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body JobDefinitionRequest
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		if body.Org == (model.ID{}) || body.Project == (model.ID{}) || !validJobDefinitionShape(body) {
			queryReply(w, nil, invalid("job_definition_request_invalid"))
			return
		}
		catalogue, err := policies.jobCatalogue(authority)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		if body.Operation == JobDefinitionList {
			scope, err := authority.Authorize(r.Context(), credential, body.Org, []model.ID{body.Project}, auth.Read)
			if err != nil {
				queryReply(w, nil, err)
				return
			}
			entries, err := catalogue.List(r.Context(), scope, body.Project)
			if err == nil {
				err = authority.Revalidate(r.Context(), scope)
			}
			if err != nil {
				queryReply(w, nil, err)
				return
			}
			answer := JobDefinitionListAnswer{Org: body.Org, Project: body.Project, Jobs: make([]JobDefinitionView, 0, len(entries))}
			// Whether the caller may author is what the page needs to offer the form;
			// the save itself is authorized again against the committed state.
			if _, aerr := authority.Authorize(r.Context(), credential, body.Org, []model.ID{body.Project}, auth.PolicyWrite); aerr == nil {
				answer.CanAuthor = true
			}
			for _, e := range entries {
				answer.Jobs = append(answer.Jobs, jobDefinitionView(e))
			}
			queryReply(w, answer, nil)
			return
		}
		scope, err := authority.Authorize(r.Context(), credential, body.Org, []model.ID{body.Project}, auth.PolicyWrite)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		if !scope.AllowsProject(body.Project) {
			queryReply(w, nil, model.Fail(model.NotFound))
			return
		}
		var entry jobs.Entry
		if body.Operation == JobDefinitionSave {
			entry, err = catalogue.Save(r.Context(), scope, jobs.SaveCommand{CommandID: body.CommandID, Project: body.Project, Job: body.JobID, ExpectedRevision: model.Revision(*body.ExpectedRevision),
				Definition: *body.Definition, Reason: body.Reason})
		} else {
			entry, err = catalogue.Retire(r.Context(), scope, jobs.RetireCommand{CommandID: body.CommandID, Project: body.Project, Job: body.JobID, ExpectedRevision: model.Revision(*body.ExpectedRevision), Reason: body.Reason})
		}
		if err == nil {
			err = authority.Revalidate(r.Context(), scope)
		}
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		queryReply(w, JobDefinitionWriteAnswer{State: ActionCommitted, Job: jobDefinitionView(entry)}, nil)
	})
}
