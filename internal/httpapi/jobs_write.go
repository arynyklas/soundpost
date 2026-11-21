// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"net/http"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
)

// This file is the write side of the job views: the external schedule observer's feed and the audited correction of
// a terminal attempt. Both need policy.write on the project (jobs.Service checks it again, on the scope this handler
// derives from the caller's own credential: a session with its CSRF binding, or a bearer token for the observer's
// service principal). The body names an organization and a project as SELECTORS that authorization confirms; the
// acting principal of a correction is the scope's, never a body field, and any unknown field is refused.

// JobWriter is the narrow consumer-owned seam over jobs.Service writes. NewJobs binds it when the reader also writes.
type JobWriter interface {
	ObserveSchedule(ctx context.Context, scope auth.Scope, evidence jobs.ScheduleEvidence) (jobs.JobState, error)
	Correct(ctx context.Context, scope auth.Scope, correction jobs.Correction) (jobs.JobState, error)
}

// ReasonJobWriteNotWired is the typed answer of a write when no job service is bound.
const ReasonJobWriteNotWired = ReasonJobServiceNotWired

// JobScheduleEvidenceBody is the POST /api/v1/jobs/schedule-evidence body: one observation of the external schedule
// observer. CompleteThrough attests the data path (source producing, ingest acknowledged, journal processed) for this
// job through that instant; it never exceeds ObservedAt. Incomplete lists the intervals the observer knows evidence is
// missing for. The command ID makes a retry idempotent.
type JobScheduleEvidenceBody struct {
	Org             model.ID         `json:"org"`
	Project         model.ID         `json:"project"`
	Job             model.ID         `json:"job"`
	CommandID       model.ID         `json:"command_id"`
	Observer        model.ID         `json:"observer"`
	ObservedAt      model.UnixNano   `json:"observed_ns"`
	CompleteThrough model.UnixNano   `json:"complete_through_ns"`
	Healthy         bool             `json:"healthy"`
	Definition      *jobs.Definition `json:"definition,omitempty"`
	Incomplete      []jobs.Interval  `json:"incomplete,omitempty"`
}

// JobCorrectionBody is the POST /api/v1/jobs/correct body: an audited, explicitly newer assertion about one terminal
// attempt. ExpectedVersion is the job source version the caller read (the view's source.version).
type JobCorrectionBody struct {
	Org             model.ID          `json:"org"`
	Project         model.ID          `json:"project"`
	Job             model.ID          `json:"job"`
	CommandID       model.ID          `json:"command_id"`
	ExpectedVersion model.Revision    `json:"expected_version"`
	Attempt         model.ID          `json:"attempt"`
	Version         model.Uint64      `json:"version"`
	State           jobs.AttemptState `json:"state"`
	Reason          string            `json:"reason"`
}

// JobWriteAnswer says a write committed and the job source version it produced.
type JobWriteAnswer struct {
	State   ActionState    `json:"state"`
	Job     model.ID       `json:"job"`
	Version model.Revision `json:"version"`
}

func (j *Jobs) writeScope(ctx context.Context, authority *auth.Service, credential auth.Credential, org, project, job, command model.ID) (auth.Scope, error) {
	if org == (model.ID{}) || project == (model.ID{}) || job == (model.ID{}) || command == (model.ID{}) {
		return auth.Scope{}, invalid("jobs_request_invalid")
	}
	scope, err := authority.Authorize(ctx, credential, org, []model.ID{project}, auth.PolicyWrite)
	if err != nil {
		return auth.Scope{}, err
	}
	if !scope.AllowsProject(project) {
		return auth.Scope{}, model.Fail(model.NotFound)
	}
	return scope, nil
}

// ObserveSchedule commits one schedule observation.
func (j *Jobs) ObserveSchedule(ctx context.Context, authority *auth.Service, credential auth.Credential, body JobScheduleEvidenceBody) (any, auth.Scope, error) {
	scope, err := j.writeScope(ctx, authority, credential, body.Org, body.Project, body.Job, body.CommandID)
	if err != nil {
		return nil, auth.Scope{}, err
	}
	if j == nil || j.writer == nil {
		return nil, auth.Scope{}, notWired()
	}
	if body.Observer == (model.ID{}) {
		return nil, auth.Scope{}, invalid("jobs_request_invalid")
	}
	state, err := j.writer.ObserveSchedule(ctx, scope, jobs.ScheduleEvidence{CommandID: body.CommandID, Project: body.Project, Job: body.Job, Observer: body.Observer, ObservedAt: body.ObservedAt,
		CompleteThrough: body.CompleteThrough, Healthy: body.Healthy, Definition: body.Definition, Incomplete: body.Incomplete})
	if err != nil {
		return nil, auth.Scope{}, err
	}
	return JobWriteAnswer{State: ActionCommitted, Job: body.Job, Version: state.Version}, scope, nil
}

// Correct commits one audited correction.
func (j *Jobs) Correct(ctx context.Context, authority *auth.Service, credential auth.Credential, body JobCorrectionBody) (any, auth.Scope, error) {
	scope, err := j.writeScope(ctx, authority, credential, body.Org, body.Project, body.Job, body.CommandID)
	if err != nil {
		return nil, auth.Scope{}, err
	}
	if j == nil || j.writer == nil {
		return nil, auth.Scope{}, notWired()
	}
	if body.Attempt == (model.ID{}) || body.Reason == "" {
		return nil, auth.Scope{}, invalid("jobs_request_invalid")
	}
	state, err := j.writer.Correct(ctx, scope, jobs.Correction{CommandID: body.CommandID, Project: body.Project, Job: body.Job, ExpectedVersion: body.ExpectedVersion,
		Attempt: body.Attempt, Version: body.Version, State: body.State, Reason: body.Reason})
	if err != nil {
		return nil, auth.Scope{}, err
	}
	return JobWriteAnswer{State: ActionCommitted, Job: body.Job, Version: state.Version}, scope, nil
}

// notWired is the typed refusal of a write when no job service is bound: a write that cannot happen is never a success.
func notWired() error {
	f := model.Fail(model.Unsupported)
	f.SafeDetail = ReasonJobWriteNotWired
	return f
}

// registerJobWriteRoutes mounts the two write routes beside the views.
//
//	POST /api/v1/jobs/schedule-evidence  JobScheduleEvidenceBody -> JobWriteAnswer
//	POST /api/v1/jobs/correct            JobCorrectionBody       -> JobWriteAnswer
func registerJobWriteRoutes(mux *http.ServeMux, authority *auth.Service, j *Jobs) {
	mux.HandleFunc("POST /api/v1/jobs/schedule-evidence", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body JobScheduleEvidenceBody
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		answer, scope, err := j.ObserveSchedule(r.Context(), authority, credential, body)
		if err == nil {
			err = authority.Revalidate(r.Context(), scope)
		}
		queryReply(w, answer, err)
	})
	mux.HandleFunc("POST /api/v1/jobs/correct", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body JobCorrectionBody
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		answer, scope, err := j.Correct(r.Context(), authority, credential, body)
		if err == nil {
			err = authority.Revalidate(r.Context(), scope)
		}
		queryReply(w, answer, err)
	})
}
