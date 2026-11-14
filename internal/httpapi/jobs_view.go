// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"bytes"
	"context"
	"math"
	"net/http"
	"sort"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
)

// This file is the C11 job view of the investigation UI: the project job
// listing and the job / run / attempt read over the committed durable job
// books (internal/jobs, internal/control).
//
// Authority. The scope is derived from the caller's credential, never from the
// body: the body names an organization and a project as SELECTORS that
// authorization confirms, and any other field (a permission, an elevation, a
// project list, a source) is refused as unknown. Reads need telemetry.read on
// the project, the permission jobs.Service reads under, and every view reports
// it. A wrong organization, a project the caller does not hold, a guessed
// project, a caller without the grant and an unknown job or run are the same
// not-found. A job service that is not wired, or a store that cannot be read,
// is an explicit not_available state, never an empty success.
//
// Content. Only what the committed job state holds leaves this file: IDs,
// ordinals, times, states, hashes, closed reason codes, and the operator-written
// correction reason (already bounded and validated by the control store). Trace
// and error causes are IDs only; their content is resolved by their own
// scope-checked views and is never embedded. The job's current health, a run's
// recovery and producer loss are three separate fields: none is derived from
// another here.

// JobsReadPermission is the grant the job reads need and report.
const JobsReadPermission = auth.Read

// Reason codes of the job views.
const (
	ReasonJobServiceNotWired    = "job_service_not_wired"
	ReasonJobStoreNotReadable   = "job_store_not_readable"
	ReasonJobNoJobs             = "no_jobs"
	ReasonJobHistoryErased      = "job_history_erased"
	ReasonJobEvidenceIncomplete = "job_evidence_incomplete"
	ReasonJobObserverStale      = "schedule_observer_stale"
	ReasonJobNoObserver         = "no_schedule_observer"
	ReasonJobLossRecorded       = "evidence_loss_recorded"
)

// Bounds. A page, a run list and the loss list may only be as large as these.
const (
	DefaultJobsPage = 25
	MaxJobsPage     = 50
	DefaultJobRuns  = 25
	MaxJobRuns      = 100
	maxOverlapIDs   = 8
	maxLossShown    = 64
)

// JobReader is the narrow consumer-owned seam over jobs.Service reads.
type JobReader interface {
	List(ctx context.Context, scope auth.Scope, project, after model.ID, limit int) (jobs.ListPage, error)
	View(ctx context.Context, scope auth.Scope, project, job model.ID) (jobs.View, error)
}

// Jobs is the handler behind POST /api/v1/jobs/list and /api/v1/jobs/view. The
// reader may be nil.
type Jobs struct{ reader JobReader }

// NewJobs binds the optional job reader. A nil *jobs.Service is not a reader.
func NewJobs(reader JobReader) *Jobs {
	if s, ok := reader.(*jobs.Service); ok && s == nil {
		reader = nil
	}
	return &Jobs{reader: reader}
}

// JobsListBody is the POST /api/v1/jobs/list body. Org and Project are
// selectors authorization confirms. After is the job ID the previous page
// ended with (absent: the first page). Limit is 1..MaxJobsPage (absent:
// DefaultJobsPage).
type JobsListBody struct {
	Org     model.ID `json:"org"`
	Project model.ID `json:"project"`
	After   model.ID `json:"after,omitempty"`
	Limit   int      `json:"limit,omitempty"`
}

// JobViewBody is the POST /api/v1/jobs/view body. Run, when present, selects
// one run whose attempts are returned in full. RunsLimit is 1..MaxJobRuns
// (absent: DefaultJobRuns) and bounds the run summaries.
type JobViewBody struct {
	Org       model.ID `json:"org"`
	Project   model.ID `json:"project"`
	Job       model.ID `json:"job"`
	Run       model.ID `json:"run,omitempty"`
	RunsLimit int      `json:"runs_limit,omitempty"`
}

// Truncation is the typed indicator that a list is shorter than the data.
type Truncation struct {
	Reason string    `json:"reason"` // page_limit | runs_limit | loss_limit
	Shown  int       `json:"shown"`
	Total  *int      `json:"total,omitempty"`
	Next   *model.ID `json:"next,omitempty"`
}

// JobSummaryView is one listed job.
type JobSummaryView struct {
	Job        model.ID         `json:"job"`
	Version    model.Revision   `json:"version"`
	Erased     bool             `json:"erased"`
	Definition *jobs.Definition `json:"definition,omitempty"`
	Health     jobs.Health      `json:"health"`
	Runs       int              `json:"runs"`
	Attempts   int              `json:"attempts"`
}

// JobsListView answers a listing.
type JobsListView struct {
	Org         model.ID         `json:"org"`
	Project     model.ID         `json:"project"`
	State       ViewState        `json:"state"`
	Reason      string           `json:"reason,omitempty"`
	Permission  string           `json:"permission"`
	EvaluatedAt model.UnixNano   `json:"evaluated_at_ns,omitempty"`
	Jobs        []JobSummaryView `json:"jobs"`
	More        bool             `json:"more"`
	Truncation  *Truncation      `json:"truncation,omitempty"`
	Sections    []ViewSection    `json:"sections"`
}

// OccurrenceView names the schedule occurrence a run belongs to. Fold is 1 for
// the second instance of a local time that occurred twice (clock moved back).
type OccurrenceView struct {
	Key       string          `json:"key"`
	Scheduled bool            `json:"scheduled"`
	At        *model.UnixNano `json:"at_ns,omitempty"`
	Fold      uint8           `json:"fold"`
}

// RunView is one run. Recovery (Status recovered / Recovered) describes this
// run's attempts only; whether the run is what the job's CURRENT health rests
// on is BasisOfHealth, and a newer occurrence is SupersededBy.
type RunView struct {
	ID             model.ID       `json:"id"`
	Occurrence     OccurrenceView `json:"occurrence"`
	Status         jobs.RunStatus `json:"status"`
	Recovered      bool           `json:"recovered"`
	FirstStarted   model.UnixNano `json:"first_started_ns"`
	FinalAttempt   model.ID       `json:"final_attempt"`
	AttemptCount   int            `json:"attempt_count"`
	FailedAttempts int            `json:"failed_attempts"`
	BasisOfHealth  bool           `json:"basis_of_health"`
	SupersededBy   string         `json:"superseded_by,omitempty"`
	Overlaps       []model.ID     `json:"overlaps"`
	OverlapCount   int            `json:"overlap_count"`
}

// AttemptView is one immutable attempt. Terminal is the original terminal fact;
// Effective is the result as of the newest correction.
type AttemptView struct {
	ID             model.ID                 `json:"id"`
	Ordinal        model.Uint64             `json:"ordinal"`
	Started        bool                     `json:"started"`
	ObservedAt     model.UnixNano           `json:"observed_ns"`
	Terminal       *jobs.TerminalResult     `json:"terminal,omitempty"`
	Effective      jobs.AttemptState        `json:"effective"`
	Corrections    []jobs.AppliedCorrection `json:"corrections"`
	EventsAccepted int                      `json:"events_accepted"`
	CauseTrace     *model.ID                `json:"cause_trace,omitempty"`
	CauseError     *model.ID                `json:"cause_error,omitempty"`
	Final          bool                     `json:"final"`
	// AfterNewerOccurrence is true when the attempt's terminal time is not before
	// the start of a newer occurrence than its own run's.
	AfterNewerOccurrence bool `json:"after_newer_occurrence"`
}

// RunDetail is a selected run with every attempt.
type RunDetail struct {
	RunView
	Attempts []AttemptView `json:"attempts"`
}

// JobSourceView is the committed source of the view: the job state version and the
// origin cursor of the newest attempt evidence applied (absent when none).
type JobSourceView struct {
	Version model.Revision `json:"version"`
	Cursor  *model.Cursor  `json:"cursor,omitempty"`
}

// ObserverView is the expected-schedule observer freshness. State is none (no
// external observer ever spoke), fresh, stale or unhealthy; ExpectedSchedule is
// whether the job has calendar expectations at all. Without an external
// observer a scheduled job is never missed: its health is unknown.
type ObserverView struct {
	State            string                 `json:"state"`
	ExpectedSchedule bool                   `json:"expected_schedule"`
	Evidence         *jobs.ObserverEvidence `json:"evidence,omitempty"`
}

// LossView is producer / evidence loss, separate from the job outcome.
// AffectsCurrentHealth is true when a declared loss interval overlaps the
// evidence the current health rests on.
type LossView struct {
	Intervals            []jobs.Interval `json:"intervals"`
	Total                int             `json:"total"`
	AffectsCurrentHealth bool            `json:"affects_current_health"`
	Truncation           *Truncation     `json:"truncation,omitempty"`
}

// JobView answers a job request.
type JobView struct {
	Org                 model.ID         `json:"org"`
	Project             model.ID         `json:"project"`
	Job                 model.ID         `json:"job"`
	State               ViewState        `json:"state"`
	Reason              string           `json:"reason,omitempty"`
	Permission          string           `json:"permission"`
	EvaluatedAt         model.UnixNano   `json:"evaluated_at_ns,omitempty"`
	Source              *JobSourceView   `json:"source,omitempty"`
	Erased              bool             `json:"erased"`
	Definition          *jobs.Definition `json:"definition,omitempty"`
	DefinitionRevisions int              `json:"definition_revisions"`
	Health              *jobs.Health     `json:"health,omitempty"`
	Observer            *ObserverView    `json:"observer,omitempty"`
	Loss                *LossView        `json:"loss,omitempty"`
	TotalRuns           int              `json:"total_runs"`
	TotalAttempts       int              `json:"total_attempts"`
	Compaction          *jobs.Compaction `json:"compaction,omitempty"`
	LatestOccurrence    string           `json:"latest_occurrence,omitempty"`
	Runs                []RunView        `json:"runs"`
	RunsTruncation      *Truncation      `json:"runs_truncation,omitempty"`
	Run                 *RunDetail       `json:"run,omitempty"`
	Sections            []ViewSection    `json:"sections"`
}

func validJobsLimit(limit, def, max int) (int, error) {
	switch {
	case limit == 0:
		return def, nil
	case limit < 0 || limit > max:
		return 0, invalid("jobs_limit_invalid")
	}
	return limit, nil
}

func (j *Jobs) scoped(ctx context.Context, authority *auth.Service, credential auth.Credential, org, project model.ID) (auth.Scope, error) {
	if org == (model.ID{}) || project == (model.ID{}) {
		return auth.Scope{}, invalid("jobs_request_invalid")
	}
	scope, err := authority.Authorize(ctx, credential, org, []model.ID{project}, JobsReadPermission)
	if err != nil {
		return auth.Scope{}, err
	}
	if !scope.AllowsProject(project) {
		return auth.Scope{}, model.Fail(model.NotFound)
	}
	return scope, nil
}

func jobsListViewOf(body JobsListBody, state ViewState, reason string) JobsListView {
	return JobsListView{Org: body.Org, Project: body.Project, State: state, Reason: reason, Permission: string(JobsReadPermission), Jobs: []JobSummaryView{}, Sections: []ViewSection{{Name: "jobs", State: state, Reason: reason}}}
}

// List answers one page of a project's jobs under the caller's own authority.
func (j *Jobs) List(ctx context.Context, authority *auth.Service, credential auth.Credential, body JobsListBody) (JobsListView, auth.Scope, error) {
	limit, err := validJobsLimit(body.Limit, DefaultJobsPage, MaxJobsPage)
	if err != nil {
		return JobsListView{}, auth.Scope{}, err
	}
	scope, err := j.scoped(ctx, authority, credential, body.Org, body.Project)
	if err != nil {
		return JobsListView{}, auth.Scope{}, err
	}
	if j == nil || j.reader == nil {
		return jobsListViewOf(body, StateNotAvailable, ReasonJobServiceNotWired), scope, nil
	}
	page, err := j.reader.List(ctx, scope, body.Project, body.After, limit)
	if faultCodeOf(err) == model.Unsupported && err != nil {
		return jobsListViewOf(body, StateNotAvailable, ReasonJobStoreNotReadable), scope, nil
	}
	if err != nil {
		return JobsListView{}, auth.Scope{}, err
	}
	view := jobsListViewOf(body, StateReady, "")
	view.EvaluatedAt = page.EvaluatedAt
	for _, s := range page.Jobs {
		sum := JobSummaryView{Job: s.Job, Version: s.Version, Erased: s.Erased, Health: s.Health, Runs: s.Runs, Attempts: s.Attempts}
		if s.Definition.Revision != 0 {
			definition := s.Definition
			sum.Definition = &definition
		}
		view.Jobs = append(view.Jobs, sum)
	}
	if len(view.Jobs) == 0 {
		view.State, view.Reason = StateEmpty, ReasonJobNoJobs
		view.Sections[0] = ViewSection{Name: "jobs", State: StateEmpty, Reason: ReasonJobNoJobs}
		return view, scope, nil
	}
	if page.More {
		next := view.Jobs[len(view.Jobs)-1].Job
		view.More = true
		view.Truncation = &Truncation{Reason: "page_limit", Shown: len(view.Jobs), Next: &next}
	}
	return view, scope, nil
}

func jobViewOf(body JobViewBody, state ViewState, reason string) JobView {
	return JobView{Org: body.Org, Project: body.Project, Job: body.Job, State: state, Reason: reason, Permission: string(JobsReadPermission), Runs: []RunView{}, Sections: []ViewSection{{Name: "job", State: state, Reason: reason}}}
}

func observerOf(h jobs.Health, scheduled bool) ObserverView {
	o := ObserverView{State: "none", ExpectedSchedule: scheduled, Evidence: h.Evidence.Observer}
	if e := h.Evidence.Observer; e != nil {
		switch {
		case !e.Healthy:
			o.State = "unhealthy"
		case e.Stale:
			o.State = "stale"
		default:
			o.State = "fresh"
		}
	}
	return o
}

// runSpans is each retained run's [start, end) in event time; a run whose final
// attempt has no result is open-ended.
func runSpans(st jobs.JobState) map[model.ID][2]model.UnixNano {
	out := make(map[model.ID][2]model.UnixNano, len(st.Runs))
	for id, run := range st.Runs {
		start, end := run.Started, model.UnixNano(math.MaxInt64)
		if final, ok := st.Attempts[run.Final]; ok && final.Effective() != jobs.AttemptStarted && final.Terminal != nil {
			end = final.Terminal.At
		}
		if end < start {
			end = start
		}
		out[id] = [2]model.UnixNano{start, end}
	}
	return out
}

func occurrenceOf(st jobs.JobState, key string) OccurrenceView {
	o := OccurrenceView{Key: key}
	if occ, ok := st.Occurrences[key]; ok && occ.Scheduled {
		at := occ.At
		o.Scheduled, o.At = true, &at
	}
	if _, fold, _, ok := jobs.ParseOccurrenceKey(key); ok {
		o.Fold = fold
	}
	return o
}

func runViewOf(st jobs.JobState, run jobs.Run, health jobs.Health, spans map[model.ID][2]model.UnixNano) RunView {
	v := RunView{ID: run.ID, Occurrence: occurrenceOf(st, run.Occurrence), Status: run.Status, Recovered: run.Recovered, FirstStarted: run.Started, FinalAttempt: run.Final, AttemptCount: len(run.Attempts), Overlaps: []model.ID{}}
	for _, id := range run.Attempts {
		if a, ok := st.Attempts[id]; ok && a.Effective() == jobs.AttemptFailed {
			v.FailedAttempts++
		}
	}
	v.BasisOfHealth = health.Evidence.Run != nil && *health.Evidence.Run == run.ID
	if st.LatestScheduleKey != "" && run.Occurrence != st.LatestScheduleKey {
		v.SupersededBy = st.LatestScheduleKey
	}
	mine := spans[run.ID]
	var others []model.ID
	for id, other := range spans {
		if id != run.ID && mine[0] < other[1] && other[0] < mine[1] {
			others = append(others, id)
		}
	}
	sort.Slice(others, func(i, k int) bool { return bytes.Compare(others[i][:], others[k][:]) < 0 })
	v.OverlapCount = len(others)
	if len(others) > maxOverlapIDs {
		others = others[:maxOverlapIDs]
	}
	v.Overlaps = append(v.Overlaps, others...)
	return v
}

func attemptViewOf(st jobs.JobState, run jobs.Run, a jobs.Attempt) AttemptView {
	v := AttemptView{ID: a.ID, Ordinal: a.Ordinal, Started: a.Started, ObservedAt: a.Observed, Terminal: a.Terminal, Effective: a.Effective(), Corrections: a.Corrections, EventsAccepted: len(a.Events), CauseTrace: a.CauseTrace, CauseError: a.CauseError, Final: a.ID == run.Final}
	if v.Corrections == nil {
		v.Corrections = []jobs.AppliedCorrection{}
	}
	if latest, ok := st.Occurrences[st.LatestScheduleKey]; ok && run.Occurrence != st.LatestScheduleKey && a.Terminal != nil {
		v.AfterNewerOccurrence = a.Terminal.At >= latest.Order
	}
	return v
}

// View reads one job, optionally one run, under the caller's own authority.
func (j *Jobs) View(ctx context.Context, authority *auth.Service, credential auth.Credential, body JobViewBody) (JobView, auth.Scope, error) {
	limit, err := validJobsLimit(body.RunsLimit, DefaultJobRuns, MaxJobRuns)
	if err != nil {
		return JobView{}, auth.Scope{}, err
	}
	if body.Job == (model.ID{}) {
		return JobView{}, auth.Scope{}, invalid("jobs_request_invalid")
	}
	scope, err := j.scoped(ctx, authority, credential, body.Org, body.Project)
	if err != nil {
		return JobView{}, auth.Scope{}, err
	}
	if j == nil || j.reader == nil {
		return jobViewOf(body, StateNotAvailable, ReasonJobServiceNotWired), scope, nil
	}
	read, err := j.reader.View(ctx, scope, body.Project, body.Job)
	if err != nil && faultCodeOf(err) == model.Unsupported {
		return jobViewOf(body, StateNotAvailable, ReasonJobStoreNotReadable), scope, nil
	}
	if err != nil {
		return JobView{}, auth.Scope{}, err
	}
	st, health := read.Report.State, read.Report.Health
	view := jobViewOf(body, StateReady, "")
	view.EvaluatedAt = read.Report.EvaluatedAt
	view.Source = &JobSourceView{Version: read.Report.Version, Cursor: read.Origin}
	view.Erased = read.Erased
	// A job that has only attempt evidence has no definition: say so by omitting it, never by a zero definition.
	if st.Definition.Revision != 0 {
		definition := st.Definition
		view.Definition, view.DefinitionRevisions = &definition, len(st.History)+1
	}
	view.Health = &health
	observer := observerOf(health, st.Definition.Schedule != nil)
	view.Observer = &observer
	view.TotalRuns, view.TotalAttempts = len(st.Runs), len(st.Attempts)
	compaction := st.Compaction
	view.Compaction = &compaction
	view.LatestOccurrence = st.LatestScheduleKey

	loss := LossView{Intervals: []jobs.Interval{}, Total: len(read.Report.Intervals), AffectsCurrentHealth: len(health.Evidence.Gaps) > 0}
	shown := read.Report.Intervals
	if len(shown) > maxLossShown {
		shown = shown[:maxLossShown]
		total := len(read.Report.Intervals)
		loss.Truncation = &Truncation{Reason: "loss_limit", Shown: maxLossShown, Total: &total}
	}
	loss.Intervals = append(loss.Intervals, shown...)
	view.Loss = &loss

	spans := runSpans(st)
	runs := make([]jobs.Run, 0, len(st.Runs))
	for _, r := range st.Runs {
		runs = append(runs, r)
	}
	sort.Slice(runs, func(a, b int) bool {
		oa, ob := st.Occurrences[runs[a].Occurrence].Order, st.Occurrences[runs[b].Occurrence].Order
		if oa != ob {
			return oa > ob
		}
		if runs[a].Started != runs[b].Started {
			return runs[a].Started > runs[b].Started
		}
		return bytes.Compare(runs[a].ID[:], runs[b].ID[:]) > 0
	})
	shownRuns := runs
	if len(shownRuns) > limit {
		shownRuns = shownRuns[:limit]
		total := len(runs)
		view.RunsTruncation = &Truncation{Reason: "runs_limit", Shown: limit, Total: &total}
	}
	for _, r := range shownRuns {
		view.Runs = append(view.Runs, runViewOf(st, r, health, spans))
	}
	if body.Run != (model.ID{}) {
		run, attempts, ok := st.RunAttempts(body.Run)
		if !ok {
			return JobView{}, auth.Scope{}, model.Fail(model.NotFound)
		}
		detail := RunDetail{RunView: runViewOf(st, run, health, spans), Attempts: make([]AttemptView, 0, len(attempts))}
		for _, a := range attempts {
			detail.Attempts = append(detail.Attempts, attemptViewOf(st, run, a))
		}
		view.Run = &detail
	}

	healthState, healthReason := StateReady, ""
	if !health.Complete {
		healthState, healthReason = StateIncomplete, ReasonJobEvidenceIncomplete
	}
	observerState, observerReason := StateReady, ""
	switch {
	case !observer.ExpectedSchedule:
	case observer.State == "none":
		observerState, observerReason = StateNotAvailable, ReasonJobNoObserver
	case observer.State == "stale" || observer.State == "unhealthy":
		observerState, observerReason = StateStale, ReasonJobObserverStale
	}
	lossState, lossReason := StateReady, ""
	if loss.Total > 0 {
		lossState, lossReason = StateIncomplete, ReasonJobLossRecorded
	}
	view.Sections = []ViewSection{
		{Name: "attempts", State: StateReady},
		{Name: "health", State: healthState, Reason: healthReason},
		{Name: "observer", State: observerState, Reason: observerReason},
		{Name: "loss", State: lossState, Reason: lossReason},
	}
	if read.Erased {
		view.State, view.Reason = StateEmpty, ReasonJobHistoryErased
		view.Sections[0] = ViewSection{Name: "attempts", State: StateEmpty, Reason: ReasonJobHistoryErased}
	} else if healthState != StateReady {
		view.State, view.Reason = healthState, healthReason
	}
	return view, scope, nil
}

// RegisterJobRoutes mounts the job views. Each route needs the CSRF binding of
// artifactCredential for a session caller and derives its scope from the
// caller's own credential; no body field names another principal's scope.
//
//	POST /api/v1/jobs/list  JobsListBody -> JobsListView
//	POST /api/v1/jobs/view  JobViewBody  -> JobView
func RegisterJobRoutes(mux *http.ServeMux, authority *auth.Service, j *Jobs) {
	mux.HandleFunc("POST /api/v1/jobs/list", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body JobsListBody
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		view, scope, err := j.List(r.Context(), authority, credential, body)
		if err == nil {
			err = authority.Revalidate(r.Context(), scope)
		}
		queryReply(w, view, err)
	})
	mux.HandleFunc("POST /api/v1/jobs/view", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body JobViewBody
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		view, scope, err := j.View(r.Context(), authority, credential, body)
		if err == nil {
			err = authority.Revalidate(r.Context(), scope)
		}
		queryReply(w, view, err)
	})
}
