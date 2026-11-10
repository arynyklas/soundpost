// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/model"
)

// UpdateKind names the C05 UpdateJob transition an UpdateCommand carries.
type UpdateKind string

const (
	UpdateAttempt    UpdateKind = "attempt"
	UpdateSchedule   UpdateKind = "schedule"
	UpdateCorrection UpdateKind = "correction"
)

// maxRetries bounds optimistic-concurrency retries of one service call.
const maxRetries = 8

// MaxDefinitionLead bounds how far in the future a definition may take effect.
const MaxDefinitionLead = 400 * 24 * time.Hour

// Audit is the control audit a correction must commit atomically with the state.
type Audit struct {
	Principal model.ID
	Action    string
	Reason    string
	At        model.UnixNano
	Targets   []model.ID
}

// UpdateCommand is the consumer-owned shape of C05 UpdateJob. The reducer
// already ran outside deterministic apply; Next is the complete resulting state
// and the store installs it only if the stored version equals ExpectedVersion
// (and Next.Version == ExpectedVersion+1).
type UpdateCommand struct {
	CommandID       model.ID
	Kind            UpdateKind
	Project         model.ID
	Job             model.ID
	ExpectedVersion model.Revision
	// InputDigest binds CommandID to its input: the same command ID with a
	// different digest must fail with model.Conflict.
	InputDigest model.Hash
	Next        JobState
	// Origin is the data-group provenance of journal evidence (nil otherwise).
	Origin *model.Cursor
	// Audit is set for corrections.
	Audit *Audit
}

// UpdateResult is the committed outcome. Replayed means the command ID had
// already been applied and nothing changed now.
type UpdateResult struct {
	Version  model.Revision
	Replayed bool
}

// Store is the narrow consumer-owned persistence seam. A production binding
// is the C05 control store; none exists today (see docs/user/jobs.md).
type Store interface {
	// Load returns the committed state for exactly this org (from scope),
	// project and job. found=false means no state exists; it must be
	// indistinguishable from an out-of-scope target.
	Load(ctx context.Context, scope auth.Scope, project, job model.ID) (state JobState, found bool, err error)
	// Update atomically installs cmd.Next. A version mismatch is model.Stale; a
	// repeated CommandID is idempotent (Replayed) or model.Conflict when its
	// digest differs.
	Update(ctx context.Context, scope auth.Scope, cmd UpdateCommand) (UpdateResult, error)
	// Gaps returns committed RecordEvidenceGap facts visible to the scope's org
	// for the project.
	Gaps(ctx context.Context, scope auth.Scope, project model.ID) ([]model.EvidenceGap, error)
}

// Authorizer revalidates an opaque scope (satisfied by *auth.Service).
type Authorizer interface {
	Revalidate(context.Context, auth.Scope) error
}

// Clock supplies admission time outside deterministic reduction.
type Clock interface {
	Now() model.UnixNano
}

// Service applies job evidence and answers current-health reads. It holds no
// mutable state: every fact lives behind Store.
type Service struct {
	store      Store
	authorizer Authorizer
	clock      Clock
}

func New(store Store, authorizer Authorizer, clock Clock) (*Service, error) {
	if store == nil || authorizer == nil || clock == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &Service{store: store, authorizer: authorizer, clock: clock}, nil
}

// authorize revalidates the scope, requires the permission and requires the
// project to be one of the scope's. A project outside the scope is NotFound so
// it cannot be told apart from a project or job that does not exist.
func (s *Service) authorize(ctx context.Context, scope auth.Scope, permission auth.Permission, project model.ID) error {
	if project == (model.ID{}) {
		return model.Fail(model.Invalid)
	}
	if err := s.authorizer.Revalidate(ctx, scope); err != nil {
		return err
	}
	if scope.Permission() != permission {
		return model.Fail(model.Forbidden)
	}
	if scope.OrgID() == (model.ID{}) || !scope.AllowsProject(project) {
		return model.Fail(model.NotFound)
	}
	return nil
}

type mutation struct {
	kind    UpdateKind
	project model.ID
	job     model.ID
	command model.ID
	digest  model.Hash
	origin  *model.Cursor
	audit   *Audit
	// create permits materializing a state for a job that has none yet.
	create bool
	// expected, when set, is a caller-supplied entity version that must match
	// unless the reduction is an idempotent duplicate of already-applied input.
	expected *model.Revision
	reduce   func(JobState) (JobState, Outcome, error)
}

// mutate loads, reduces and commits with optimistic concurrency. A retry after
// a crash or lost acknowledgement is safe at every point: before commit nothing
// changed; after commit the command ID (and the reducer's own idempotence)
// make the repeat a no-op.
func (s *Service) mutate(ctx context.Context, scope auth.Scope, m mutation) (JobState, Outcome, error) {
	for range maxRetries {
		if err := ctx.Err(); err != nil {
			return JobState{}, "", model.Fail(model.Cancelled)
		}
		state, found, err := s.store.Load(ctx, scope, m.project, m.job)
		if err != nil {
			return JobState{}, "", err
		}
		if !found {
			if !m.create {
				return JobState{}, "", model.Fail(model.NotFound)
			}
			state = JobState{Org: scope.OrgID(), Project: m.project, Job: m.job}
		}
		if state.Org != scope.OrgID() || state.Project != m.project || state.Job != m.job {
			return JobState{}, "", model.Fail(model.Corrupt)
		}
		next, outcome, err := m.reduce(state)
		if err != nil {
			return JobState{}, "", err
		}
		if outcome == Duplicate || outcome == Ignored {
			return state, outcome, nil
		}
		if m.expected != nil && state.Version != *m.expected {
			return JobState{}, "", model.Fail(model.Conflict)
		}
		result, err := s.store.Update(ctx, scope, UpdateCommand{CommandID: m.command, Kind: m.kind, Project: m.project, Job: m.job, ExpectedVersion: state.Version, InputDigest: m.digest, Next: next, Origin: m.origin, Audit: m.audit})
		if err != nil {
			if fault, ok := err.(*model.Fault); ok && fault.Code == model.Stale {
				continue
			}
			return JobState{}, "", err
		}
		if result.Replayed {
			current, found, err := s.store.Load(ctx, scope, m.project, m.job)
			if err != nil {
				return JobState{}, "", err
			}
			if !found {
				return JobState{}, "", model.Fail(model.Corrupt)
			}
			return current, Duplicate, nil
		}
		return next, Applied, nil
	}
	fault := model.Fail(model.Unavailable)
	fault.Retryable = true
	return JobState{}, "", fault
}

func digest(domain string, parts ...any) (model.Hash, error) {
	h := sha256.New()
	h.Write([]byte("soundpost.jobs." + domain + "\x00"))
	for _, part := range parts {
		raw, err := json.Marshal(part)
		if err != nil {
			return model.Hash{}, model.Fail(model.Invalid)
		}
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(raw)))
		h.Write(length[:])
		h.Write(raw)
	}
	var out model.Hash
	copy(out[:], h.Sum(nil))
	return out, nil
}

// ApplyAttempt folds one journal record into the job's state. The command ID is
// derived from the record's origin (group, index, record ID) so the same
// journal record can never take effect twice, whatever crashes or retries
// happen around it; the reducer additionally makes a re-delivered attempt event
// idempotent by attempt identity and (epoch, sequence). The calling principal
// needs policy.write on the project (the journal worker's service principal).
func (s *Service) ApplyAttempt(ctx context.Context, scope auth.Scope, evidence AttemptEvidence) (JobState, Outcome, error) {
	if err := s.authorize(ctx, scope, auth.PolicyWrite, evidence.Project); err != nil {
		return JobState{}, "", err
	}
	if evidence.Cursor.Group == (model.ID{}) || evidence.Record == (model.ID{}) || evidence.Event.Job == (model.ID{}) {
		return JobState{}, "", model.Fail(model.Invalid)
	}
	if err := validateEvent(evidence.Event); err != nil {
		return JobState{}, "", err
	}
	limit := s.clock.Now() + model.UnixNano(MaxFutureSkew)
	// A scheduled-form occurrence key names the instant the run was due; one far
	// in the future would otherwise outrank every real occurrence.
	scheduledAt, _, _, isScheduled := ParseOccurrenceKey(evidence.Event.Schedule)
	if evidence.Event.Observed > limit || evidence.Event.Terminal != nil && *evidence.Event.Terminal > limit || isScheduled && scheduledAt > limit {
		return JobState{}, "", model.Fail(model.Invalid)
	}
	sum := sha256.New()
	sum.Write([]byte("soundpost.jobs.attempt-command\x00"))
	org := scope.OrgID()
	sum.Write(org[:])
	sum.Write(evidence.Project[:])
	sum.Write(evidence.Cursor.Group[:])
	var index [8]byte
	binary.BigEndian.PutUint64(index[:], uint64(evidence.Cursor.Index))
	sum.Write(index[:])
	sum.Write(evidence.Record[:])
	var command model.ID
	copy(command[:], sum.Sum(nil))
	input, err := digest("attempt", evidence.Event)
	if err != nil {
		return JobState{}, "", err
	}
	origin := evidence.Cursor
	return s.mutate(ctx, scope, mutation{kind: UpdateAttempt, project: evidence.Project, job: evidence.Event.Job, command: command, digest: input, origin: &origin, create: true,
		reduce: func(state JobState) (JobState, Outcome, error) { return ReduceEvent(state, evidence.Event) }})
}

// ObserveSchedule applies one observation from the external schedule observer
// (policy.write on the project; the observer's service principal). The
// observation's clock must not be ahead of the service clock by more than
// MaxFutureSkew: a far-future observation would otherwise win every "newest"
// rule and make every later run look missed.
func (s *Service) ObserveSchedule(ctx context.Context, scope auth.Scope, evidence ScheduleEvidence) (JobState, error) {
	if err := s.authorize(ctx, scope, auth.PolicyWrite, evidence.Project); err != nil {
		return JobState{}, err
	}
	if evidence.CommandID == (model.ID{}) || evidence.Job == (model.ID{}) {
		return JobState{}, model.Fail(model.Invalid)
	}
	now := s.clock.Now()
	limit := now + model.UnixNano(MaxFutureSkew)
	if evidence.ObservedAt > limit || evidence.CompleteThrough > limit {
		return JobState{}, model.Fail(model.Invalid)
	}
	if evidence.Definition != nil && evidence.Definition.EffectiveFrom > now+model.UnixNano(MaxDefinitionLead) {
		return JobState{}, model.Fail(model.Invalid)
	}
	for _, iv := range evidence.Incomplete {
		if iv.End > limit {
			return JobState{}, model.Fail(model.Invalid)
		}
	}
	input := evidence
	input.CommandID = model.ID{}
	wire := struct {
		Project, Job, Observer model.ID
		ObservedAt             model.UnixNano
		CompleteThrough        model.UnixNano
		Healthy                bool
		Definition             *Definition
		Incomplete             []Interval
	}{input.Project, input.Job, input.Observer, input.ObservedAt, input.CompleteThrough, input.Healthy, input.Definition, input.Incomplete}
	sum, err := digest("schedule", wire)
	if err != nil {
		return JobState{}, err
	}
	state, _, err := s.mutate(ctx, scope, mutation{kind: UpdateSchedule, project: evidence.Project, job: evidence.Job, command: evidence.CommandID, digest: sum, create: true,
		reduce: func(state JobState) (JobState, Outcome, error) { return Observe(state, evidence) }})
	return state, err
}

// Correct records an audited, explicitly newer correction of one terminal
// attempt (policy.write on the project). The actor is derived from the scope,
// never from the request. The original terminal event stays immutable; the
// attempt's effective result becomes the correction's. ExpectedVersion is the
// job-state version the caller read; a mismatch is model.Conflict unless the
// identical correction is already applied (an idempotent retry).
func (s *Service) Correct(ctx context.Context, scope auth.Scope, correction Correction) (JobState, error) {
	if err := s.authorize(ctx, scope, auth.PolicyWrite, correction.Project); err != nil {
		return JobState{}, err
	}
	if correction.CommandID == (model.ID{}) || correction.Job == (model.ID{}) || correction.Attempt == (model.ID{}) {
		return JobState{}, model.Fail(model.Invalid)
	}
	actor := scope.PrincipalID()
	at := s.clock.Now()
	sum, err := digest("correction", correction.Project, correction.Job, correction.Attempt, correction.Version, correction.State, correction.Reason)
	if err != nil {
		return JobState{}, err
	}
	expected := correction.ExpectedVersion
	state, _, err := s.mutate(ctx, scope, mutation{kind: UpdateCorrection, project: correction.Project, job: correction.Job, command: correction.CommandID, digest: sum, expected: &expected,
		audit: &Audit{Principal: actor, Action: "jobs.correct", Reason: correction.Reason, At: at, Targets: []model.ID{correction.Job, correction.Attempt}},
		reduce: func(state JobState) (JobState, Outcome, error) {
			return ApplyCorrection(state, correction, actor, at)
		}})
	return state, err
}

// Health answers "what is this job's health now" (telemetry.read on the
// project). The verdict is re-derived with the service clock and the project's
// committed evidence gaps, and names the evidence it used. A job with no
// committed state, or one outside the scope, is NotFound; a known job with no
// attempts is unknown/no_evidence, never healthy.
func (s *Service) Health(ctx context.Context, scope auth.Scope, project, job model.ID) (Report, error) {
	if err := s.authorize(ctx, scope, auth.Read, project); err != nil {
		return Report{}, err
	}
	if job == (model.ID{}) {
		return Report{}, model.Fail(model.Invalid)
	}
	state, found, err := s.store.Load(ctx, scope, project, job)
	if err != nil {
		return Report{}, err
	}
	if !found || state.Org != scope.OrgID() || state.Project != project || state.Job != job {
		return Report{}, model.Fail(model.NotFound)
	}
	gaps, err := s.store.Gaps(ctx, scope, project)
	if err != nil {
		return Report{}, err
	}
	var extra []Interval
	for _, gap := range gaps {
		if gap.Org != scope.OrgID() || gap.Project != project || !coversJobs(gap.Signals) {
			continue
		}
		start := gap.Start
		if gap.End <= start {
			start = gap.End - 1
		}
		extra = append(extra, Interval{ID: gap.ID, Start: start, End: gap.End, Reason: "evidence_expired"})
	}
	now := s.clock.Now()
	intervals := append(append([]Interval(nil), state.IncompleteIntervals...), extra...)
	return Report{Version: state.Version, EvaluatedAt: now, Health: Evaluate(state, now, extra...), Intervals: intervals, State: state}, nil
}

func coversJobs(signals []model.Kind) bool {
	if len(signals) == 0 {
		return true
	}
	for _, k := range signals {
		if k == model.JobAttempt {
			return true
		}
	}
	return false
}
