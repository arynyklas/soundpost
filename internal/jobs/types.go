// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package jobs owns Soundpost's job definitions, runs, immutable attempt
// history, schedule expectations and derived current health (C07).
//
// Four things are deliberately kept apart: the job Definition (configured
// schedule/timezone/grace), Runs and Attempts (immutable evidence reported by
// the SDK), the schedule Observer (an external clock that can establish
// missed-run evidence), and CurrentHealth (a verdict derived from the other
// three, never an input to them). Health is independent of alert-condition and
// incident lifecycles; nothing here acknowledges, resolves or notifies.
package jobs

import (
	"time"

	"github.com/arynyklas/soundpost/internal/model"

	// The zone database is embedded so that DST folds and gaps resolve identically
	// on every node and on hosts without an installed tz database.
	_ "time/tzdata"
)

const (
	// DefaultGrace is how long after an expected occurrence the run may start
	// before it is considered late (C07: five minutes).
	DefaultGrace = 5 * time.Minute
	// DefaultObserverStaleAfter is how old the newest observer observation may be
	// before schedule health is treated as unknown rather than as last observed.
	DefaultObserverStaleAfter = 10 * time.Minute
	// MaxFutureSkew bounds how far ahead of the service clock evidence times may be
	// when admitted. A far-future time would otherwise win every "newest" rule.
	MaxFutureSkew = 5 * time.Minute

	// MaxRetainedRuns bounds one job state. The data-group journal remains the
	// complete history; the state is the current-health projection. Older runs
	// fall out of the state with an explicit Compaction record, never silently.
	MaxRetainedRuns          = 512
	MaxAttemptsPerRun        = 256
	MaxEventsPerAttempt      = 16
	MaxCorrectionsPerAttempt = 16
	MaxDefinitions           = 64
	MaxIntervals             = 256
	MaxReasonBytes           = 1024
)

// Duration is a nanosecond span serialized as an exact decimal string (C01).
type Duration int64

func (d Duration) MarshalJSON() ([]byte, error) { return model.Int64(d).MarshalJSON() }
func (d *Duration) UnmarshalJSON(raw []byte) error {
	var v model.Int64
	if err := v.UnmarshalJSON(raw); err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// AttemptState is the lifecycle state of one attempt. Terminal states are
// succeeded, failed and cancelled; cancelled is never success.
type AttemptState string

const (
	AttemptStarted   AttemptState = "started"
	AttemptSucceeded AttemptState = "succeeded"
	AttemptFailed    AttemptState = "failed"
	AttemptCancelled AttemptState = "cancelled"
)

func (s AttemptState) terminal() bool {
	return s == AttemptSucceeded || s == AttemptFailed || s == AttemptCancelled
}

// RunStatus is derived from a run's attempts. Recovered means the final
// attempt succeeded after at least one earlier attempt failed; the failed
// attempt remains in history.
type RunStatus string

const (
	RunRunning   RunStatus = "running"
	RunSucceeded RunStatus = "succeeded"
	RunRecovered RunStatus = "recovered"
	RunFailed    RunStatus = "failed"
	RunCancelled RunStatus = "cancelled"
)

// Status is the derived current health of a job.
type Status string

const (
	StatusSucceeded      Status = "succeeded"
	StatusFailed         Status = "failed"
	StatusCancelled      Status = "cancelled"
	StatusRunning        Status = "running"
	StatusRunningTooLong Status = "running_too_long"
	// StatusLate: an expected occurrence is past its grace window, nothing has
	// been observed, evidence of absence is complete through the grace deadline
	// and the occurrence window is still open.
	StatusLate Status = "late"
	// StatusMissed: as late, but the occurrence window has closed (the next
	// expected occurrence time was reached) with complete evidence of absence.
	StatusMissed Status = "missed"
	// StatusUnknown: the evidence cannot support any other claim. It is never a
	// synonym for healthy or for zero failures.
	StatusUnknown Status = "unknown"
)

// Reason is a closed machine-readable code explaining a verdict.
type Reason string

const (
	ReasonNoEvidence         Reason = "no_evidence"
	ReasonAttemptSucceeded   Reason = "attempt_succeeded"
	ReasonAttemptFailed      Reason = "attempt_failed"
	ReasonAttemptCancelled   Reason = "attempt_cancelled"
	ReasonRunRecovered       Reason = "run_recovered_after_retry"
	ReasonRetryInProgress    Reason = "retry_in_progress"
	ReasonAttemptRunning     Reason = "attempt_running"
	ReasonBeyondMaxRuntime   Reason = "running_beyond_max_runtime"
	ReasonCorrected          Reason = "attempt_result_corrected"
	ReasonExpectedNotStarted Reason = "expected_occurrence_not_started"
	ReasonOccurrenceClosed   Reason = "occurrence_window_closed_without_run"
	ReasonNoObserver         Reason = "no_schedule_observer"
	ReasonObserverStale      Reason = "schedule_observer_stale"
	ReasonObserverUnhealthy  Reason = "schedule_observer_unhealthy"
	ReasonNoClock            Reason = "no_clock_evidence"
	ReasonEvidenceGap        Reason = "evidence_gap_overlaps"
	ReasonAbsenceIncomplete  Reason = "evidence_of_absence_incomplete"
	ReasonSkippedLocalTime   Reason = "nonexistent_local_time_skipped"
)

// Definition configures a job. Revisions are supplied by the schedule observer
// and are totally ordered; EffectiveFrom says from which instant the revision
// governs which occurrences are expected.
type Definition struct {
	Revision      model.Uint64   `json:"revision"`
	EffectiveFrom model.UnixNano `json:"effective_from_ns"`
	// Schedule is nil for jobs without calendar expectations (queue or manual
	// jobs): such jobs can fail or succeed but can never be "missed".
	Schedule *Schedule `json:"schedule,omitempty"`
	// Grace is the allowed start delay after an expected occurrence. Zero means
	// DefaultGrace and is normalized when the revision is adopted.
	Grace Duration `json:"grace_ns"`
	// MaxRuntime enables running_too_long. Zero disables it.
	MaxRuntime Duration `json:"max_runtime_ns"`
	// ObserverStaleAfter is the observation age after which schedule health is
	// unknown. Zero means DefaultObserverStaleAfter.
	ObserverStaleAfter Duration `json:"observer_stale_after_ns"`
	// Overlap is "allow" (the only supported policy and the default): a run that
	// starts while another is running is recorded, never dropped or merged.
	Overlap string `json:"overlap"`
}

// Schedule is a five-field cron expression evaluated in an IANA time zone.
// Wall-clock semantics: a local time that does not exist (spring-forward) is
// skipped with evidence; a local time that occurs twice (fall-back) yields one
// expected occurrence per distinct UTC instant.
type Schedule struct {
	Cron     string `json:"cron"`
	Timezone string `json:"timezone"`
}

// Interval is a closed-open event-time span (Start, End] for which lifecycle
// evidence is known to be incomplete.
type Interval struct {
	ID     model.ID       `json:"id"`
	Start  model.UnixNano `json:"start_ns"`
	End    model.UnixNano `json:"end_ns"`
	Reason string         `json:"reason"`
}

// Observation is the newest statement of the external schedule observer. The
// observer owns a clock independent of the SDK: only it can say that time has
// passed without a run being reported, and only if it also attests how far the
// data path is complete (CompleteThrough).
type Observation struct {
	Observer        model.ID       `json:"observer"`
	ObservedAt      model.UnixNano `json:"observed_at_ns"`
	CompleteThrough model.UnixNano `json:"complete_through_ns"`
	Healthy         bool           `json:"healthy"`
}

// AppliedEvent is the provenance of one accepted attempt event. Distinct
// (Epoch, Sequence) pairs are retained; the identical pair is a duplicate.
type AppliedEvent struct {
	Epoch    model.ID        `json:"epoch"`
	Sequence model.Uint64    `json:"sequence"`
	State    AttemptState    `json:"state"`
	Terminal *model.UnixNano `json:"terminal_ns,omitempty"`
}

// TerminalResult is the original terminal fact of an attempt. It is never
// rewritten; corrections are separate audited records.
type TerminalResult struct {
	State AttemptState   `json:"state"`
	At    model.UnixNano `json:"at_ns"`
}

// AppliedCorrection is an authorized later assertion about an attempt result.
type AppliedCorrection struct {
	Version model.Uint64   `json:"version"`
	State   AttemptState   `json:"state"`
	Reason  string         `json:"reason"`
	Actor   model.ID       `json:"actor"`
	At      model.UnixNano `json:"at_ns"`
	Command model.ID       `json:"command"`
}

// Attempt is one immutable attempt. Identity is (job, run, attempt ID).
type Attempt struct {
	ID       model.ID       `json:"id"`
	Run      model.ID       `json:"run"`
	Ordinal  model.Uint64   `json:"ordinal"`
	Observed model.UnixNano `json:"observed_ns"`
	// Started reports whether a started event has been accepted; a terminal event
	// may legitimately arrive first.
	Started     bool                `json:"started"`
	Terminal    *TerminalResult     `json:"terminal,omitempty"`
	CauseTrace  *model.ID           `json:"cause_trace,omitempty"`
	CauseError  *model.ID           `json:"cause_error,omitempty"`
	Events      []AppliedEvent      `json:"events"`
	Corrections []AppliedCorrection `json:"corrections,omitempty"`
}

// Effective is the attempt's result as of the newest correction, or the original
// terminal state when uncorrected; started while no terminal event was accepted.
func (a Attempt) Effective() AttemptState {
	if n := len(a.Corrections); n > 0 {
		return a.Corrections[n-1].State
	}
	if a.Terminal != nil {
		return a.Terminal.State
	}
	return AttemptStarted
}

// Run groups the attempts of one execution of a job occurrence.
type Run struct {
	ID         model.ID       `json:"id"`
	Occurrence string         `json:"occurrence"`
	Attempts   []model.ID     `json:"attempts"`
	Status     RunStatus      `json:"status"`
	Final      model.ID       `json:"final_attempt"`
	Recovered  bool           `json:"recovered"`
	Started    model.UnixNano `json:"first_started_ns"`
}

// Occurrence is a schedule occurrence (or a manual/unscheduled execution
// identity) that has at least one run.
type Occurrence struct {
	Key       string         `json:"key"`
	Scheduled bool           `json:"scheduled"`
	At        model.UnixNano `json:"at_ns,omitempty"`
	// Order is the instant used to decide which occurrence is newest: the
	// scheduled instant, or for manual executions the earliest attempt start.
	Order model.UnixNano `json:"order_ns"`
	Runs  []model.ID     `json:"runs"`
}

// Compaction records, explicitly, the history that left the bounded state.
type Compaction struct {
	Runs    model.Uint64   `json:"runs"`
	Through model.UnixNano `json:"through_ns"`
}

// ObserverEvidence names the observer facts a verdict used.
type ObserverEvidence struct {
	Observer        model.ID       `json:"observer"`
	ObservedAt      model.UnixNano `json:"observed_at_ns"`
	CompleteThrough model.UnixNano `json:"complete_through_ns"`
	Healthy         bool           `json:"healthy"`
	Stale           bool           `json:"stale"`
}

// Evidence names exactly what a Health verdict used.
type Evidence struct {
	Occurrence         string            `json:"occurrence,omitempty"`
	Run                *model.ID         `json:"run,omitempty"`
	Attempt            *model.ID         `json:"attempt,omitempty"`
	AttemptState       AttemptState      `json:"attempt_state,omitempty"`
	AttemptCount       int               `json:"attempt_count,omitempty"`
	ExpectedAt         *model.UnixNano   `json:"expected_at_ns,omitempty"`
	WindowEnd          *model.UnixNano   `json:"window_end_ns,omitempty"`
	CauseTrace         *model.ID         `json:"cause_trace,omitempty"`
	CauseError         *model.ID         `json:"cause_error,omitempty"`
	DefinitionRevision model.Uint64      `json:"definition_revision,omitempty"`
	Observer           *ObserverEvidence `json:"observer,omitempty"`
	Gaps               []model.ID        `json:"gaps,omitempty"`
	Skipped            []string          `json:"skipped_local_times,omitempty"`
}

// Health is the derived verdict. Complete is false whenever any evidence the
// verdict would need to be conclusive is missing; a Complete=false succeeded
// is never produced (it becomes unknown).
type Health struct {
	Status   Status         `json:"status"`
	AsOf     model.UnixNano `json:"as_of_ns"`
	Complete bool           `json:"complete"`
	Reasons  []Reason       `json:"reasons"`
	Evidence Evidence       `json:"evidence"`
}

// JobState keeps definition, runs, attempts and current health separately.
type JobState struct {
	Version model.Revision `json:"version"`
	Org     model.ID       `json:"org"`
	Project model.ID       `json:"project"`
	Job     model.ID       `json:"job"`

	Definition Definition   `json:"definition"`
	History    []Definition `json:"history,omitempty"` // older revisions, ascending

	CurrentHealth     Health                `json:"current_health"`
	LatestScheduleKey string                `json:"latest_schedule_key,omitempty"`
	Occurrences       map[string]Occurrence `json:"occurrences,omitempty"`
	Runs              map[model.ID]Run      `json:"runs,omitempty"`
	Attempts          map[model.ID]Attempt  `json:"attempts,omitempty"`

	IncompleteIntervals []Interval   `json:"incomplete_intervals,omitempty"`
	Observer            *Observation `json:"observer,omitempty"`
	Compaction          Compaction   `json:"compaction"`
}

// Outcome reports what a reduction did, so callers can tell an applied change
// from an idempotent duplicate or evidence that is outside the retained window.
type Outcome string

const (
	Applied   Outcome = "applied"
	Duplicate Outcome = "duplicate"
	// Ignored evidence is older than the retained window or an older definition
	// revision: it cannot change any retained fact.
	Ignored Outcome = "ignored"
)

// Correction is an audited, authorized later assertion about one terminal
// attempt. Version must be explicitly newer than the attempt's newest
// correction; the original terminal event is retained untouched.
type Correction struct {
	CommandID       model.ID
	Project         model.ID
	Job             model.ID
	ExpectedVersion model.Revision
	Attempt         model.ID
	Version         model.Uint64
	State           AttemptState
	Reason          string
}

// ScheduleEvidence is one observation from the external schedule observer.
type ScheduleEvidence struct {
	CommandID model.ID
	Project   model.ID
	Job       model.ID
	Observer  model.ID
	// ObservedAt is the observer's clock reading.
	ObservedAt model.UnixNano
	// CompleteThrough attests the data path (source producing, ingest ACKed,
	// journal processed) is complete for this job through that instant. It never
	// exceeds ObservedAt.
	CompleteThrough model.UnixNano
	Healthy         bool
	Definition      *Definition
	Incomplete      []Interval
}

// AttemptEvidence is one journal record: the origin cursor makes application
// exactly-once-effective across retries and crashes.
type AttemptEvidence struct {
	Project model.ID
	Cursor  model.Cursor
	Record  model.ID
	Event   model.JobAttemptEvent
}

// Report is a truthful current-health read.
type Report struct {
	Version     model.Revision
	EvaluatedAt model.UnixNano
	Health      Health
	// Intervals are every known incomplete interval (the job's own and the
	// project's committed evidence gaps), so unknown stretches of history stay
	// annotated even when they do not change the current verdict.
	Intervals []Interval
	State     JobState
}
