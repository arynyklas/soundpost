// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package jobs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"soundpost/internal/model"
)

// Every function in this file is pure and deterministic: no wall clock, no
// randomness, no I/O, and inputs are never mutated. Time enters only as
// explicit evidence (event times, observer observations) or an explicit `at`.

// ---------------------------------------------------------------- attempts

// Reduce is the C07 reducer: it folds one SDK job-attempt event into the
// state. A duplicate or out-of-window event returns the state unchanged.
func Reduce(current JobState, event model.JobAttemptEvent) (JobState, error) {
	next, _, err := ReduceEvent(current, event)
	return next, err
}

// ReduceEvent is Reduce with the outcome. Attempt identity is (job, run,
// attempt ID); the exact (producer epoch, sequence) pair of an attempt is
// applied once. Terminal results are immutable: an identical resend is
// idempotent and a conflicting one is rejected with model.Conflict and
// changes nothing. Events of one attempt may arrive in any order.
func ReduceEvent(current JobState, event model.JobAttemptEvent) (JobState, Outcome, error) {
	if err := validateEvent(event); err != nil {
		return current, "", err
	}
	if current.Job != (model.ID{}) && current.Job != event.Job {
		return current, "", model.Fail(model.Invalid)
	}
	state := AttemptState(event.State)
	attempt, hasAttempt := current.Attempts[event.Attempt]
	run, hasRun := current.Runs[event.Run]
	if hasAttempt && attempt.Run != event.Run {
		return current, "", model.Fail(model.Conflict)
	}
	if hasAttempt && !hasRun {
		return current, "", model.Fail(model.Corrupt)
	}
	if hasRun && run.Occurrence != event.Schedule {
		return current, "", model.Fail(model.Conflict)
	}
	if hasAttempt && (attempt.Run != event.Run || attempt.Ordinal != event.Ordinal || attempt.Observed != event.Observed) {
		return current, "", model.Fail(model.Conflict)
	}
	if !hasRun && current.Compaction.Runs > 0 && eventOrder(event) <= current.Compaction.Through {
		// A new run older than everything already compacted out of the bounded
		// state: it cannot change any retained fact or the newest verdict.
		return current, Ignored, nil
	}

	if hasAttempt {
		for _, applied := range attempt.Events {
			if applied.Epoch == event.Epoch && applied.Sequence == event.Sequence {
				if applied.State != state || !sameTime(applied.Terminal, event.Terminal) {
					return current, "", model.Fail(model.Conflict)
				}
				if _, err := mergeCause(attempt, event); err != nil {
					return current, "", err
				}
				return current, Duplicate, nil
			}
		}
	}

	next := current.clone()
	if next.Job == (model.ID{}) {
		next.Job = event.Job
	}
	if !hasAttempt {
		attempt = Attempt{ID: event.Attempt, Run: event.Run, Ordinal: event.Ordinal, Observed: event.Observed}
	}
	if !hasRun {
		run = Run{ID: event.Run, Occurrence: event.Schedule}
	}
	if len(attempt.Events) >= MaxEventsPerAttempt || !hasAttempt && len(run.Attempts) >= MaxAttemptsPerRun {
		return current, "", model.Fail(model.Quota)
	}
	merged, err := mergeCause(attempt, event)
	if err != nil {
		return current, "", err
	}
	attempt = merged
	if state == AttemptStarted {
		attempt.Started = true
	} else {
		result := TerminalResult{State: state, At: *event.Terminal}
		if attempt.Terminal != nil && *attempt.Terminal != result {
			return current, "", model.Fail(model.Conflict)
		}
		attempt.Terminal = &result
	}
	attempt.Events = insertEvent(attempt.Events, AppliedEvent{Epoch: event.Epoch, Sequence: event.Sequence, State: state, Terminal: cloneTime(event.Terminal)})
	next.Attempts[attempt.ID] = attempt
	if !hasRun {
		next.Runs[run.ID] = run
		occurrence := next.Occurrences[event.Schedule]
		occurrence.Key = event.Schedule
		if at, _, _, ok := ParseOccurrenceKey(event.Schedule); ok {
			occurrence.Scheduled, occurrence.At = true, at
		}
		occurrence.Runs = appendCopy(occurrence.Runs, run.ID)
		next.Occurrences[event.Schedule] = occurrence
	}
	if !hasAttempt {
		run = next.Runs[run.ID]
		run.Attempts = appendCopy(run.Attempts, attempt.ID)
		next.Runs[run.ID] = run
	}
	next.refreshRun(event.Run)
	next.evict()
	next.finish()
	return next, Applied, nil
}

func validateEvent(e model.JobAttemptEvent) error {
	if e.Job == (model.ID{}) || e.Run == (model.ID{}) || e.Attempt == (model.ID{}) || e.Epoch == (model.ID{}) || e.Ordinal == 0 || e.Observed <= 0 || !safeKey(e.Schedule) {
		return model.Fail(model.Invalid)
	}
	switch AttemptState(e.State) {
	case AttemptStarted:
		if e.Terminal != nil {
			return model.Fail(model.Invalid)
		}
	case AttemptSucceeded, AttemptFailed, AttemptCancelled:
		if e.Terminal == nil || *e.Terminal < e.Observed {
			return model.Fail(model.Invalid)
		}
	default:
		return model.Fail(model.Invalid)
	}
	return nil
}

// mergeCause adds each cause reference at most once. A different reference for
// an already-set cause is a conflict: cause links are part of the immutable
// attempt, though a later event may fill an absent one.
func mergeCause(a Attempt, e model.JobAttemptEvent) (Attempt, error) {
	var err error
	if a.CauseTrace, err = mergeRef(a.CauseTrace, e.CauseTrace); err != nil {
		return a, err
	}
	a.CauseError, err = mergeRef(a.CauseError, e.CauseError)
	return a, err
}
func mergeRef(have, incoming *model.ID) (*model.ID, error) {
	switch {
	case incoming == nil:
		return have, nil
	case have == nil:
		id := *incoming
		return &id, nil
	case *have != *incoming:
		return have, model.Fail(model.Conflict)
	}
	return have, nil
}
func sameTime(a, b *model.UnixNano) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
func cloneTime(t *model.UnixNano) *model.UnixNano {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}
func insertEvent(events []AppliedEvent, e AppliedEvent) []AppliedEvent {
	out := make([]AppliedEvent, 0, len(events)+1)
	out = append(out, events...)
	out = append(out, e)
	sort.Slice(out, func(i, j int) bool {
		if c := bytes.Compare(out[i].Epoch[:], out[j].Epoch[:]); c != 0 {
			return c < 0
		}
		return out[i].Sequence < out[j].Sequence
	})
	return out
}
func appendCopy[T any](s []T, v T) []T {
	out := make([]T, 0, len(s)+1)
	out = append(out, s...)
	return append(out, v)
}
func eventOrder(e model.JobAttemptEvent) model.UnixNano {
	if at, _, _, ok := ParseOccurrenceKey(e.Schedule); ok {
		return at
	}
	return e.Observed
}

func (s JobState) clone() JobState {
	out := s
	out.Occurrences = make(map[string]Occurrence, len(s.Occurrences)+1)
	for k, v := range s.Occurrences {
		out.Occurrences[k] = v
	}
	out.Runs = make(map[model.ID]Run, len(s.Runs)+1)
	for k, v := range s.Runs {
		out.Runs[k] = v
	}
	out.Attempts = make(map[model.ID]Attempt, len(s.Attempts)+1)
	for k, v := range s.Attempts {
		out.Attempts[k] = v
	}
	return out
}

// refreshRun re-derives a run's attempt order, final attempt and status, and
// its occurrence's ordering instant. Derived fields never feed back into
// attempts.
func (s *JobState) refreshRun(id model.ID) {
	run := s.Runs[id]
	ids := append([]model.ID(nil), run.Attempts...)
	sort.Slice(ids, func(i, j int) bool { return s.attemptLess(ids[i], ids[j]) })
	run.Attempts = ids
	run.Final = ids[len(ids)-1]
	run.Started = math.MaxInt64
	failedBefore := false
	for i, a := range ids {
		attempt := s.Attempts[a]
		if attempt.Observed < run.Started {
			run.Started = attempt.Observed
		}
		if i < len(ids)-1 && attempt.Effective() == AttemptFailed {
			failedBefore = true
		}
	}
	switch s.Attempts[run.Final].Effective() {
	case AttemptStarted:
		run.Status = RunRunning
	case AttemptSucceeded:
		run.Status = RunSucceeded
		if failedBefore {
			run.Status = RunRecovered
		}
	case AttemptFailed:
		run.Status = RunFailed
	case AttemptCancelled:
		run.Status = RunCancelled
	}
	run.Recovered = run.Status == RunRecovered
	s.Runs[id] = run
	occurrence := s.Occurrences[run.Occurrence]
	if !occurrence.Scheduled {
		order := model.UnixNano(math.MaxInt64)
		for _, r := range occurrence.Runs {
			if started := s.Runs[r].Started; started < order {
				order = started
			}
		}
		occurrence.Order = order
	} else {
		occurrence.Order = occurrence.At
	}
	s.Occurrences[run.Occurrence] = occurrence
}
func (s *JobState) attemptLess(a, b model.ID) bool {
	x, y := s.Attempts[a], s.Attempts[b]
	if x.Ordinal != y.Ordinal {
		return x.Ordinal < y.Ordinal
	}
	if x.Observed != y.Observed {
		return x.Observed < y.Observed
	}
	return bytes.Compare(a[:], b[:]) < 0
}

// evict bounds the state. Only the oldest runs by occurrence order leave, and
// the departure is recorded in Compaction.
func (s *JobState) evict() {
	for len(s.Runs) > MaxRetainedRuns {
		var oldest model.ID
		first := true
		for id, run := range s.Runs {
			if first || s.runOlder(run, s.Runs[oldest]) {
				oldest, first = id, false
			}
		}
		run := s.Runs[oldest]
		occurrence := s.Occurrences[run.Occurrence]
		if occurrence.Order > s.Compaction.Through {
			s.Compaction.Through = occurrence.Order
		}
		for _, a := range run.Attempts {
			delete(s.Attempts, a)
		}
		delete(s.Runs, oldest)
		kept := make([]model.ID, 0, len(occurrence.Runs))
		for _, r := range occurrence.Runs {
			if r != oldest {
				kept = append(kept, r)
			}
		}
		if len(kept) == 0 {
			delete(s.Occurrences, run.Occurrence)
		} else {
			occurrence.Runs = kept
			s.Occurrences[run.Occurrence] = occurrence
		}
		s.Compaction.Runs++
	}
}
func (s *JobState) runOlder(a, b Run) bool {
	oa, ob := s.Occurrences[a.Occurrence].Order, s.Occurrences[b.Occurrence].Order
	if oa != ob {
		return oa < ob
	}
	if a.Started != b.Started {
		return a.Started < b.Started
	}
	return bytes.Compare(a.ID[:], b.ID[:]) < 0
}

// finish bumps the entity version and refreshes the stored verdict. The stored
// verdict is as of the newest observer observation (no staleness); readers
// re-evaluate with their own clock.
func (s *JobState) finish() {
	s.Version++
	s.LatestScheduleKey = ""
	if o, ok := s.latestOccurrence(); ok {
		s.LatestScheduleKey = o.Key
	}
	var at model.UnixNano
	if s.Observer != nil {
		at = s.Observer.ObservedAt
	}
	s.CurrentHealth = Evaluate(*s, at)
}
func (s JobState) latestOccurrence() (Occurrence, bool) {
	var best Occurrence
	found := false
	for _, o := range s.Occurrences {
		if !found || o.Order > best.Order || o.Order == best.Order && o.Key > best.Key {
			best, found = o, true
		}
	}
	return best, found
}
func (s JobState) representative(o Occurrence) Run {
	var best Run
	for i, id := range o.Runs {
		r := s.Runs[id]
		if i == 0 || r.Started > best.Started || r.Started == best.Started && bytes.Compare(r.ID[:], best.ID[:]) > 0 {
			best = r
		}
	}
	return best
}

// ------------------------------------------------------------- corrections

// ApplyCorrection records an authorized, explicitly versioned later assertion
// about a terminal attempt. The original terminal event and every earlier
// correction stay in history; the attempt's effective result becomes the
// newest correction's. An identical resubmission is a duplicate.
func ApplyCorrection(current JobState, c Correction, actor model.ID, at model.UnixNano) (JobState, Outcome, error) {
	if c.CommandID == (model.ID{}) || c.Attempt == (model.ID{}) || c.Version == 0 || actor == (model.ID{}) || at <= 0 || !c.State.terminal() || !safeText(c.Reason, MaxReasonBytes) {
		return current, "", model.Fail(model.Invalid)
	}
	attempt, ok := current.Attempts[c.Attempt]
	if !ok {
		return current, "", model.Fail(model.NotFound)
	}
	if attempt.Terminal == nil {
		return current, "", model.Fail(model.Conflict)
	}
	for _, applied := range attempt.Corrections {
		if applied.Version == c.Version {
			if applied.State == c.State && applied.Reason == c.Reason {
				return current, Duplicate, nil
			}
			return current, "", model.Fail(model.Conflict)
		}
	}
	if n := len(attempt.Corrections); n > 0 && c.Version < attempt.Corrections[n-1].Version {
		return current, "", model.Fail(model.Conflict)
	}
	if len(attempt.Corrections) >= MaxCorrectionsPerAttempt {
		return current, "", model.Fail(model.Quota)
	}
	next := current.clone()
	attempt.Corrections = appendCopy(attempt.Corrections, AppliedCorrection{Version: c.Version, State: c.State, Reason: c.Reason, Actor: actor, At: at, Command: c.CommandID})
	next.Attempts[attempt.ID] = attempt
	next.refreshRun(attempt.Run)
	next.finish()
	return next, Applied, nil
}

func safeText(v string, max int) bool {
	if strings.TrimSpace(v) == "" || len(v) > max || !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func safeKey(v string) bool {
	if v == "" || len(v) > 256 {
		return false
	}
	for i := range len(v) {
		c := v[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- observer

// Observe folds one external schedule-observer observation into the state.
// It is a join: any order and any repetition of the same observations reaches
// the same state. The newest observation (observer clock) wins; equal clocks
// resolve conservatively (unhealthy, then smaller attestation). Definition
// revisions are totally ordered and a late older revision is inserted, never
// dropped or allowed to replace a newer one.
func Observe(current JobState, e ScheduleEvidence) (JobState, Outcome, error) {
	if e.Job == (model.ID{}) || e.Observer == (model.ID{}) || e.ObservedAt <= 0 || e.CompleteThrough < 0 || e.CompleteThrough > e.ObservedAt {
		return current, "", model.Fail(model.Invalid)
	}
	if current.Job != (model.ID{}) && current.Job != e.Job || current.Project != (model.ID{}) && e.Project != (model.ID{}) && current.Project != e.Project {
		return current, "", model.Fail(model.Invalid)
	}
	next := current.clone()
	changed := false
	if next.Job == (model.ID{}) {
		next.Job, changed = e.Job, true
	}
	if next.Project == (model.ID{}) && e.Project != (model.ID{}) {
		next.Project, changed = e.Project, true
	}
	if e.Definition != nil {
		def, err := normalizeDefinition(*e.Definition)
		if err != nil {
			return current, "", err
		}
		if err := next.insertDefinition(def, &changed); err != nil {
			return current, "", err
		}
	}
	if len(e.Incomplete) > 0 {
		if err := next.mergeIntervals(e.Incomplete, &changed); err != nil {
			return current, "", err
		}
	}
	candidate := Observation{Observer: e.Observer, ObservedAt: e.ObservedAt, CompleteThrough: e.CompleteThrough, Healthy: e.Healthy}
	if next.Observer == nil || observationWins(candidate, *next.Observer) {
		next.Observer, changed = &candidate, true
	}
	if !changed {
		return current, Duplicate, nil
	}
	next.finish()
	return next, Applied, nil
}

func observationWins(a, b Observation) bool {
	if a.ObservedAt != b.ObservedAt {
		return a.ObservedAt > b.ObservedAt
	}
	if a.Healthy != b.Healthy {
		return !a.Healthy
	}
	if c := bytes.Compare(a.Observer[:], b.Observer[:]); c != 0 {
		return c > 0
	}
	return a.CompleteThrough < b.CompleteThrough
}

func (s *JobState) insertDefinition(def Definition, changed *bool) error {
	all := append([]Definition(nil), s.History...)
	if s.Definition.Revision != 0 {
		all = append(all, s.Definition)
	}
	for _, have := range all {
		if have.Revision == def.Revision {
			if reflect.DeepEqual(have, def) {
				return nil
			}
			return model.Fail(model.Conflict)
		}
	}
	all = append(all, def)
	if len(all) > MaxDefinitions {
		return model.Fail(model.Quota)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Revision < all[j].Revision })
	for i := 1; i < len(all); i++ {
		if all[i].EffectiveFrom < all[i-1].EffectiveFrom {
			return model.Fail(model.Invalid)
		}
	}
	s.Definition = all[len(all)-1]
	s.History = nil
	if len(all) > 1 {
		s.History = all[:len(all)-1]
	}
	*changed = true
	return nil
}

func (s *JobState) mergeIntervals(in []Interval, changed *bool) error {
	byID := map[model.ID]Interval{}
	for _, iv := range s.IncompleteIntervals {
		byID[iv.ID] = iv
	}
	for _, iv := range in {
		if iv.ID == (model.ID{}) || iv.Start < 0 || iv.End <= iv.Start || !safeKey(iv.Reason) {
			return model.Fail(model.Invalid)
		}
		if have, ok := byID[iv.ID]; ok {
			if have != iv {
				return model.Fail(model.Conflict)
			}
			continue
		}
		byID[iv.ID] = iv
		*changed = true
	}
	if len(byID) > MaxIntervals {
		return model.Fail(model.Quota)
	}
	out := make([]Interval, 0, len(byID))
	for _, iv := range byID {
		out = append(out, iv)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		if out[i].End != out[j].End {
			return out[i].End < out[j].End
		}
		return bytes.Compare(out[i].ID[:], out[j].ID[:]) < 0
	})
	s.IncompleteIntervals = out
	return nil
}

func normalizeDefinition(d Definition) (Definition, error) {
	if d.Revision == 0 || d.EffectiveFrom <= 0 {
		return d, model.Fail(model.Invalid)
	}
	switch d.Overlap {
	case "":
		d.Overlap = "allow"
	case "allow":
	default:
		return d, model.Fail(model.Unsupported)
	}
	if d.Grace == 0 {
		d.Grace = Duration(DefaultGrace)
	}
	if d.ObserverStaleAfter == 0 {
		d.ObserverStaleAfter = Duration(DefaultObserverStaleAfter)
	}
	if d.Grace < 0 || d.Grace > Duration(24*time.Hour) || d.MaxRuntime < 0 || d.MaxRuntime > Duration(30*24*time.Hour) || d.ObserverStaleAfter < Duration(time.Second) || d.ObserverStaleAfter > Duration(24*time.Hour) {
		return d, model.Fail(model.Invalid)
	}
	if d.Schedule != nil {
		if _, err := compileSchedule(*d.Schedule); err != nil {
			return d, err
		}
		s := *d.Schedule
		d.Schedule = &s
	}
	return d, nil
}

// ---------------------------------------------------------------- health

type blockingFlags struct {
	blocking   bool // evidence needed to call the job healthy is missing
	incomplete bool // evidence needed for this verdict to be conclusive is missing
}

// Evaluate derives current health from the state as of the newest observer
// observation, using `at` only to decide whether that observation is stale.
// extra are additional incomplete intervals (for example project-level
// evidence gaps held outside this job's state). It never reads a wall clock.
//
// The verdict is the newest of (a) the latest run's effective attempt result
// and (b) for scheduled jobs, the latest expected occurrence that is overdue
// with no run in its window. Evidence that cannot support a positive claim
// yields unknown, never succeeded; it may only withhold "complete" from a
// negative claim that has already been observed.
func Evaluate(st JobState, at model.UnixNano, extra ...Interval) Health {
	def := st.Definition
	scheduled := def.Schedule != nil
	obs := st.Observer
	var et model.UnixNano
	stale := false
	var oe *ObserverEvidence
	if obs != nil {
		et = obs.ObservedAt
		stale = at > et && time.Duration(at-et) > staleAfter(def)
		oe = &ObserverEvidence{Observer: obs.Observer, ObservedAt: obs.ObservedAt, CompleteThrough: obs.CompleteThrough, Healthy: obs.Healthy, Stale: stale}
	}
	intervals := append(append([]Interval(nil), st.IncompleteIntervals...), extra...)
	h := Health{AsOf: et, Evidence: Evidence{DefinitionRevision: def.Revision, Observer: oe}}
	reasons := map[Reason]bool{}
	var flags blockingFlags

	latest, hasLatest := st.latestOccurrence()
	var run Run
	var attempt Attempt
	if hasLatest {
		run = st.representative(latest)
		attempt = st.Attempts[run.Final]
	}

	// (b) expected occurrences with no run in their window. An occurrence's
	// window runs from its instant to the next expected instant. The newest
	// closed window with no run is "missed" (and stays missed until a run
	// happens); otherwise an open occurrence past its grace is "late".
	usedExpected := false
	uncovered := func(at model.UnixNano) bool { return !hasLatest || latest.Order < at }
	absenceUnproven := func(from, through model.UnixNano) {
		reasons[ReasonAbsenceIncomplete] = true
		flags.blocking, flags.incomplete = true, true
		h.Evidence.Gaps = append(h.Evidence.Gaps, overlapping(intervals, from, through)...)
	}
	if scheduled && obs != nil {
		if p, ok := st.expectedPrev(et); ok {
			if c, ok := st.expectedPrev(p.At - 1); ok && uncovered(c.At) {
				if absenceComplete(obs, intervals, c.At, p.At) {
					usedExpected = true
					h.Status = StatusMissed
					reasons[ReasonExpectedNotStarted], reasons[ReasonOccurrenceClosed] = true, true
					h.Evidence.Occurrence = c.Key
					expectedAt, windowEnd := c.At, p.At
					h.Evidence.ExpectedAt, h.Evidence.WindowEnd = &expectedAt, &windowEnd
				} else {
					absenceUnproven(c.At, p.At)
				}
			}
			if through := p.At + model.UnixNano(grace(def)); !usedExpected && through <= et && uncovered(p.At) {
				if absenceComplete(obs, intervals, p.At, through) {
					usedExpected = true
					h.Status = StatusLate
					reasons[ReasonExpectedNotStarted] = true
					h.Evidence.Occurrence = p.Key
					expectedAt := p.At
					h.Evidence.ExpectedAt = &expectedAt
				} else {
					absenceUnproven(p.At, through)
				}
			}
		}
	}

	if !usedExpected {
		switch {
		case !hasLatest:
			h.Status = StatusUnknown
			reasons[ReasonNoEvidence] = true
			flags.incomplete = true
		default:
			h.Evidence.Occurrence = latest.Key
			runID, attemptID := run.ID, attempt.ID
			h.Evidence.Run, h.Evidence.Attempt = &runID, &attemptID
			h.Evidence.AttemptCount = len(run.Attempts)
			h.Evidence.CauseTrace, h.Evidence.CauseError = attempt.CauseTrace, attempt.CauseError
			state := attempt.Effective()
			h.Evidence.AttemptState = state
			if len(attempt.Corrections) > 0 {
				reasons[ReasonCorrected] = true
			}
			switch state {
			case AttemptSucceeded:
				h.Status = StatusSucceeded
				reasons[ReasonAttemptSucceeded] = true
				if run.Recovered {
					reasons[ReasonRunRecovered] = true
				}
			case AttemptFailed:
				h.Status = StatusFailed
				reasons[ReasonAttemptFailed] = true
			case AttemptCancelled:
				h.Status = StatusCancelled
				reasons[ReasonAttemptCancelled] = true
			default:
				h.Status = StatusRunning
				reasons[ReasonAttemptRunning] = true
				if len(run.Attempts) > 1 {
					reasons[ReasonRetryInProgress] = true
				}
				if def.MaxRuntime > 0 {
					if obs == nil {
						reasons[ReasonNoClock] = true
						flags.incomplete = true
					} else if time.Duration(et-attempt.Observed) > time.Duration(def.MaxRuntime) {
						h.Status = StatusRunningTooLong
						reasons[ReasonBeyondMaxRuntime] = true
					}
				}
			}
			var windowEnd model.UnixNano = math.MaxInt64
			if obs != nil {
				windowEnd = et
			}
			// Evidence already in hand about this attempt is not threatened by a
			// gap before its result; later lost evidence (a newer run, a retry, a
			// correction) is. A running attempt is threatened from its start.
			windowStart := attempt.Observed
			if attempt.Terminal != nil {
				windowStart = attempt.Terminal.At
			}
			if gaps := overlapping(intervals, windowStart, windowEnd); len(gaps) > 0 {
				h.Evidence.Gaps = gaps
				reasons[ReasonEvidenceGap] = true
				flags.blocking, flags.incomplete = true, true
			}
		}
	}

	if scheduled {
		switch {
		case obs == nil:
			reasons[ReasonNoObserver] = true
			flags.blocking, flags.incomplete = true, true
		case !obs.Healthy:
			reasons[ReasonObserverUnhealthy] = true
			flags.blocking, flags.incomplete = true, true
		case stale:
			reasons[ReasonObserverStale] = true
			flags.blocking, flags.incomplete = true, true
		}
	}
	if (h.Status == StatusSucceeded || h.Status == StatusRunning) && flags.blocking {
		h.Status = StatusUnknown
	}
	if scheduled && obs != nil {
		lo := et - model.UnixNano(48*time.Hour)
		if h.Evidence.ExpectedAt != nil {
			lo = *h.Evidence.ExpectedAt
		} else if hasLatest {
			lo = latest.Order
		}
		if floor := et - model.UnixNano(7*24*time.Hour); lo < floor {
			lo = floor
		}
		if skipped := st.skippedLocal(lo, et, 8); len(skipped) > 0 {
			h.Evidence.Skipped = skipped
			reasons[ReasonSkippedLocalTime] = true
		}
	}
	h.Complete = !flags.incomplete
	for r := range reasons {
		h.Reasons = append(h.Reasons, r)
	}
	sort.Slice(h.Reasons, func(i, j int) bool { return h.Reasons[i] < h.Reasons[j] })
	sort.Slice(h.Evidence.Gaps, func(i, j int) bool { return bytes.Compare(h.Evidence.Gaps[i][:], h.Evidence.Gaps[j][:]) < 0 })
	return h
}

func grace(d Definition) time.Duration {
	if d.Grace == 0 {
		return DefaultGrace
	}
	return time.Duration(d.Grace)
}
func staleAfter(d Definition) time.Duration {
	if d.ObserverStaleAfter == 0 {
		return DefaultObserverStaleAfter
	}
	return time.Duration(d.ObserverStaleAfter)
}

// absenceComplete reports whether "no run was observed in [from, through]" is
// supported: a healthy observer attests data-path completeness through the
// whole span and no declared incomplete interval overlaps it.
func absenceComplete(obs *Observation, intervals []Interval, from, through model.UnixNano) bool {
	return obs != nil && obs.Healthy && obs.CompleteThrough >= through && len(overlapping(intervals, from, through)) == 0
}

// overlapping returns the IDs of intervals intersecting (from, to].
func overlapping(intervals []Interval, from, to model.UnixNano) []model.ID {
	var ids []model.ID
	for _, iv := range intervals {
		if iv.End > from && iv.Start < to {
			ids = append(ids, iv.ID)
		}
	}
	return ids
}

// ---------------------------------------------------------------- schedule

// OccurrenceKey is the wire identity of a scheduled occurrence: the scheduled
// UTC instant, the fold (0, or 1 for the second instance of a repeated local
// time) and a tag of the configured time zone. The key stays within the SDK's
// schedule_occurrence alphabet ([A-Za-z0-9_.-], 256 bytes).
func OccurrenceKey(timezone string, at model.UnixNano, fold uint8) string {
	return "s." + strconv.FormatInt(int64(at), 10) + ".f" + strconv.Itoa(int(fold)) + "." + zoneTag(timezone)
}

// ParseOccurrenceKey decodes a key made by OccurrenceKey. Any other string is a
// manual or otherwise unscheduled execution identity (ok=false).
func ParseOccurrenceKey(key string) (at model.UnixNano, fold uint8, tag string, ok bool) {
	parts := strings.Split(key, ".")
	if len(parts) != 4 || parts[0] != "s" || len(parts[3]) != 8 || (parts[2] != "f0" && parts[2] != "f1") {
		return 0, 0, "", false
	}
	if _, err := hex.DecodeString(parts[3]); err != nil || strings.ToLower(parts[3]) != parts[3] {
		return 0, 0, "", false
	}
	v, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || v <= 0 || strconv.FormatInt(v, 10) != parts[1] {
		return 0, 0, "", false
	}
	return model.UnixNano(v), parts[2][1] - '0', parts[3], true
}
func zoneTag(tz string) string {
	sum := sha256.Sum256([]byte("soundpost.jobs.zone\x00" + tz))
	return hex.EncodeToString(sum[:4])
}

// Expected is one expected occurrence of a schedule.
type Expected struct {
	At    model.UnixNano
	Fold  uint8
	Local string // wall time in the schedule's zone, "2006-01-02T15:04"
	Key   string
}

// Skipped is a local wall time the schedule matched but that does not exist
// (spring-forward gap), so no occurrence is expected for it.
type Skipped struct {
	Local string
	Near  model.UnixNano // approximate instant, for ordering only
}

// ExpectedWindow lists expected occurrences and skipped local times in (from, through].
type ExpectedWindow struct {
	Runs    []Expected
	Skipped []Skipped
}

// ExpectedOccurrences enumerates one definition's schedule. A local time that
// does not exist is reported in Skipped; a local time that occurs twice yields
// two occurrences, one per UTC instant (fold 0 then 1). At most limit
// occurrences are returned; a larger window fails with model.TooLarge.
func ExpectedOccurrences(def Definition, from, through model.UnixNano, limit int) (ExpectedWindow, error) {
	if def.Schedule == nil || through < from || limit <= 0 {
		return ExpectedWindow{}, model.Fail(model.Invalid)
	}
	c, err := compileSchedule(*def.Schedule)
	if err != nil {
		return ExpectedWindow{}, err
	}
	var out ExpectedWindow
	first := c.civil(from).AddDate(0, 0, -1)
	last := c.civil(through).AddDate(0, 0, 1)
	for day := first; !day.After(last); day = day.AddDate(0, 0, 1) {
		runs, skipped := c.day(day)
		for _, r := range runs {
			if r.At > from && r.At <= through {
				if len(out.Runs) == limit {
					return ExpectedWindow{}, model.Fail(model.TooLarge)
				}
				out.Runs = append(out.Runs, r)
			}
		}
		for _, s := range skipped {
			if s.Near > from && s.Near <= through {
				out.Skipped = append(out.Skipped, s)
			}
		}
	}
	return out, nil
}

type compiled struct {
	loc                      *time.Location
	tag                      string
	zone                     string
	minute, hour, dom, month uint64
	dow                      uint64
	domStar, dowStar         bool
}

func compileSchedule(s Schedule) (*compiled, error) {
	if !safeZone(s.Timezone) {
		return nil, model.Fail(model.Invalid)
	}
	loc, err := time.LoadLocation(s.Timezone)
	if err != nil {
		return nil, model.Fail(model.Invalid)
	}
	fields := strings.Fields(s.Cron)
	if len(fields) != 5 || len(s.Cron) > 256 {
		return nil, model.Fail(model.Invalid)
	}
	c := &compiled{loc: loc, tag: zoneTag(s.Timezone), zone: s.Timezone}
	var star [5]bool
	for i, spec := range []struct {
		lo, hi int
		bits   *uint64
	}{{0, 59, &c.minute}, {0, 23, &c.hour}, {1, 31, &c.dom}, {1, 12, &c.month}, {0, 7, &c.dow}} {
		bits, isStar, err := parseCronField(fields[i], spec.lo, spec.hi)
		if err != nil {
			return nil, err
		}
		*spec.bits, star[i] = bits, isStar
	}
	if c.dow&(1<<7) != 0 { // 7 is Sunday
		c.dow = c.dow&^(1<<7) | 1
	}
	c.domStar, c.dowStar = star[2], star[4]
	return c, nil
}
func safeZone(z string) bool {
	if z == "" || len(z) > 64 || strings.Contains(z, "..") || strings.HasPrefix(z, "/") || z == "Local" {
		return false
	}
	for i := range len(z) {
		c := z[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '+' || c == '/') {
			return false
		}
	}
	return true
}

// parseCronField accepts "*", numbers, ranges "a-b", steps "*/n" and "a-b/n",
// and comma lists. Names (JAN, MON) and macros (@daily) are not accepted.
func parseCronField(field string, lo, hi int) (uint64, bool, error) {
	if field == "*" {
		var bits uint64
		for v := lo; v <= hi; v++ {
			bits |= 1 << uint(v)
		}
		if hi == 7 {
			bits &^= 1 << 7 // "*" for weekdays is 0-6
		}
		return bits, true, nil
	}
	var bits uint64
	for _, part := range strings.Split(field, ",") {
		step := 1
		if i := strings.IndexByte(part, '/'); i >= 0 {
			n, err := strconv.Atoi(part[i+1:])
			if err != nil || n < 1 || part[i+1:] != strconv.Itoa(n) {
				return 0, false, model.Fail(model.Invalid)
			}
			step, part = n, part[:i]
		}
		a, b := lo, hi
		switch {
		case part == "*":
		case strings.Contains(part, "-"):
			ends := strings.SplitN(part, "-", 2)
			x, e1 := strconv.Atoi(ends[0])
			y, e2 := strconv.Atoi(ends[1])
			if e1 != nil || e2 != nil || x > y {
				return 0, false, model.Fail(model.Invalid)
			}
			a, b = x, y
		default:
			x, err := strconv.Atoi(part)
			if err != nil {
				return 0, false, model.Fail(model.Invalid)
			}
			a, b = x, x
		}
		if a < lo || b > hi {
			return 0, false, model.Fail(model.Invalid)
		}
		for v := a; v <= b; v += step {
			bits |= 1 << uint(v)
		}
	}
	return bits, false, nil
}

func (c *compiled) civil(at model.UnixNano) time.Time {
	l := time.Unix(0, int64(at)).In(c.loc)
	return time.Date(l.Year(), l.Month(), l.Day(), 0, 0, 0, 0, time.UTC)
}
func (c *compiled) dayMatches(day time.Time) bool {
	if c.month&(1<<uint(day.Month())) == 0 {
		return false
	}
	dom := c.dom&(1<<uint(day.Day())) != 0
	dow := c.dow&(1<<uint(day.Weekday())) != 0
	switch {
	case c.domStar && c.dowStar:
		return true
	case c.domStar:
		return dow
	case c.dowStar:
		return dom
	}
	return dom || dow
}

// day lists the occurrences and skipped wall times of one civil local date,
// ordered by UTC instant.
func (c *compiled) day(civil time.Time) ([]Expected, []Skipped) {
	if !c.dayMatches(civil) {
		return nil, nil
	}
	var runs []Expected
	var skipped []Skipped
	for h := range 24 {
		if c.hour&(1<<uint(h)) == 0 {
			continue
		}
		for m := range 60 {
			if c.minute&(1<<uint(m)) == 0 {
				continue
			}
			local := time.Date(civil.Year(), civil.Month(), civil.Day(), h, m, 0, 0, time.UTC)
			label := local.Format("2006-01-02T15:04")
			instants := c.resolve(local)
			if len(instants) == 0 {
				_, off := local.Add(-24 * time.Hour).In(c.loc).Zone()
				skipped = append(skipped, Skipped{Local: label, Near: model.UnixNano(local.Add(-time.Duration(off) * time.Second).UnixNano())})
				continue
			}
			for fold, at := range instants {
				runs = append(runs, Expected{At: model.UnixNano(at), Fold: uint8(fold), Local: label, Key: OccurrenceKey(c.zone, model.UnixNano(at), uint8(fold))})
			}
		}
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].At < runs[j].At })
	return runs, skipped
}

// resolve returns the distinct UTC instants whose local wall time in the zone
// equals the given wall time (given as a UTC-labelled civil time): none for a
// spring-forward gap, one normally, two across a fall-back. It assumes at most
// one offset transition within a day of the wall time.
func (c *compiled) resolve(wall time.Time) []int64 {
	var out []int64
	for _, probe := range []time.Duration{-24 * time.Hour, 0, 24 * time.Hour} {
		_, off := wall.Add(probe).In(c.loc).Zone()
		instant := wall.Add(-time.Duration(off) * time.Second).UnixNano()
		l := time.Unix(0, instant).In(c.loc)
		if l.Year() != wall.Year() || l.Month() != wall.Month() || l.Day() != wall.Day() || l.Hour() != wall.Hour() || l.Minute() != wall.Minute() {
			continue
		}
		dup := false
		for _, v := range out {
			dup = dup || v == instant
		}
		if !dup {
			out = append(out, instant)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

const scheduleSearchDays = 400

func (c *compiled) prevAtOrBefore(t model.UnixNano) (Expected, bool) {
	for day, i := c.civil(t), 0; i < scheduleSearchDays; day, i = day.AddDate(0, 0, -1), i+1 {
		runs, _ := c.day(day)
		for k := len(runs) - 1; k >= 0; k-- {
			if runs[k].At <= t {
				return runs[k], true
			}
		}
	}
	return Expected{}, false
}
func (c *compiled) nextAfter(t model.UnixNano) (Expected, bool) {
	for day, i := c.civil(t), 0; i < scheduleSearchDays; day, i = day.AddDate(0, 0, 1), i+1 {
		runs, _ := c.day(day)
		for _, r := range runs {
			if r.At > t {
				return r, true
			}
		}
	}
	return Expected{}, false
}

// definitions returns every revision ascending; revision i governs
// [EffectiveFrom_i, EffectiveFrom_{i+1}).
func (s JobState) definitions() []Definition {
	all := append([]Definition(nil), s.History...)
	if s.Definition.Revision != 0 {
		all = append(all, s.Definition)
	}
	return all
}

// expectedPrev is the latest expected occurrence at or before t, honouring
// which revision was effective at that instant.
func (s JobState) expectedPrev(t model.UnixNano) (Expected, bool) {
	defs := s.definitions()
	for i := len(defs) - 1; i >= 0; i-- {
		hi := t
		if i+1 < len(defs) && defs[i+1].EffectiveFrom-1 < hi {
			hi = defs[i+1].EffectiveFrom - 1
		}
		if hi < defs[i].EffectiveFrom || defs[i].Schedule == nil {
			continue
		}
		c, err := compileSchedule(*defs[i].Schedule)
		if err != nil {
			continue
		}
		if o, ok := c.prevAtOrBefore(hi); ok && o.At >= defs[i].EffectiveFrom {
			return o, true
		}
	}
	return Expected{}, false
}

// expectedNext is the first expected occurrence strictly after t.
func (s JobState) expectedNext(t model.UnixNano) (Expected, bool) {
	defs := s.definitions()
	for i := range defs {
		if defs[i].Schedule == nil {
			continue
		}
		lo := t
		if defs[i].EffectiveFrom-1 > lo {
			lo = defs[i].EffectiveFrom - 1
		}
		c, err := compileSchedule(*defs[i].Schedule)
		if err != nil {
			continue
		}
		if o, ok := c.nextAfter(lo); ok && (i+1 == len(defs) || o.At < defs[i+1].EffectiveFrom) {
			return o, true
		}
	}
	return Expected{}, false
}

// skippedLocal lists nonexistent local times of the current schedule in (from, to].
func (s JobState) skippedLocal(from, to model.UnixNano, limit int) []string {
	if s.Definition.Schedule == nil {
		return nil
	}
	if from < s.Definition.EffectiveFrom {
		from = s.Definition.EffectiveFrom
	}
	if to < from || time.Duration(to-from) > 400*24*time.Hour {
		return nil
	}
	c, err := compileSchedule(*s.Definition.Schedule)
	if err != nil {
		return nil
	}
	var out []string
	for day, last := c.civil(from).AddDate(0, 0, -1), c.civil(to).AddDate(0, 0, 1); !day.After(last); day = day.AddDate(0, 0, 1) {
		_, skipped := c.day(day)
		for _, k := range skipped {
			if k.Near > from && k.Near <= to && len(out) < limit {
				out = append(out, k.Local)
			}
		}
	}
	return out
}
