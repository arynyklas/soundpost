// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/replica"
)

// QueryExecutor is C06's Execute, exactly (satisfied by *query.Engine).
type QueryExecutor interface {
	Execute(ctx context.Context, scope auth.Scope, req query.Request) (query.Result, error)
}

// RuleStateReader returns committed C07 state. Read returns the state of the
// newest committed version of the rule, or the zero State (Version 0) when the
// rule has never been evaluated. ReadEvaluation returns the committed
// evaluation of exactly (version, at), verbatim.
type RuleStateReader interface {
	Read(ctx context.Context, scope auth.Scope, ruleID model.ID) (State, error)
	ReadEvaluation(ctx context.Context, scope auth.Scope, ruleID model.ID, version model.Revision, at model.UnixNano) (Evaluation, bool, error)
}

// Fencer validates a leadership lease against a fresh quorum observation
// (satisfied by *replica.Group): an election term or a clock alone is not a
// lease.
type Fencer interface {
	ValidateFence(ctx context.Context, token replica.FenceToken) error
}

// Clock supplies wall-clock observations outside the pure reducer.
type Clock interface {
	Now() model.UnixNano
}

type systemClock struct{}

func (systemClock) Now() model.UnixNano { return model.UnixNano(time.Now().UnixNano()) }

// Evidence is what a producer/loss/gap source says about the completeness of
// the input a window of evaluation depended on.
type Evidence struct {
	Incomplete bool
	// Reason is one of the closed Reason* codes when Incomplete.
	Reason string
}

// EvidenceChecker reports stale producers, declared loss and committed evidence
// gaps for a project over [from, to]. Ordinary language absence is not evidence
// of incompleteness; only a checker can say the source itself was incomplete.
type EvidenceChecker interface {
	Check(ctx context.Context, scope auth.Scope, project model.ID, from, to model.UnixNano) (Evidence, error)
}

// Evaluator evaluates rules. It holds no rule state: everything it reads is
// committed state behind RuleStateReader.
type Evaluator struct {
	engine   QueryExecutor
	store    RuleStateReader
	clock    Clock
	fencer   Fencer
	evidence EvidenceChecker
	producer *ProducerIdentity
	resolver ProducerResolver
}

// Option configures an Evaluator.
type Option func(*Evaluator)

// WithClock injects the wall clock (the live/backfill decision and ObservedAt).
func WithClock(c Clock) Option { return func(e *Evaluator) { e.clock = c } }

// WithFencer makes Evaluate validate its lease before any work.
func WithFencer(f Fencer) Option { return func(e *Evaluator) { e.fencer = f } }

// WithEvidence injects the producer/loss/gap evidence source.
func WithEvidence(c EvidenceChecker) Option { return func(e *Evaluator) { e.evidence = c } }

// WithProducer sets the registered recording producer identity; it is required
// to evaluate recording rules.
func WithProducer(p ProducerIdentity) Option {
	return func(e *Evaluator) { copied := p; e.producer = &copied }
}

// ProducerResolver resolves the recording producer identity currently
// registered, so a source-policy revision change is picked up without a restart.
type ProducerResolver func(ctx context.Context) (ProducerIdentity, error)

// WithProducerResolver resolves the producer identity at every evaluation
// instead of pinning one at construction.
func WithProducerResolver(r ProducerResolver) Option {
	return func(e *Evaluator) { e.resolver = r }
}

// NewEvaluator builds an evaluator over the C06 engine and committed state.
func NewEvaluator(engine QueryExecutor, store RuleStateReader, options ...Option) *Evaluator {
	e := &Evaluator{engine: engine, store: store, clock: systemClock{}}
	for _, option := range options {
		option(e)
	}
	return e
}

const maxDiagnostics = 64

// fenceFault maps a lease validation failure to the typed model error.
func fenceFault(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, replica.ErrStale):
		return ruleFault(model.Stale, "rule_lease_stale")
	case errors.Is(err, replica.ErrInvalid):
		return model.Fail(model.Invalid)
	case errors.Is(err, context.Canceled):
		return model.Fail(model.Cancelled)
	case errors.Is(err, context.DeadlineExceeded):
		return model.Fail(model.Timeout)
	}
	return model.Fail(model.Unavailable)
}

func ruleFault(code model.Code, detail string) error {
	f := model.Fail(code)
	f.SafeDetail = detail
	return f
}

func faultCode(err error) model.Code {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code
	}
	return ""
}

// Evaluate evaluates rule at the scheduled grid time at under lease.
//
// A (rule version, at) that is already committed is returned unchanged,
// including its wall-clock observation: the first fenced committed payload is
// the evaluation, and nothing here may differ from it. Otherwise the rule is
// evaluated at exactly at (never at the wall clock), with AllowPartial false and
// the committed minimum input cursors, and the result reduced into the next
// state together with the deterministic recording and condition intents. The
// result is not committed: Commit does that, atomically, under the same lease.
func (e *Evaluator) Evaluate(ctx context.Context, scope auth.Scope, rule Rule, at model.UnixNano, lease replica.FenceToken) (Evaluation, error) {
	if err := rule.Validate(); err != nil {
		return Evaluation{}, err
	}
	if err := checkWorkerScope(scope, rule); err != nil {
		return Evaluation{}, err
	}
	interval := model.UnixNano(rule.Interval)
	if at < 0 || at%interval != 0 || lease.Group == (model.ID{}) || lease.Term == 0 {
		return Evaluation{}, model.Fail(model.Invalid)
	}
	if rule.Kind == KindRecording && e.producer == nil && e.resolver == nil {
		return Evaluation{}, model.Fail(model.Invalid)
	}
	if e.fencer != nil {
		if err := e.fencer.ValidateFence(ctx, lease); err != nil {
			return Evaluation{}, fenceFault(err)
		}
	}
	definition := rule.Digest()
	committed, found, err := e.store.ReadEvaluation(ctx, scope, rule.ID, rule.Version, at)
	if err != nil {
		return Evaluation{}, err
	}
	if found {
		if committed.Definition != definition {
			return Evaluation{}, ruleFault(model.Conflict, "rule_definition_changed")
		}
		return committed, nil
	}
	state, err := e.store.Read(ctx, scope, rule.ID)
	if err != nil {
		return Evaluation{}, err
	}
	if state.Version > rule.Version {
		return Evaluation{}, ruleFault(model.Stale, "rule_version_superseded")
	}
	current := state
	if state.Version != rule.Version {
		// A new version starts fresh pending and recovery timers; the earlier
		// version's history stays where it was committed.
		current = State{Org: scope.OrgID(), Project: rule.Project, Rule: rule.ID, Version: rule.Version, Definition: definition, Series: map[string]SeriesState{}, Cursors: []model.Cursor{}, Replays: state.Replays, Missed: state.Missed}
	} else {
		if state.Definition != definition {
			return Evaluation{}, ruleFault(model.Conflict, "rule_definition_changed")
		}
		if state.Applied != nil && at <= state.Applied.At {
			return Evaluation{}, ruleFault(model.Stale, "rule_evaluation_out_of_order")
		}
	}
	now := e.clock.Now()
	if at > now {
		return Evaluation{}, ruleFault(model.Invalid, "evaluation_in_future")
	}
	mode := ModeLive
	if now-at >= interval {
		mode = ModeBackfill
		for _, w := range state.Replays {
			if w.From <= at && at <= w.To {
				mode = ModeReplay
			}
		}
	}

	ev := Evaluation{
		Org: scope.OrgID(), Project: rule.Project, Rule: rule.ID, Version: rule.Version, At: at, ObservedAt: now, Mode: mode, Kind: rule.Kind, Signal: rule.signal(),
		Definition: definition, Lease: lease, Cursors: []model.Cursor{}, Diagnostics: []query.Diagnostic{}, Members: []model.Labels{}, Recorded: []Recorded{},
		Recording: []RecordingIntent{}, Conditions: []ConditionIntent{},
	}
	if rule.Kind == KindRecording {
		identity, err := e.producerIdentity(ctx)
		if err != nil {
			return Evaluation{}, err
		}
		ev.Producer = &identity
	}

	result, qerr := e.engine.Execute(ctx, scope, query.Request{
		Language: rule.language(), Profile: rule.Profile, Expression: rule.Expression,
		Evaluation: query.Evaluation{Instant: true, Time: at}, Projects: []model.ID{rule.Project}, FeatureSet: rule.FeatureSet,
		Budget: rule.Budget, MinCursors: append([]model.Cursor(nil), current.Cursors...),
		// A rule never accepts a partial answer: a missing shard must not read as
		// an absent series.
		AllowPartial: false,
	})
	switch {
	case qerr != nil:
		if ctx.Err() != nil {
			return Evaluation{}, qerr
		}
		outcome, reason, fatal := classifyFailure(qerr, rule)
		if fatal != nil {
			return Evaluation{}, fatal
		}
		ev.Outcome, ev.Reason = outcome, reason
	default:
		e.interpret(&ev, rule, result)
	}

	if ev.Outcome == OutcomeComplete {
		window := rule.For + rule.RecoveryHold + rule.Interval
		status, err := e.checkEvidence(ctx, scope, rule, at, window)
		if err != nil {
			return Evaluation{}, err
		}
		if status.Incomplete {
			ev.RecoveryBlocked, ev.Reason = true, status.Reason
		}
	}

	transition, err := Reduce(current, ev, rule)
	if err != nil {
		return Evaluation{}, err
	}
	ev.State = transition.State
	if transition.Conditions != nil {
		ev.Conditions = transition.Conditions
	}
	if rule.Kind == KindRecording && ev.Outcome == OutcomeComplete {
		batches, err := RecordingBatches(ev, rule)
		if err != nil {
			return Evaluation{}, err
		}
		for _, batch := range batches {
			ev.Recording = append(ev.Recording, RecordingIntent{ID: batch.ID, Slot: batch.RouteSlot, Batch: batch, Inputs: append([]model.Cursor{}, ev.Cursors...)})
		}
	}
	if reason := overflow(ev); reason != "" {
		// More than one control command may carry. Committing nothing would wedge the
		// rule silently and committing a truncated set would drop firing conditions
		// unseen, so the evaluation is committed as an error with a closed reason:
		// health shows it, no phase or frontier moves, the effects are dropped, and
		// the rule stays alive for the next grid point.
		ev.Outcome, ev.Reason, ev.RecoveryBlocked = OutcomeError, reason, false
		ev.Cursors, ev.Members, ev.Recorded = []model.Cursor{}, []model.Labels{}, []Recorded{}
		ev.Recording, ev.Conditions = []RecordingIntent{}, []ConditionIntent{}
		if transition, err = Reduce(current, ev, rule); err != nil {
			return Evaluation{}, err
		}
		ev.State = transition.State
		if overflow(ev) != "" {
			return Evaluation{}, model.Fail(model.TooLarge) // the committed state alone no longer fits
		}
	}
	return ev, nil
}

// producerIdentity is the recording producer an evaluation is built for: the one
// the resolver names now, else the one pinned at construction.
func (e *Evaluator) producerIdentity(ctx context.Context) (ProducerIdentity, error) {
	if e.resolver != nil {
		identity, err := e.resolver(ctx)
		if err != nil {
			return ProducerIdentity{}, err
		}
		return identity, nil
	}
	return *e.producer, nil
}

// checkWorkerScope asserts the pairing of a scope with the rule it evaluates: a
// rule runs as the project-scoped worker of its own project, so a scope that
// names any other project (or several) is refused before anything is read. A
// scope that names no project is the unscoped form used where no principal
// exists (the pure evaluator); every principal-backed scope the scheduler passes
// is stricter, see (*Scheduler).RunOnce. The organization is the scope's only:
// a Rule carries no organization, and control keys every commit by the scope's.
func checkWorkerScope(scope auth.Scope, rule Rule) error {
	projects := scope.ProjectIDs()
	if len(projects) > 0 && (len(projects) != 1 || projects[0] != rule.Project) {
		return model.Fail(model.Invalid)
	}
	return nil
}

// checkEvidence asks the evidence source about the window the decision depends
// on. A source that cannot answer is itself unknown: recovery stays blocked.
func (e *Evaluator) checkEvidence(ctx context.Context, scope auth.Scope, rule Rule, at model.UnixNano, window time.Duration) (Evidence, error) {
	if e.evidence == nil {
		return Evidence{}, nil
	}
	status, err := e.evidence.Check(ctx, scope, rule.Project, at-model.UnixNano(window), at)
	if err != nil {
		if ctx.Err() != nil {
			return Evidence{}, err
		}
		switch faultCode(err) {
		case model.Forbidden, model.NotFound, model.Unauthenticated, model.Cancelled:
			return Evidence{}, err
		}
		return Evidence{Incomplete: true, Reason: ReasonUnavailable}, nil
	}
	if status.Incomplete && status.Reason == "" {
		status.Reason = ReasonEvidenceGap
	}
	return status, nil
}

// classifyFailure maps an Execute error to an outcome. Authorization and
// deletion failures are never an evaluation: they are returned to the caller.
// Missing or stale input follows the rule's missing-data policy; a failed query
// (language error, budget) is an error whatever the policy.
func classifyFailure(err error, rule Rule) (Outcome, string, error) {
	missing := OutcomeUnknown
	if rule.missingPolicy() == MissingError {
		missing = OutcomeError
	}
	var language *syntax.LanguageError
	if errors.As(err, &language) {
		return OutcomeError, ReasonQueryError, nil
	}
	switch faultCode(err) {
	case model.Timeout:
		return missing, ReasonTimeout, nil
	case model.Unavailable:
		return missing, ReasonUnavailable, nil
	case model.Stale:
		return missing, ReasonStaleInput, nil
	case model.Quota:
		return OutcomeError, ReasonBudget, nil
	case model.Cancelled, model.Forbidden, model.NotFound, model.Unauthenticated:
		return "", "", err
	case "":
		return missing, ReasonUnavailable, nil
	}
	return OutcomeError, ReasonQueryError, nil
}

// interpret turns a C06 result into membership or recorded samples.
func (e *Evaluator) interpret(ev *Evaluation, rule Rule, result query.Result) {
	incomplete := func(reason string) {
		ev.Outcome, ev.Reason = OutcomeUnknown, reason
		if rule.missingPolicy() == MissingError {
			ev.Outcome = OutcomeError
		}
	}
	fail := func(reason string) {
		ev.Outcome, ev.Reason = OutcomeError, reason
		// A failed interpretation leaves no partial membership or samples behind.
		ev.Members, ev.Recorded = []model.Labels{}, []Recorded{}
	}
	if len(result.Projects) != 1 || result.Projects[0].ProjectID != rule.Project {
		fail(ReasonResultKind)
		return
	}
	pr := result.Projects[0]
	if pr.Failure != nil || pr.Value == nil || pr.Completeness != query.CompletenessComplete {
		incomplete(ReasonIncompleteResult)
		return
	}
	if pr.Value.Type != query.ValueVector {
		fail(ReasonResultKind)
		return
	}
	diagnostics := pr.Diagnostics
	if len(diagnostics) > maxDiagnostics {
		diagnostics = diagnostics[:maxDiagnostics]
	}
	ev.Diagnostics = append([]query.Diagnostic{}, diagnostics...)
	cursors := append([]model.Cursor{}, pr.Watermarks...)
	sort.Slice(cursors, func(i, j int) bool { return string(cursors[i].Group[:]) < string(cursors[j].Group[:]) })

	seen := make(map[string]bool, len(pr.Value.Vector))
	for _, element := range pr.Value.Vector {
		labels, ok := canonicalLabels(element.Labels)
		if !ok {
			fail(ReasonDuplicateSeries)
			return
		}
		if rule.Kind == KindAlert {
			key := seriesKey(labels)
			if seen[key] {
				fail(ReasonDuplicateSeries)
				return
			}
			seen[key] = true
			ev.Members = append(ev.Members, labels)
			continue
		}
		recorded, reason := recordedSample(rule, labels, element.Sample)
		if reason != "" {
			fail(reason)
			ev.Recorded = []Recorded{}
			return
		}
		key := seriesKey(recorded.Labels)
		if seen[key] {
			// Two source series collapsing onto one output identity: reject before
			// any effect exists.
			fail(ReasonDuplicateSeries)
			ev.Recorded = []Recorded{}
			return
		}
		seen[key] = true
		ev.Recorded = append(ev.Recorded, recorded)
	}
	sort.Slice(ev.Members, func(i, j int) bool { return seriesKey(ev.Members[i]) < seriesKey(ev.Members[j]) })
	sort.Slice(ev.Recorded, func(i, j int) bool { return seriesKey(ev.Recorded[i].Labels) < seriesKey(ev.Recorded[j].Labels) })
	ev.Outcome, ev.Cursors = OutcomeComplete, cursors
}

// canonicalLabels returns the labels sorted by name; a repeated name is invalid.
func canonicalLabels(in model.Labels) (model.Labels, bool) {
	out := append(model.Labels{}, in...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	for i, l := range out {
		if l.Name == "" || i > 0 && out[i-1].Name == l.Name {
			return nil, false
		}
	}
	return out, true
}

const staleMarkerBits = 0x7ff0000000000002

// recordedSample builds one output sample: the metric name label is replaced by
// the configured record name (so it is dropped here and set on the record), the
// configured labels override, and the sample must be a float or a native
// histogram with its exact bits. A reason is returned for an unacceptable one.
func recordedSample(rule Rule, labels model.Labels, sample query.Sample) (Recorded, string) {
	set := make(map[string]string, len(labels)+len(rule.Labels))
	for _, l := range labels {
		if l.Name != "__name__" {
			set[l.Name] = l.Value
		}
	}
	for _, l := range rule.Labels {
		set[l.Name] = l.Value
	}
	out := Recorded{Labels: make(model.Labels, 0, len(set)), StartTimestamp: sample.StartTimestamp}
	for name, value := range set {
		out.Labels = append(out.Labels, model.Label{Name: name, Value: value})
	}
	sort.Slice(out.Labels, func(i, j int) bool { return out.Labels[i].Name < out.Labels[j].Name })
	switch {
	case sample.Float != nil && sample.Histogram == nil:
		if uint64(*sample.Float) == staleMarkerBits {
			return Recorded{}, ReasonInvalidSample
		}
		bits := *sample.Float
		out.SampleKind, out.Value = "float", &bits
	case sample.Histogram != nil && sample.Float == nil:
		if sample.Histogram.Validate() != nil {
			return Recorded{}, ReasonInvalidSample
		}
		histogram := *sample.Histogram
		switch {
		case histogram.Integer != nil && histogram.Float == nil:
			out.SampleKind = "integer_histogram"
		case histogram.Float != nil && histogram.Integer == nil:
			out.SampleKind = "float_histogram"
		default:
			return Recorded{}, ReasonInvalidSample
		}
		out.Histogram = &histogram
	default:
		return Recorded{}, ReasonInvalidSample
	}
	return out, ""
}
