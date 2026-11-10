// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package rules is C07 rule execution: a fenced evaluation of one pinned rule
// version at an immutable scheduled time over the owned C06 engine, a pure
// reducer from the committed state and the evaluation to the next state, and the
// durable effects (recording batches and condition events) that evaluation
// derives. The effects live in the control outbox in the same transition as the
// evaluation; this package never keeps rule state of its own, never starts a
// global engine and never calls an upstream evaluator.
//
// Three properties are the point of the design:
//
//   - Incomplete input is not an answer. Rule queries always set AllowPartial
//     false; a timeout, a missing shard or stale producer/loss evidence yields
//     unknown or error health and never a recovery.
//   - Membership, not truthiness, drives conditions: a series is firing because
//     it is present in an instant vector, whatever its numeric value.
//   - The first committed payload for (rule, version, at) is final. Replays read
//     it back verbatim; a conflicting later payload is rejected.
package rules

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"soundpost/internal/model"
	"soundpost/internal/query"
	"soundpost/internal/query/logql"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/promql"
	"soundpost/internal/replica"
)

// Kind is what a rule does with the instant vector its expression yields.
type Kind string

const (
	// KindAlert drives per-series condition state from vector membership.
	KindAlert Kind = "alert"
	// KindRecording writes the vector back as metric samples under RecordName.
	KindRecording Kind = "recording"
)

// MissingData selects how input that could not be read completely (a timeout, an
// unavailable shard, a read that did not reach the committed input cursors) is
// reported. Both policies block every transition toward recovery; they differ in
// the health reported. The default is unknown.
type MissingData string

const (
	MissingUnknown MissingData = "unknown"
	MissingError   MissingData = "error"
)

// Rule is one immutable, version-pinned definition. Saving a rule runs
// (Rule).Check; evaluation refuses a rule that fails it. A recording rule's
// destination is explicit: RecordName and Labels, never inferred from the
// expression.
type Rule struct {
	ID      model.ID       `json:"id"`
	Project model.ID       `json:"project"`
	Version model.Revision `json:"version"`
	Kind    Kind           `json:"kind"`
	// Profile and FeatureSet pin the language semantics, exactly as a C06 request
	// does; the profile ID names the language (promql-... or logql-...).
	Profile    string `json:"profile"`
	FeatureSet string `json:"feature_set"`
	Expression string `json:"expression"`
	// Interval is the fixed evaluation grid step; scheduled times are multiples of
	// it. For is how long a series must be continuously present before firing;
	// RecoveryHold how long it must be continuously absent before recovering.
	Interval     time.Duration `json:"interval"`
	For          time.Duration `json:"for"`
	RecoveryHold time.Duration `json:"recovery_hold"`
	MissingData  MissingData   `json:"missing_data"`
	// Severity is the literal severity carried on condition events (alert rules).
	//
	// It is free text here (safeText): the conditions package, which consumes the
	// committed intents, accepts any safe text, so a closed set enforced at Check
	// would reject rules that package takes. Likewise the status words of the
	// events a rule emits are the C07 lifecycle (pending, firing, recovering,
	// resolved), not the C04 record vocabulary (firing, recovered, unknown): the
	// mapping (resolved is its recovered) belongs to the conditions package.
	Severity string `json:"severity,omitempty"`
	// RecordName and Labels configure recording rules: the resulting metric name,
	// and labels set on (overriding) every resulting series.
	RecordName string       `json:"record_name,omitempty"`
	Labels     model.Labels `json:"labels,omitempty"`
	// Budget optionally asks for a per-evaluation resource budget; zero fields use
	// the engine defaults and the engine rejects anything above its bounds.
	Budget query.Budget `json:"budget"`
}

const (
	minInterval   = time.Second
	maxInterval   = 24 * time.Hour
	maxHold       = 30 * 24 * time.Hour
	maxExpression = 64 << 10
	maxLabelValue = 1024
	maxRuleLabels = 64
)

var (
	metricName = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
	labelName  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

func (r Rule) language() string {
	switch {
	case strings.HasPrefix(r.Profile, query.LanguagePromQL+"-"):
		return query.LanguagePromQL
	case strings.HasPrefix(r.Profile, query.LanguageLogQL+"-"):
		return query.LanguageLogQL
	}
	return ""
}

func (r Rule) missingPolicy() MissingData {
	if r.MissingData == "" {
		return MissingUnknown
	}
	return r.MissingData
}

// signal is the telemetry signal the rule's expression reads.
func (r Rule) signal() model.Kind {
	if r.language() == query.LanguageLogQL {
		return model.Log
	}
	return model.Metric
}

func safeText(v string, max int) bool {
	if v == "" || len(v) > max || !utf8.ValidString(v) {
		return false
	}
	for _, c := range v {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

// Validate checks everything that needs no profile registry.
func (r Rule) Validate() error {
	invalid := func() error { return model.Fail(model.Invalid) }
	if r.ID == (model.ID{}) || r.Project == (model.ID{}) || r.Version == 0 || r.language() == "" || r.FeatureSet == "" || len(r.FeatureSet) > 128 || len(r.Profile) > 128 {
		return invalid()
	}
	if r.Expression == "" || len(r.Expression) > maxExpression || !utf8.ValidString(r.Expression) {
		return invalid()
	}
	if r.Interval < minInterval || r.Interval > maxInterval || r.Interval%time.Second != 0 || r.For < 0 || r.For > maxHold || r.RecoveryHold < 0 || r.RecoveryHold > maxHold {
		return invalid()
	}
	switch r.MissingData {
	case "", MissingUnknown, MissingError:
	default:
		return invalid()
	}
	switch r.Kind {
	case KindAlert:
		if !safeText(r.Severity, 64) || r.RecordName != "" || len(r.Labels) != 0 {
			return invalid()
		}
	case KindRecording:
		if r.Severity != "" || r.For != 0 || r.RecoveryHold != 0 || r.RecordName == "" || len(r.RecordName) > 256 || !metricName.MatchString(r.RecordName) || len(r.Labels) > maxRuleLabels {
			return invalid()
		}
		if err := validateOutputLabels(r.Labels); err != nil {
			return err
		}
	default:
		return invalid()
	}
	return nil
}

// validateOutputLabels requires sorted, unique, well-formed configured labels
// that never name the metric name label.
func validateOutputLabels(l model.Labels) error {
	if l.Validate() != nil {
		return model.Fail(model.Invalid)
	}
	for _, label := range l {
		if label.Name == "__name__" || !labelName.MatchString(label.Name) || len(label.Name) > 256 || len(label.Value) > maxLabelValue || !utf8.ValidString(label.Value) {
			return model.Fail(model.Invalid)
		}
	}
	return nil
}

// Registry resolves an immutable pinned profile (satisfied by query's registry).
type Registry interface {
	Resolve(id, featureSet string) (profile.Profile, error)
}

// Check is the save-time validation: Validate, then parse and type-check the
// expression under the pinned profile and feature set and require an instant
// vector. Any other result kind (scalar, string, range, log streams) is rejected
// when the rule is saved, never discovered at the first evaluation.
func (r Rule) Check(reg Registry) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if reg == nil {
		return model.Fail(model.Invalid)
	}
	prof, err := reg.Resolve(r.Profile, r.FeatureSet)
	if err != nil {
		return model.Fail(model.Invalid)
	}
	switch r.language() {
	case query.LanguagePromQL:
		expr, err := promql.Parse(r.Expression, prof)
		if err != nil {
			return model.Fail(model.Invalid)
		}
		typed, _, err := promql.Check(expr, prof)
		if err != nil || typed.Type != promql.Vector {
			return model.Fail(model.Invalid)
		}
	default:
		expr, err := logql.Parse(r.Expression, prof)
		if err != nil {
			return model.Fail(model.Invalid)
		}
		typed, _, err := logql.Check(expr, prof)
		if err != nil || typed.Type != logql.TypeVector {
			return model.Fail(model.Invalid)
		}
	}
	return nil
}

// Digest identifies the definition of a rule version. A committed version whose
// digest changes is a different rule under a reused version number, which is
// refused: a new definition is a new version.
func (r Rule) Digest() model.Hash {
	raw, err := model.CanonicalJSON(r)
	if err != nil {
		return model.Hash{}
	}
	return model.HashCanonical(raw)
}

// Phase is the per-series condition phase of an alert rule.
type Phase string

const (
	PhaseInactive   Phase = "inactive"
	PhasePending    Phase = "pending"
	PhaseFiring     Phase = "firing"
	PhaseRecovering Phase = "recovering"
)

// Health is the input health the last evaluation left, separate from phase:
// an unknown or error evaluation changes no phase, and never recovers one.
type Health string

const (
	HealthOK      Health = "ok"
	HealthUnknown Health = "unknown"
	HealthError   Health = "error"
)

// Outcome says whether the evaluation obtained a complete answer.
type Outcome string

const (
	OutcomeComplete Outcome = "complete"
	OutcomeUnknown  Outcome = "unknown"
	OutcomeError    Outcome = "error"
)

// Mode is how an evaluation relates to its scheduled time. Live evaluations
// notify; backfilled ones (evaluated one interval or more after their scheduled
// time) never do; replay is the explicit operator mode that lets a committed
// window of late evaluations notify.
type Mode string

const (
	ModeLive     Mode = "live"
	ModeBackfill Mode = "backfill"
	ModeReplay   Mode = "replay"
)

// Safe, closed reason codes: never query text, label values or telemetry.
const (
	ReasonTimeout          = "timeout"
	ReasonUnavailable      = "unavailable"
	ReasonStaleInput       = "stale_input"
	ReasonBudget           = "budget"
	ReasonQueryError       = "query_error"
	ReasonIncompleteResult = "incomplete_result"
	ReasonResultKind       = "invalid_result_kind"
	ReasonDuplicateSeries  = "duplicate_series"
	ReasonInvalidSample    = "invalid_sample"
	ReasonEvidenceGap      = "evidence_gap"
	ReasonStaleProducer    = "stale_producer"
	ReasonLoss             = "loss"
	// ReasonTooManyOutputs and ReasonPayloadTooLarge report an evaluation whose
	// effects or committed payload exceed what one control command may carry. The
	// evaluation is committed as an error, with its effects dropped, never lost.
	ReasonTooManyOutputs  = "too_many_outputs"
	ReasonPayloadTooLarge = "payload_too_large"
)

// EvaluationRef is the identity of an applied evaluation.
type EvaluationRef struct {
	ID model.ID       `json:"id"`
	At model.UnixNano `json:"at_ns"`
}

// SeriesState is the committed condition state of one series.
type SeriesState struct {
	Labels model.Labels `json:"labels"`
	Phase  Phase        `json:"phase"`
	// Since is the pending frontier: when the series was first continuously
	// present. RecoverySince is the recovery frontier: when it was first
	// continuously absent while firing.
	Since         model.UnixNano `json:"since_ns"`
	RecoverySince model.UnixNano `json:"recovery_since_ns,omitempty"`
}

// ReplayWindow is a committed operator declaration (read from control, never
// written by an evaluation).
type ReplayWindow struct {
	From model.UnixNano `json:"from_ns"`
	To   model.UnixNano `json:"to_ns"`
}

// MissedInterval is committed evidence that grid points [From, To] were not
// evaluated on time.
type MissedInterval struct {
	From  model.UnixNano `json:"from_ns"`
	To    model.UnixNano `json:"to_ns"`
	Count uint64         `json:"count,string"`
}

// State is the committed C07 state of one rule version.
type State struct {
	Org     model.ID       `json:"org"`
	Project model.ID       `json:"project"`
	Rule    model.ID       `json:"rule"`
	Version model.Revision `json:"version"`
	// Definition is the digest of the rule version this state belongs to.
	Definition model.Hash `json:"definition"`
	// Revision counts the evaluations applied to this version: the control
	// compare-and-set token.
	Revision model.Revision `json:"revision"`
	Applied  *EvaluationRef `json:"applied,omitempty"`
	// Series holds only series that are not inactive, keyed by canonical labels.
	Series map[string]SeriesState `json:"series"`
	// Cursors are the committed minimum input cursors: per group, the highest
	// read cut any complete evaluation saw. The next evaluation reads at least
	// this far or fails as stale input.
	Cursors  []model.Cursor `json:"cursors"`
	Health   Health         `json:"health"`
	Reason   string         `json:"reason,omitempty"`
	Sequence model.Uint64   `json:"sequence"`

	// Replays and Missed are control facts the read adapter attaches; they are not
	// part of the evaluated state and never serialized with it.
	Replays []ReplayWindow   `json:"-"`
	Missed  []MissedInterval `json:"-"`
}

// Recorded is one validated output sample of a recording rule.
type Recorded struct {
	Labels         model.Labels           `json:"labels"`
	SampleKind     string                 `json:"sample_kind"`
	Value          *model.FloatBits       `json:"value,omitempty"`
	Histogram      *model.NativeHistogram `json:"histogram,omitempty"`
	StartTimestamp *model.UnixNano        `json:"start_timestamp_ns,omitempty"`
}

// ProducerIdentity is the registered recording producer: the C03 source and
// producer a rule's samples are admitted as, the source policy revision the
// batches are built for, and the registered resource they carry.
type ProducerIdentity struct {
	Source         model.ID       `json:"source"`
	Producer       model.ID       `json:"producer"`
	PolicyRevision model.Revision `json:"policy_revision"`
	Resource       model.Resource `json:"resource"`
}

// RecordingIntent is one internal recording output: exactly one stable one-slot
// C03 batch. Inputs is its provenance: the input cursors of the evaluation.
type RecordingIntent struct {
	ID     model.ID       `json:"id"`
	Slot   uint16         `json:"slot"`
	Batch  model.Batch    `json:"batch"`
	Inputs []model.Cursor `json:"inputs"`
}

// ConditionIntent is one internal condition output for the incident side.
// Notify is false for every evaluation that is not live or explicitly replayed.
type ConditionIntent struct {
	ID     model.ID             `json:"id"`
	Event  model.ConditionEvent `json:"event"`
	Notify bool                 `json:"notify"`
	Mode   Mode                 `json:"mode"`
}

// Evaluation is the immutable result of evaluating one rule version at one
// scheduled time. Once committed it is final.
type Evaluation struct {
	Org     model.ID       `json:"org"`
	Project model.ID       `json:"project"`
	Rule    model.ID       `json:"rule"`
	Version model.Revision `json:"version"`
	// At is the scheduled grid time; ObservedAt the wall clock the evaluation was
	// computed at (LogQL `now` and the live/backfill decision depend on it, which
	// is why a committed evaluation is read back instead of recomputed).
	At         model.UnixNano `json:"at_ns"`
	ObservedAt model.UnixNano `json:"observed_ns"`
	Mode       Mode           `json:"mode"`
	Kind       Kind           `json:"kind"`
	// Definition is the digest of the evaluated rule version.
	Definition model.Hash `json:"definition"`
	// Signal is the telemetry kind the rule's expression reads (metric for PromQL,
	// log for LogQL); a deletion covering that signal makes its outputs obsolete.
	Signal   model.Kind         `json:"signal"`
	Lease    replica.FenceToken `json:"lease"`
	Producer *ProducerIdentity  `json:"producer,omitempty"`

	Outcome Outcome `json:"outcome"`
	Reason  string  `json:"reason,omitempty"`
	// RecoveryBlocked marks a complete result whose input evidence (stale
	// producer, loss, a declared gap) is not: absent series are then unknown, not
	// false.
	RecoveryBlocked bool               `json:"recovery_blocked,omitempty"`
	Cursors         []model.Cursor     `json:"cursors"`
	Diagnostics     []query.Diagnostic `json:"diagnostics"`

	// Members are the label sets present in an alert rule's instant vector;
	// Recorded the validated samples of a recording rule.
	Members  []model.Labels `json:"members"`
	Recorded []Recorded     `json:"recorded"`

	State      State             `json:"state"`
	Recording  []RecordingIntent `json:"recording"`
	Conditions []ConditionIntent `json:"conditions"`
}

// Ref is the evaluation's identity.
func (e Evaluation) Ref() EvaluationRef {
	return EvaluationRef{ID: EvaluationID(e.Org, e.Project, e.Rule, e.Version, e.At), At: e.At}
}

// Canonical is the evaluation's deterministic JSON and its digest.
func (e Evaluation) Canonical() ([]byte, model.Hash, error) {
	raw, err := model.CanonicalJSON(e)
	if err != nil {
		return nil, model.Hash{}, model.Fail(model.Invalid)
	}
	return raw, model.Hash(sha256.Sum256(raw)), nil
}

// Transition is the pure result of reducing one evaluation into a state.
type Transition struct {
	State      State
	Conditions []ConditionIntent
	// Changed lists the series keys whose phase changed, in key order.
	Changed []string
}

// derive builds a deterministic ID from a domain and its parts.
func derive(domain string, parts ...[]byte) model.ID {
	h := sha256.New()
	h.Write([]byte("soundpost.rules." + domain + "\x00"))
	for _, p := range parts {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		h.Write(n[:])
		h.Write(p)
	}
	var id model.ID
	copy(id[:], h.Sum(nil))
	if id == (model.ID{}) {
		id[0] = 1
	}
	return id
}

func u64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

// EvaluationID is the stable identity of (rule, version, at).
func EvaluationID(org, project, rule model.ID, version model.Revision, at model.UnixNano) model.ID {
	return derive("evaluation", org[:], project[:], rule[:], u64(uint64(version)), u64(uint64(at)))
}

// seriesKey is the canonical identity of a label set within a rule.
func seriesKey(l model.Labels) string {
	var b bytes.Buffer
	for _, label := range l {
		raw, _ := json.Marshal([2]string{label.Name, label.Value})
		b.Write(raw)
	}
	return b.String()
}
