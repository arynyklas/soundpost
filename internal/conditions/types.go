// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package conditions is the C07/C08 alert-condition lifecycle: the ordered,
// idempotent state of one source condition, kept distinct from the error issue
// and from the human incident it may be linked to. It does two things and
// nothing else:
//
//   - Reduce folds one model.ConditionEvent into a condition's State with the
//     source order the design requires: events carry a producer epoch and a
//     source sequence, an old or duplicate event can never overwrite newer state,
//     the same event retried is a no-op, and a conflicting replay of an accepted
//     event is rejected. An adapter with no sequence is ordered by event time
//     plus a deterministic tie key and can never overwrite a newer trusted
//     sequence.
//   - Service applies those transitions through the C05 ApplyCondition command
//     under the control lease, and joins the committed C07 rule outputs (the
//     internal condition outbox of internal/rules) into this lifecycle state.
//     It is not a second rule scheduler and not a second output outbox, and it is
//     not a notify.Delivery: it never sends anything.
//
// The rules reducer already owns pending/for/recovery-hold semantics; this
// package consumes its transitions and never recomputes them. What it adds is
// the property the incident side depends on: unknown input (an unknown or error
// evaluation, a stale producer, a missing shard, an evidence gap) never moves a
// condition's phase, is never a recovery, and is kept as explicit freshness.
package conditions

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"soundpost/internal/model"
)

// Phase is the last definite lifecycle phase the source reported. The empty
// phase means the source has reported nothing definite yet (only unknown).
type Phase string

const (
	PhaseNone       Phase = ""
	PhasePending    Phase = "pending"
	PhaseFiring     Phase = "firing"
	PhaseRecovering Phase = "recovering"
	PhaseRecovered  Phase = "recovered"
)

// Active reports whether the condition is still a problem: firing, or recovering
// with its recovery hold not yet elapsed.
func (p Phase) Active() bool { return p == PhaseFiring || p == PhaseRecovering }

// Freshness is how much the current state can be trusted, in the vocabulary the
// incident side already uses. Only fresh evidence can support a recovery.
type Freshness string

const (
	FreshnessFresh   Freshness = "fresh"
	FreshnessStale   Freshness = "stale"
	FreshnessUnknown Freshness = "unknown"
)

// Health is the input health of one rule evaluation, as C07 reports it.
type Health string

const (
	HealthOK      Health = "ok"
	HealthUnknown Health = "unknown"
	HealthError   Health = "error"
)

// Closed, safe reason codes. They are the C07 evaluation reason codes plus the
// two this package adds; nothing here can carry a query, a label value or any
// telemetry text.
const (
	ReasonSourceUnknown = "source_unknown"
	ReasonUnspecified   = "unspecified"
)

var reasons = map[string]Freshness{
	// Evidence that is old: the producer or the input stopped.
	"stale_input":    FreshnessStale,
	"stale_producer": FreshnessStale,
	"loss":           FreshnessStale,
	// Evidence that is missing or unusable.
	"timeout":             FreshnessUnknown,
	"unavailable":         FreshnessUnknown,
	"budget":              FreshnessUnknown,
	"query_error":         FreshnessUnknown,
	"incomplete_result":   FreshnessUnknown,
	"invalid_result_kind": FreshnessUnknown,
	"duplicate_series":    FreshnessUnknown,
	"invalid_sample":      FreshnessUnknown,
	"evidence_gap":        FreshnessUnknown,
	ReasonSourceUnknown:   FreshnessUnknown,
	ReasonUnspecified:     FreshnessUnknown,
}

// Limits.
const (
	// MaxRecent bounds the accepted-event refs kept to recognise duplicates and
	// conflicting replays.
	MaxRecent    = 16
	maxLabels    = 64
	maxLabelName = 256
	maxLabelVal  = 1024
	maxLinks     = 64
	maxSeverity  = 64
)

// EventRef identifies one accepted event: enough to recognise a duplicate and to
// reject a conflicting replay of the same (epoch, sequence).
type EventRef struct {
	Epoch    model.ID       `json:"epoch"`
	Sequence model.Uint64   `json:"sequence"`
	At       model.UnixNano `json:"event_ns"`
	Status   string         `json:"status"`
	Digest   model.Hash     `json:"digest"`
}

// State is the committed lifecycle of one condition. It is produced only by
// Reduce, Observe and Join, which are pure; the service adds the arrival time
// and the source-rule link when it commits.
type State struct {
	Condition model.ID       `json:"condition_id"`
	Version   model.Revision `json:"version"`

	// Rule and RuleVersion link a condition that a C07 rule produced to its rule
	// version. Adapter conditions have no rule.
	Rule        *model.ID      `json:"rule_id,omitempty"`
	RuleVersion model.Revision `json:"rule_version,omitempty"`

	// Epoch and Sequence are the source order of the newest accepted event;
	// Sequence zero means the source gave none (timestamp-only). EventAt is its
	// event time and Arrived the time the worker accepted it. Both times are kept
	// and neither orders trusted events.
	Epoch    model.ID       `json:"epoch"`
	Sequence model.Uint64   `json:"sequence"`
	EventAt  model.UnixNano `json:"event_ns"`
	Arrived  model.UnixNano `json:"arrived_ns"`

	Phase Phase `json:"phase"`
	// Episode identifies the current firing episode: it changes when a condition
	// that was inactive or recovered becomes pending or firing again.
	Episode  *model.ID    `json:"episode_id,omitempty"`
	Severity string       `json:"severity"`
	Labels   model.Labels `json:"labels"`
	Links    []model.ID   `json:"links"`

	// Freshness, Reason and FreshAt are the newest evidence about how far the
	// state can be trusted, independent of Phase: unknown evidence never changes
	// the phase.
	Freshness Freshness      `json:"freshness"`
	Reason    string         `json:"reason,omitempty"`
	FreshAt   model.UnixNano `json:"fresh_ns"`

	// Notify is whether the newest accepted event may notify. False for evidence
	// that was only backfilled: a late evaluation never sends a retroactive
	// notification.
	Notify bool `json:"notify"`

	// Recent are the newest accepted events, oldest first; the last is the
	// current event.
	Recent []EventRef `json:"recent"`
}

// Recovered reports whether the condition is positively recovered: the source
// said so and nothing since has made that evidence unknown or stale.
func (s State) Recovered() bool {
	return s.Phase == PhaseRecovered && s.Freshness == FreshnessFresh
}

// Observation is the input health of one C07 rule evaluation at its scheduled
// time. An unknown or error evaluation emits no condition event, so this is how
// missing data becomes explicit condition history.
type Observation struct {
	At     model.UnixNano `json:"at_ns"`
	Health Health         `json:"health"`
	// Reason is a closed code; empty for a healthy observation.
	Reason string `json:"reason,omitempty"`
}

// Safe error details.
const (
	DetailEventConflict   = "condition_event_conflict"
	DetailRecoveryBlocked = "condition_recovery_blocked"
	DetailInvalidEvent    = "condition_event_invalid"
	DetailVersionRace     = "condition_version_race"
)

func fault(code model.Code, detail string) error {
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

func faultDetail(err error) string {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.SafeDetail
	}
	return ""
}

// derive builds a deterministic nonzero ID from a domain and its parts.
func derive(domain string, parts ...[]byte) model.ID {
	h := sha256.New()
	h.Write([]byte("soundpost.conditions." + domain + "\x00"))
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
