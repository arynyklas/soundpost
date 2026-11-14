// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention

import (
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"time"
)

// Policy is the effective retention in whole days (design section 12).
type Policy struct {
	Days         map[model.Kind]uint32
	RawDays      uint32 // restricted_raw sources
	ArtifactDays uint32 // source maps / symbols; see reference-aware expiry
	AuditDays    uint32
}

// Defaults are the exact approved proposals: metrics/logs/traces 14 days;
// errors, lifecycle conditions and job histories 90 days; replay 7; profiles 7;
// source maps/symbols 90 (or until their last referencing retained record
// expires, whichever is later); audit 365; restricted raw 24 hours (1 day).
// Capability and loss reports describe the data they accompany and follow the
// 14-day telemetry default (ambiguity recorded in docs/privacy/retention.md).
func Defaults() Policy {
	return Policy{
		Days: map[model.Kind]uint32{
			model.Metric: 14, model.Log: 14, model.SpanKind: 14, model.CapabilityKind: 14, model.Loss: 14,
			model.ErrorKind: 90, model.JobAttempt: 90, model.Condition: 90,
			model.Replay: 7, model.Profile: 7,
		},
		RawDays: 1, ArtifactDays: 90, AuditDays: 365,
	}
}

// DaysFor returns the retention of a signal; restricted raw is always the
// (shorter) raw period.
func (p Policy) DaysFor(kind model.Kind, restrictedRaw bool) uint32 {
	if restrictedRaw && p.RawDays != 0 {
		return p.RawDays
	}
	return p.Days[kind]
}

// Deadline is the absolute time a record admitted at admittedAt must be kept
// until. It is computed once at admission and stored in the receipt; a later
// policy change never recomputes it.
func Deadline(admittedAt model.UnixNano, days uint32) model.UnixNano {
	return admittedAt + model.UnixNano(time.Duration(days)*24*time.Hour)
}

// Resolve layers the audited versions of control state over the defaults as of
// the instant at: organization default first, then the project's, each only if
// its Effective time has been reached. Versions are append-only, so resolving a
// past instant always reproduces the policy that was in force then.
func Resolve(st control.State, org model.ID, project *model.ID, at model.UnixNano) Policy {
	out := Defaults()
	apply := func(key string) {
		for _, v := range st.RetentionPolicies[key] {
			if v.Effective > at {
				continue
			}
			for k, d := range v.Days {
				out.Days[k] = d
			}
			if v.RawDays != 0 {
				out.RawDays = v.RawDays
			}
			if v.Artifacts != 0 {
				out.ArtifactDays = v.Artifacts
			}
		}
	}
	apply(org.String())
	if project != nil {
		apply(org.String() + ":" + project.String())
	}
	return out
}

// evidenceKind reports whether a signal feeds lifecycle projections whose
// unprocessed expiry must be declared as a gap (C05).
func evidenceKind(k model.Kind) bool {
	return k == model.ErrorKind || k == model.Condition || k == model.JobAttempt
}
