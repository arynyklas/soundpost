// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package health decides whether one Soundpost server may take traffic. Readiness is
// computed from the node's real local state (replication quorum, apply progress, disk
// pressure, policy-fence freshness, schema), never from a listening socket.
package health

import "github.com/arynyklas/soundpost/internal/model"

// Reason is the closed set of safe unready reasons. A reason names a class of failure
// only: it never carries an error string, path, address, identifier of a tenant or
// any credential, so it can be shown on an unauthenticated route.
type Reason string

const (
	// ReasonStarting is reported by the process before storage has finished opening
	// (recovery of the journal, control state and replication groups).
	ReasonStarting Reason = "starting"
	// ReasonStartupHold is reported while the operator's startup gate file does not exist yet.
	ReasonStartupHold Reason = "startup_hold"
	// ReasonRestorePending: a disaster-restored installation has not been activated.
	ReasonRestorePending Reason = "restore_pending"
	// ReasonSchemaOld: the stored state predates what this binary requires and needs a migration.
	ReasonSchemaOld Reason = "schema_old"
	// ReasonSchemaNewer: the stored state was written by a newer binary.
	ReasonSchemaNewer Reason = "schema_newer"
	// ReasonSyncFailed: a replication group stopped after a failed durable write (fsync).
	ReasonSyncFailed Reason = "sync_failed"
	// ReasonNoQuorum: a group cannot complete one quorum read round.
	ReasonNoQuorum Reason = "no_quorum"
	// ReasonApplyLag: a group has committed entries it has not applied yet beyond MaxApplyLag.
	ReasonApplyLag Reason = "apply_lag"
	// ReasonPolicyStale: a source revocation or retirement fence has not finished draining.
	ReasonPolicyStale Reason = "policy_stale"
	// ReasonDiskPressure: disk usage is at or above the level where intake is denied.
	ReasonDiskPressure Reason = "disk_pressure"
	// ReasonDiskUnknown: the disk meter exists but could not be read.
	ReasonDiskUnknown Reason = "disk_unknown"
	// ReasonStateUnavailable: local state could not be read at all.
	ReasonStateUnavailable Reason = "state_unavailable"
	// ReasonUnreachable is produced only by the `soundpost ready` client when the server could
	// not be asked (refused, untrusted certificate, timeout); a server never reports it.
	ReasonUnreachable Reason = "unreachable"
)

// Valid reports whether r is one of the closed reasons.
func (r Reason) Valid() bool {
	switch r {
	case ReasonStarting, ReasonStartupHold, ReasonRestorePending, ReasonSchemaOld, ReasonSchemaNewer, ReasonSyncFailed, ReasonNoQuorum, ReasonApplyLag, ReasonPolicyStale, ReasonDiskPressure, ReasonDiskUnknown, ReasonStateUnavailable, ReasonUnreachable:
		return true
	}
	return false
}

// Readiness is the whole public answer. Version and the applied cursor are present
// only when Ready is true; an unready answer carries the reason and nothing else.
type Readiness struct {
	Ready   bool          `json:"ready"`
	Reason  Reason        `json:"reason,omitempty"`
	Version string        `json:"version,omitempty"`
	Applied *model.Cursor `json:"applied_cursor,omitempty"`
}

// Unready builds the answer for a reason that is not part of Ready's evaluation (the
// startup gate uses it before any state exists).
func Unready(r Reason) Readiness { return Readiness{Reason: r} }
