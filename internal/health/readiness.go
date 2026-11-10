// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package health

import (
	"context"
	"errors"

	"soundpost/internal/model"
)

// MaxApplyLag is how many committed-but-unapplied entries a group may hold before the
// node reports apply_lag. A small backlog is normal while writes are in flight, so
// zero would make the probe flap under load; a backlog beyond this means apply is stuck
// or far behind.
const MaxApplyLag uint64 = 256

// Schema is the stored-state version this node observed against the version this binary
// supports: Observed < Supported is old (a migration is owed), Observed > Supported newer.
type Schema struct{ Observed, Supported uint32 }

// DiskLevel mirrors the storage admission levels without importing the storage package.
type DiskLevel uint8

const (
	DiskNormal DiskLevel = iota
	DiskWarn
	DiskDenyLow
	DiskDenyAll
)

// Disk is the last sampled disk pressure of the data volume. Unmetered is a platform
// with no meter: not unready (the status says so elsewhere), only unmeasured.
type Disk struct {
	Level     DiskLevel
	Unmetered bool
}

// Group is one replication group of this node.
type Group struct {
	ID model.ID
	// Control marks the installation's control group; its applied cursor is the one
	// readiness reports.
	Control bool
	Failed  bool
	// Quorum is true when one quorum read round completed just now.
	Quorum  bool
	Commit  uint64
	Applied uint64
	Cursor  model.Cursor
}

// LocalState is what readiness needs from the running node. appcore.App satisfies it
// through the adapter in cmd/soundpost; tests use fakes.
type LocalState interface {
	Version() string
	RestoreHold() bool
	Schema(ctx context.Context) (Schema, error)
	Groups(ctx context.Context) ([]Group, error)
	PendingPolicyFences(ctx context.Context) (uint64, error)
	Disk(ctx context.Context) (Disk, error)
}

// Ready evaluates every check and returns the first failing safe reason, in this order:
// restore hold, schema, failed groups, quorum, apply backlog, policy fences, disk. An error
// from a dependency becomes the closed reason state_unavailable (disk_unknown for the disk
// meter) and its text is dropped: it can carry paths or credentials. The only error Ready
// returns is the caller's own cancellation, or a missing state.
func Ready(ctx context.Context, s LocalState) (Readiness, error) {
	if s == nil {
		return Readiness{}, errors.New("health: local state required")
	}
	unready := func(r Reason) (Readiness, error) {
		if err := ctx.Err(); err != nil {
			return Readiness{}, err
		}
		return Readiness{Reason: r}, nil
	}
	if err := ctx.Err(); err != nil {
		return Readiness{}, err
	}
	if s.RestoreHold() {
		return unready(ReasonRestorePending)
	}
	schema, err := s.Schema(ctx)
	if err != nil {
		return unready(ReasonStateUnavailable)
	}
	if schema.Observed < schema.Supported {
		return unready(ReasonSchemaOld)
	}
	if schema.Observed > schema.Supported {
		return unready(ReasonSchemaNewer)
	}
	groups, err := s.Groups(ctx)
	if err != nil {
		return unready(ReasonStateUnavailable)
	}
	var control *Group
	for i := range groups {
		if groups[i].Control {
			control = &groups[i]
		}
	}
	if control == nil {
		return unready(ReasonStateUnavailable)
	}
	for _, g := range groups {
		if g.Failed {
			return unready(ReasonSyncFailed)
		}
	}
	for _, g := range groups {
		if !g.Quorum {
			return unready(ReasonNoQuorum)
		}
	}
	for _, g := range groups {
		if g.Commit > g.Applied && g.Commit-g.Applied > MaxApplyLag {
			return unready(ReasonApplyLag)
		}
	}
	fences, err := s.PendingPolicyFences(ctx)
	if err != nil {
		return unready(ReasonStateUnavailable)
	}
	if fences > 0 {
		return unready(ReasonPolicyStale)
	}
	disk, err := s.Disk(ctx)
	if err != nil {
		return unready(ReasonDiskUnknown)
	}
	if disk.Level >= DiskDenyLow {
		return unready(ReasonDiskPressure)
	}
	if err := ctx.Err(); err != nil {
		return Readiness{}, err
	}
	cursor := control.Cursor
	return Readiness{Ready: true, Version: s.Version(), Applied: &cursor}, nil
}
