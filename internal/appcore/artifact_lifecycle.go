// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"time"

	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
	"github.com/arynyklas/soundpost/internal/storage"
)

// artifactReadCacheBytes is the budget of the visibility-bound fragment cache the
// lifecycle's read gate keeps (artifacts.LifecycleConfig.CacheBytes).
const artifactReadCacheBytes = 4 << 20

// NewArtifactLifecycle builds the artifact lifecycle over the application's own
// artifact service and installs it in both places that need it:
//
//   - on the artifact Service, as its read gate: every read (Get, ReadAuthorized,
//     ReadSourcesAuthorized) also fences on the organization delete generation and
//     on the artifact's reference state, and uses the visibility-bound cache;
//   - on the retention service, it is NOT bound here: retention.Service takes one
//     References source, and the artifact lifecycle is one of two (the other is the
//     replay service). BindRetentionReferences binds the composite once, so an expiry
//     pass asks the artifact lifecycle before it erases an artifact root (a map that a
//     retained error, profile or build record still references is kept, a map
//     nothing references is fenced for erasure in the same control transaction as
//     the last check, and a reference state that cannot be verified fails the pass
//     closed) and the replay service before it erases a replay chunk.
//
// The retention service is both an input (the lifecycle takes it as its
// delete-generation source) and the consumer of the result, so it is built first
// and bound afterwards.
//
// Snapshot pins come from the real durable journal pins of the control group and
// of every data group (see journalPins). The clock is the wall clock, the same one
// retention.New defaults to.
func NewArtifactLifecycle(store *control.Store, service *artifacts.Service, engine *storage.Engine, ret *retention.Service) (*artifacts.Lifecycle, error) {
	if store == nil || engine == nil {
		return nil, model.Fail(model.Invalid)
	}
	return bindArtifactLifecycle(store, service, journalPins{data: dataJournalPins(engine), control: controlJournalPins(store)}, ret, time.Now)
}

func bindArtifactLifecycle(store artifacts.StateStore, service *artifacts.Service, pins artifacts.SnapshotPins, ret *retention.Service, now func() time.Time) (*artifacts.Lifecycle, error) {
	if service == nil || ret == nil {
		return nil, model.Fail(model.Invalid)
	}
	life, err := artifacts.NewLifecycle(service, artifacts.LifecycleConfig{State: store, Deletes: ret, Pins: pins, CacheBytes: artifactReadCacheBytes, Now: now,
		DefaultRetention: artifactRetention(store)})
	if err != nil {
		return nil, err
	}
	// The References binding is not made here: retention accepts exactly one source,
	// and the artifact lifecycle is one of several (see BindRetentionReferences).
	return life, nil
}

// artifactRetention is the lifecycle's default retention of a reference with no explicit
// deadline: the source-map period of the audited retention policy in force for the project at
// the instant, the defaults layered with the organization's and then the project's versions
// (retention.Resolve, ArtifactDays). A per-organization or per-project override therefore
// changes how long a reference keeps a map, and with it the map's effective retention (D-new
// C07, auth.Scope.ValidateArtifactState).
func artifactRetention(store artifacts.StateStore) func(context.Context, model.ID, model.ID, model.UnixNano) (time.Duration, error) {
	return func(ctx context.Context, org, project model.ID, at model.UnixNano) (time.Duration, error) {
		var days uint32
		err := store.View(ctx, func(st model.ControlState) error {
			days = retention.Resolve(st, org, &project, at).ArtifactDays
			return nil
		})
		if err != nil {
			return 0, err
		}
		if days == 0 {
			return 0, model.Fail(model.Invalid)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
}

// journalPins is artifacts.SnapshotPins over the durable journal pins a backup (or
// the copy of a snapshot) holds. A data-group pin records the artifact roots its
// group held when it was taken (storage.Engine.BeginBackupOwned) and the data
// source answers per root (storage.Engine.RootPinned): only a live pin of the
// group that owns the root, and that holds it, pins it. The control group's
// journal names every root's intent and ledger, so a live control pin is still
// answered conservatively for every root. Pins carry a lease, so a pin left by a
// dead backup stops holding maps when it lapses or is dropped. A source that
// cannot be read is an error (never "no pin"): the lifecycle turns it into
// Unavailable and the pass fails closed.
type journalPins struct {
	data    func(org, project, root model.ID) (bool, error) // a live data-group pin holds the root
	control func() (int, error)                             // live pins in the control group
}

func (p journalPins) Pinned(ctx context.Context, org, project, root model.ID) (bool, error) {
	if p.data == nil || p.control == nil {
		return false, model.Fail(model.Unavailable)
	}
	if err := ctx.Err(); err != nil {
		return false, model.Fail(model.Cancelled)
	}
	held, err := p.data(org, project, root)
	if err != nil || held {
		return held, err
	}
	if err := ctx.Err(); err != nil {
		return false, model.Fail(model.Cancelled)
	}
	n, err := p.control()
	return n > 0, err
}

func dataJournalPins(engine *storage.Engine) func(org, project, root model.ID) (bool, error) {
	return engine.RootPinned
}

func controlJournalPins(store *control.Store) func() (int, error) {
	return func() (int, error) {
		group := store.ReplicaGroup()
		if group == nil {
			return 0, model.Fail(model.Unavailable) // replication not enabled: pins unknown
		}
		pins, err := group.Pins()
		return len(pins), err
	}
}
