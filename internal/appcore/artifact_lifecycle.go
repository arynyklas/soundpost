// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"time"

	"soundpost/internal/artifacts"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/retention"
	"soundpost/internal/storage"
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
//   - on the retention service, as its References source
//     (retention.Service.UseReferences): an expiry pass asks LatestReference before
//     it erases an artifact root, so a map that a retained error, profile or build
//     record still references is kept, a map nothing references is fenced for
//     erasure in the same control transaction as the last check, and a reference
//     state that cannot be verified fails the pass closed (erases nothing).
//
// The retention service is both an input (the lifecycle takes it as its
// delete-generation source) and the consumer of the result, so it is built first
// and bound afterwards; UseReferences refuses a second binding.
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
	life, err := artifacts.NewLifecycle(service, artifacts.LifecycleConfig{State: store, Deletes: ret, Pins: pins, CacheBytes: artifactReadCacheBytes, Now: now})
	if err != nil {
		return nil, err
	}
	if err = ret.UseReferences(life); err != nil {
		return nil, err
	}
	return life, nil
}

// journalPins is artifacts.SnapshotPins over the durable journal pins a backup (or
// the copy of a snapshot) holds. A pin protects journal and snapshot state of a
// whole Raft group: it names no organization, project or artifact root, so the
// only honest answer to "does anything still need this root" is the conservative
// one: while any pin is live, every root is pinned, and no map is fenced or
// erased. Pins carry a lease, so a pin left by a dead backup stops holding maps
// when it lapses or is dropped. A source that cannot be read is an error (never
// "no pin"): the lifecycle turns it into Unavailable and the pass fails closed.
type journalPins struct {
	data, control func() (int, error) // live pins in the data groups / the control group
}

func (p journalPins) Pinned(ctx context.Context, _, _, _ model.ID) (bool, error) {
	if p.data == nil || p.control == nil {
		return false, model.Fail(model.Unavailable)
	}
	for _, live := range []func() (int, error){p.data, p.control} {
		if err := ctx.Err(); err != nil {
			return false, model.Fail(model.Cancelled)
		}
		n, err := live()
		if err != nil {
			return false, err
		}
		if n > 0 {
			return true, nil
		}
	}
	return false, nil
}

func dataJournalPins(engine *storage.Engine) func() (int, error) {
	return func() (int, error) {
		pins, err := engine.JournalPins()
		return len(pins), err
	}
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
