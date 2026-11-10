// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"soundpost/internal/appcore"
	"soundpost/internal/health"
	"soundpost/internal/model"
	"soundpost/internal/storage"
	"sync"
)

// supportedSchema is the control-state format this binary reads: the persisted bearer-hash
// key format marker (auth refuses any other value at open). A stored 0 is the pre-marker
// layout that needs the one-time initialization; a larger value was written by a newer binary.
const supportedSchema = 1

// appState adapts the running appcore.App to health.LocalState. Everything it reports is read
// from the node's real state: the replication groups' own status and one quorum read round
// each, the control state's schema marker and pending source fences, and the storage
// engine's sampled disk pressure and restore hold.
type appState struct {
	app     *appcore.App
	version string
}

func newAppState(app *appcore.App, version string) *appState {
	return &appState{app: app, version: version}
}

func (s *appState) Version() string { return s.version }

func (s *appState) RestoreHold() bool { return s.app.Storage.RestoreReady() != nil }

func (s *appState) Schema(ctx context.Context) (health.Schema, error) {
	out := health.Schema{Supported: supportedSchema}
	err := s.app.Control.View(ctx, func(st model.ControlState) error {
		out.Observed = uint32(st.BearerHashKeyVersion)
		return nil
	})
	return out, err
}

// Groups reports the control group and every data group with one quorum read round each,
// run concurrently under ctx so 65 groups cost one round trip, not 65.
func (s *appState) Groups(ctx context.Context) ([]health.Group, error) {
	statuses := s.app.ReplicationStatus()
	node := s.app.ReplicaNode()
	if len(statuses) == 0 || node == nil {
		return nil, model.Fail(model.Unavailable)
	}
	control := s.app.Control.ReplicaGroup()
	if control == nil {
		return nil, model.Fail(model.Unavailable)
	}
	controlID := control.Status().Group
	out := make([]health.Group, len(statuses))
	var wg sync.WaitGroup
	for i, st := range statuses {
		out[i] = health.Group{ID: st.Group, Control: st.Group == controlID, Failed: st.Failed, Commit: st.Commit, Applied: st.Applied, Cursor: st.ApplicationCursor}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := node.ReadIndex(ctx, st.Group)
			out[i].Quorum = err == nil
		}()
	}
	wg.Wait()
	return out, nil
}

// PendingPolicyFences counts source revocation/retirement fences that have not finished
// draining: until they do, an old source policy can still be honoured by some data group.
func (s *appState) PendingPolicyFences(ctx context.Context) (uint64, error) {
	var pending uint64
	err := s.app.Control.View(ctx, func(st model.ControlState) error {
		for _, f := range st.SourceFences {
			if f.Phase == "fencing" {
				pending++
			}
		}
		return nil
	})
	return pending, err
}

func (s *appState) Disk(ctx context.Context) (health.Disk, error) {
	status, err := s.app.Storage.ObservePressure(ctx)
	if err != nil {
		return health.Disk{}, err
	}
	out := health.Disk{Unmetered: status.Unmetered}
	switch status.Level {
	case storage.PressureWarn:
		out.Level = health.DiskWarn
	case storage.PressureDenyLow:
		out.Level = health.DiskDenyLow
	case storage.PressureDenyAll:
		out.Level = health.DiskDenyAll
	}
	return out, nil
}
