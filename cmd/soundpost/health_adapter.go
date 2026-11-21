// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/health"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
	"sync"
	"time"
)

// appState adapts the running appcore.App to health.LocalState. Everything it reports is read
// from the node's real state: the replication groups' own status and one quorum read round
// each, the control state's schema marker and pending source fences, and the storage
// engine's sampled disk pressure and restore hold.
type appState struct {
	app     *appcore.App
	version string
	// quorumBound caps one quorum read round. It sits below the readiness evaluation deadline
	// (httpapi readyEvalTimeout, 3 s): a read that cannot reach a majority only ends when its
	// context does, and if that context were the evaluation deadline itself, health.Ready would
	// have nothing left to answer with and the loss would surface as state_unavailable instead of
	// the designed no_quorum.
	quorumBound time.Duration
	// readIndex is one quorum read of a group; tests replace it.
	readIndex func(ctx context.Context, group model.ID) error
}

const defaultQuorumBound = time.Second

func newAppState(app *appcore.App, version string) *appState {
	s := &appState{app: app, version: version, quorumBound: defaultQuorumBound}
	s.readIndex = func(ctx context.Context, group model.ID) error {
		node := app.ReplicaNode()
		if node == nil {
			return model.Fail(model.Unavailable)
		}
		_, err := node.ReadIndex(ctx, group)
		return err
	}
	return s
}

func (s *appState) Version() string { return s.version }

func (s *appState) RestoreHold() bool { return s.app.Storage.RestoreReady() != nil }

// Schema reports the stored control-state format marker against auth.SchemaMarker, the format
// this binary reads. A node that was started on a foreign marker never reaches this method:
// auth.NewService refuses it at open (auth.SchemaError) and `serve` then answers the same
// decision, schema_newer or schema_old, from its startup gate. This method decides the marker of
// a node that is running, whose state changed under it.
func (s *appState) Schema(ctx context.Context) (health.Schema, error) {
	out := health.Schema{Supported: uint32(auth.SchemaMarker)}
	ctx, cancel := context.WithTimeout(ctx, s.quorumBound)
	defer cancel()
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
	if len(statuses) == 0 || s.app.ReplicaNode() == nil {
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
		out[i] = health.Group{ID: st.Group, Control: st.Group == controlID, Failed: st.Failed, Commit: st.Commit, Applied: st.Applied, Cursor: st.ApplicationCursor, Node: st.ID, Leader: st.Leader, Term: st.Term}
		wg.Add(1)
		go func() {
			defer wg.Done()
			read, cancel := context.WithTimeout(ctx, s.quorumBound)
			defer cancel()
			out[i].Quorum = s.readIndex(read, st.Group) == nil
		}()
	}
	wg.Wait()
	return out, nil
}

// PendingPolicyFences counts source revocation/retirement fences that have not finished
// draining: until they do, an old source policy can still be honoured by some data group.
func (s *appState) PendingPolicyFences(ctx context.Context) (uint64, error) {
	var pending uint64
	ctx, cancel := context.WithTimeout(ctx, s.quorumBound)
	defer cancel()
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
