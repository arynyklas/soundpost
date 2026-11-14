// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"path/filepath"
	"testing"
)

// Removing the activation gate, replaying preparation callbacks, or using a
// different Raft directory on restart must break these observable assertions.
func TestControlFeatureUpdateRequiresActualConsensus(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	store, err := control.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	err = store.Update(ctx, func(state *control.State) error { calls++; state.DataInitialized = true; return nil })
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != model.Unavailable || calls != 0 {
		store.Close()
		t.Fatal("preactivation feature mutation was allowed")
	}
	if _, err = auth.NewService(auth.AuthDependencies{Control: store}); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if store.ReplicaGroup() != nil {
		store.Close()
		t.Fatal("private authority initialization implicitly activated a group")
	}
	raftDirectory := filepath.Join(directory, "raft-control")
	if err = store.EnableSingle(ctx, raftDirectory); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err = store.Update(ctx, func(state *control.State) error { calls++; state.DataInitialized = true; return nil }); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if calls != 1 {
		store.Close()
		t.Fatal("preparation callback was replayed")
	}
	cut, err := store.ReplicaGroup().ReadIndex(ctx)
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err = store.View(ctx, func(state control.State) error {
		if !state.DataInitialized || uint64(cut.Index) != uint64(state.Revision) {
			t.Fatal("logical applied cut not installed with control state")
		}
		return nil
	}); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if store.ReplicaGroup().Status().Applied <= uint64(cut.Index) {
		store.Close()
		t.Fatal("physical election no-op was labeled a logical control revision")
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = control.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err = auth.NewService(auth.AuthDependencies{Control: store}); err != nil {
		t.Fatal(err)
	}
	if err = store.EnableSingle(ctx, raftDirectory); err != nil {
		t.Fatal(err)
	}
	if err = store.View(ctx, func(state control.State) error {
		if !state.DataInitialized {
			t.Fatal("real committed state disappeared at restart")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
