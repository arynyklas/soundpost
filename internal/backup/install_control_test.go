// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/storage"
)

// A control state that still carries the stash of an EARLIER restore (a backup
// taken by a build that did not strip it, or any state handed to installControl)
// must still restore: the new generation quarantines what is active in it and
// replaces the stash. Items the earlier generation never reconciled are not
// carried across.
func TestInstallControlReplacesAnEarlierGenerationsStash(t *testing.T) {
	ctx := context.Background()
	srcDir := t.TempDir()
	src, err := control.Open(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { src.Close() })
	if err = src.EnableSingle(ctx, filepath.Join(srcDir, "raft-control")); err != nil {
		t.Fatal(err)
	}
	neverReauthorized, recoveryAdmin := model.NewID(), model.NewID()
	if err = src.Update(ctx, func(st *model.ControlState) error {
		st.Users[neverReauthorized.String()] = model.ControlUser{ID: neverReauthorized, Email: "never@example.test"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Generation 1's restore quarantined the installation, then its recovery admin was bootstrapped.
	sealed, err := auth.SealedBearerKey(src.Seal)
	if err != nil {
		t.Fatal(err)
	}
	_, hash := auth.NewRecoveryBootstrap()
	if err = src.Update(ctx, func(st *model.ControlState) error {
		_, e := auth.QuarantineRestoredState(st, auth.RestoreInput{Generation: model.NewID(), Backup: model.NewID(), BootstrapHash: hash, SealedBearerKey: sealed, At: time.Now()})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = src.Update(ctx, func(st *model.ControlState) error {
		st.Users[recoveryAdmin.String()] = model.ControlUser{ID: recoveryAdmin, Email: "recovery@example.test", Admin: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var pending int
	_ = src.View(ctx, func(st model.ControlState) error { pending = auth.RestorePending(st); return nil })
	if pending != 1 {
		t.Fatalf("fixture: generation 1 should hold exactly one stashed account, holds %d", pending)
	}
	seed, _, err := src.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	var parts map[string]json.RawMessage
	if err = json.Unmarshal(seed, &parts); err != nil {
		t.Fatal(err)
	}
	stateObject, err := json.Marshal(map[string]json.RawMessage{"state": parts["state"], "keys": json.RawMessage(`{}`), "metadata": parts["metadata"]})
	if err != nil {
		t.Fatal(err)
	}
	seed, _, err = reassembleSeed(stateObject, parts["keys"]) // as a restore does: the old bootstrap key file is dropped
	if err != nil {
		t.Fatal(err)
	}

	stage := filepath.Join(t.TempDir(), "stage")
	summary, err := installControl(ctx, stage, seed, storage.QuotaReconciliation{Version: 1}, nil, nil, model.NewID(), time.Now())
	if err != nil {
		t.Fatalf("a state carrying an earlier restore's stash cannot be restored: %v", err)
	}
	if summary.Users != 1 {
		t.Fatalf("generation 2 quarantined %d accounts, want exactly the one that was active (the recovery admin)", summary.Users)
	}
	restored, err := control.Open(stage)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restored.Close() })
	if err = restored.EnableSingle(ctx, filepath.Join(stage, "raft", "control")); err != nil {
		t.Fatal(err)
	}
	if err = restored.View(ctx, func(st model.ControlState) error {
		if got := auth.RestorePending(st); got != 1 {
			t.Fatalf("the stash holds %d items, want only generation 2's single account", got)
		}
		for _, u := range []model.ID{neverReauthorized, recoveryAdmin} {
			if !st.Users[u.String()].Disabled {
				t.Fatalf("account %s is active after the restore", u)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
