// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/health"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

type fixedMeter struct{ percent uint64 }

func (m fixedMeter) Usage(string) (storage.DiskUsage, error) {
	return storage.DiskUsage{TotalBytes: 100 << 30, UsedBytes: m.percent * (1 << 30)}, nil
}

func decide(t *testing.T, app *appcore.App) health.Readiness {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	got, err := health.Ready(ctx, newAppState(app, "test-1"))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// A freshly opened single node is ready, and what it reports is its own real state: the
// control group's applied cursor, not a constant.
func TestAppStateReportsARealSingleNodeAsReady(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	got := decide(t, app)
	if !got.Ready || got.Version != "test-1" || got.Applied == nil {
		t.Fatalf("fresh node: %+v", got)
	}
	control := app.Control.ReplicaGroup().Status()
	if got.Applied.Group != control.Group || got.Applied.Index == 0 || got.Applied.Index != control.ApplicationCursor.Index {
		t.Fatalf("applied cursor %+v is not the control group's %+v", got.Applied, control.ApplicationCursor)
	}
	groups, err := newAppState(app, "x").Groups(context.Background())
	if err != nil || len(groups) < 2 {
		t.Fatalf("expected the control group and data groups: %d %v", len(groups), err)
	}
	controls := 0
	for _, g := range groups {
		if g.Control {
			controls++
		}
		if !g.Quorum || g.Failed {
			t.Fatalf("group %s: %+v", g.ID, g)
		}
	}
	if controls != 1 {
		t.Fatalf("%d control groups", controls)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "bootstrap") || strings.Contains(string(raw), "/") {
		t.Fatalf("answer carries more than readiness: %s", raw)
	}
}

// Disk pressure is read from the engine's sampled meter: warning still serves, deny-low and
// above is unready.
func TestAppStateReadsDiskPressureFromTheEngine(t *testing.T) {
	for _, c := range []struct {
		percent uint64
		ready   bool
	}{{50, true}, {85, true}, {92, false}, {97, false}} {
		app, err := appcore.OpenWithPressure(t.TempDir(), fixedMeter{c.percent}, storage.DefaultPressureConfig())
		if err != nil {
			t.Fatal(err)
		}
		got := decide(t, app)
		app.Close()
		if got.Ready != c.ready || (!c.ready && got.Reason != health.ReasonDiskPressure) {
			t.Fatalf("%d%% used: %+v", c.percent, got)
		}
	}
}

// Policy freshness is the control state's own undrained source fences; the schema is the
// control state's persisted format marker. Both are read from the live control store.
func TestAppStateReadsPolicyFencesAndSchemaFromControlState(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx := context.Background()
	fence := model.SourceFence{Operation: model.NewID(), Source: model.NewID(), Org: model.NewID(), Epoch: 1, Phase: "fencing"}
	if err = app.Control.Update(ctx, func(st *model.ControlState) error {
		st.SourceFences = map[string]model.SourceFence{fence.Source.String(): fence}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := decide(t, app); got.Ready || got.Reason != health.ReasonPolicyStale {
		t.Fatalf("undrained fence: %+v", got)
	}
	fence.Phase = "complete"
	if err = app.Control.Update(ctx, func(st *model.ControlState) error {
		st.SourceFences[fence.Source.String()] = fence
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := decide(t, app); !got.Ready {
		t.Fatalf("drained fence still blocks: %+v", got)
	}
	for version, want := range map[uint8]health.Reason{0: health.ReasonSchemaOld, 2: health.ReasonSchemaNewer} {
		if err = app.Control.Update(ctx, func(st *model.ControlState) error { st.BearerHashKeyVersion = version; return nil }); err != nil {
			t.Fatal(err)
		}
		if got := decide(t, app); got.Ready || got.Reason != want {
			t.Fatalf("schema marker %d: %+v", version, got)
		}
	}
}

// A node that has been stopped is never ready, and asking must not panic.
func TestAppStateOfAClosedNodeIsNotReady(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = app.Close(); err != nil {
		t.Fatal(err)
	}
	if got := decide(t, app); got.Ready || !got.Reason.Valid() {
		t.Fatalf("closed node: %+v", got)
	}
}

// Group status is the replication groups' own: once they are closed every group reports failed
// and none completes a quorum read, whatever the control state says.
func TestAppStateGroupsReportFailureAndQuorumLossFromTheGroups(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if err = app.CloseReplication(); err != nil {
		t.Fatal(err)
	}
	groups, err := newAppState(app, "x").Groups(context.Background())
	if err != nil || len(groups) < 2 {
		t.Fatalf("%d %v", len(groups), err)
	}
	for _, g := range groups {
		if !g.Failed || g.Quorum {
			t.Fatalf("a closed group reported failed=%v quorum=%v", g.Failed, g.Quorum)
		}
	}
}

// A restored installation that has not been activated holds intake closed; readiness says so.
func TestAppStateReportsAnArmedRestoreHold(t *testing.T) {
	dir := t.TempDir()
	first, err := appcore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	// The marker a disaster restore leaves in the data directory until activation lifts it.
	if err = os.WriteFile(filepath.Join(dir, "data", "restore-quota.pending"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	app, err := appcore.OpenForActivation(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if !newAppState(app, "x").RestoreHold() {
		t.Fatal("an armed restore hold was not reported")
	}
	if got := decide(t, app); got.Ready || got.Reason != health.ReasonRestorePending {
		t.Fatalf("restored installation before activation: %+v", got)
	}
}
