// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"context"
	"testing"

	"soundpost/internal/appcore"
	"soundpost/internal/storage"
)

// The default Open must give the host a working disk meter (or, where the
// platform has none, an engine visibly marked unmetered). It must never leave a
// meter that fails every sample, which would reject all intake as "capacity".
func TestOpenBindsAWorkingHostMeterOrVisiblyUnmetered(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	st, err := app.Storage.ObservePressure(context.Background())
	if err != nil {
		t.Fatalf("host pressure sample failed: %v", err)
	}
	if want := storage.HostMeter() == nil; st.Unmetered != want {
		t.Fatalf("Unmetered=%v, host meter absent=%v", st.Unmetered, want)
	}
	if st.UsedPercent > 100 {
		t.Fatalf("used percent %d", st.UsedPercent)
	}
	if st.Unmetered && (len(st.Warnings) != 1 || st.Warnings[0].Code != "disk_unmetered") {
		t.Fatalf("unmetered engine is not visible in the warning ring: %+v", st.Warnings)
	}
}

func TestOpenWithNoMeterRunsUnmeteredAndSaysSo(t *testing.T) {
	app, err := appcore.OpenWithPressure(t.TempDir(), nil, storage.DefaultPressureConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	st, err := app.Storage.ObservePressure(context.Background())
	if err != nil {
		t.Fatalf("unmetered observe must not be a failing step: %v", err)
	}
	if !st.Unmetered || st.Level != storage.PressureNormal || len(st.Warnings) != 1 || st.Warnings[0].Code != "disk_unmetered" {
		t.Fatalf("status %+v", st)
	}
}
