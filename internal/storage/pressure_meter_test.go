// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin || freebsd || windows

package storage

import (
	"context"
	"path/filepath"
	"testing"

	"soundpost/internal/model"
)

func TestHostMeterReportsTheVolumeHoldingTheDirectory(t *testing.T) {
	m := HostMeter()
	if m == nil {
		t.Fatal("this platform must have a host meter")
	}
	dir := t.TempDir()
	u, err := m.Usage(dir)
	if err != nil {
		t.Fatal(err)
	}
	if u.TotalBytes == 0 || u.UsedBytes > u.TotalBytes {
		t.Fatalf("implausible usage %+v", u)
	}
	// A path that does not exist and an unrepresentable path are not volumes to
	// measure: the answer must be an unavailable fault, never a guess.
	for _, bad := range []string{filepath.Join(dir, "missing", "deeper"), filepath.Join(dir, "no\x00nul")} {
		_, err = m.Usage(bad)
		if f, ok := err.(*model.Fault); !ok || f.Code != model.Unavailable {
			t.Fatalf("path %q: want unavailable fault, got %v", bad, err)
		}
	}
}

// The engine bound to the host meter must be able to sample: a meter that fails
// every sample makes admitPressure reject all intake as a capacity fault.
func TestHostMeterBoundEngineSamplesTheVolume(t *testing.T) {
	var e Engine
	if err := e.BindPressure(t.TempDir(), HostMeter(), DefaultPressureConfig()); err != nil {
		t.Fatal(err)
	}
	st, err := e.ObservePressure(context.Background())
	if err != nil {
		t.Fatalf("sample failed: %v", err)
	}
	if st.Unmetered || st.UsedPercent > 100 {
		t.Fatalf("status %+v", st)
	}
}
