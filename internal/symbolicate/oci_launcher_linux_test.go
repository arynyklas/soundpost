//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// OCI symbolication through the current launcher on a host where clone3 is
// unusable (the case that selects the staged native launch). The OCI path must not
// consult clone3 or stage anything: it runs the fixed `--worker-v1` vector in the
// container, sends the whole batch on stdin once, and removes the container.
func TestOCIModeIsIndependentOfTheStagedLauncher(t *testing.T) {
	previous := cloneIntoCgroupAvailable
	cloneIntoCgroupAvailable = func() bool {
		t.Error("the OCI launch consulted clone3 availability")
		return false
	}
	t.Cleanup(func() { cloneIntoCgroupAvailable = previous })

	d := newFakeDocker(t, "okbatch")
	raw := []byte("{}")
	in := workerInput{Version: 1, Map: raw, MapHash: model.HashCanonical(raw), Positions: []workerPosition{{Line: 1}, {Line: 2}, {Line: 3, Column: 4}}}
	got := d.service(t).run(context.Background(), in)
	if len(got) != 3 {
		t.Fatalf("answers=%d: %+v", len(got), got)
	}
	for i, o := range got {
		if o.Reason != Unmapped {
			t.Fatalf("position %d: %+v", i, o)
		}
	}
	d.assertRemoved(t)
	argv := strings.Join(d.argv(), "\n")
	ran := false
	for _, l := range d.argv() {
		ran = ran || strings.HasPrefix(l, "run ") && strings.HasSuffix(l, " "+workerArg)
	}
	if !ran {
		t.Fatalf("the container did not run the worker vector %s:\n%s", workerArg, argv)
	}
	if strings.Contains(argv, stageWorkerArg) || strings.Contains(argv, stageProbeArg) {
		t.Fatalf("an OCI launch used a staging vector:\n%s", argv)
	}
	sent, e := os.ReadFile(filepath.Join(d.dir, "stdin.json"))
	if e != nil || strings.Count(string(sent), `"line"`) != 3 {
		t.Fatalf("the container did not receive all three positions in one request: %q (%v)", sent, e)
	}
}
